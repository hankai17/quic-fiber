#include "quic-fiber/quic_session.hh"
#include "quic-fiber/quic_server.hh"
#include "my_sylar/log.hh"
#include "my_sylar/util.hh"
#include "my_sylar/scheduler.hh"
#include "my_sylar/iomanager.hh"
#include "my_sylar/mbuffer.hh"
#include "my_sylar/address.hh"

#include <functional>
#include <my_sylar/macro.hh>

namespace sylar {
    namespace quic {
        static sylar::Logger::ptr g_logger = SYLAR_LOG_NAME("system");

	    /// SessionSemaphore
        SessionSemaphore::SessionSemaphore() {
        }

        SessionSemaphore::~SessionSemaphore() {
            // SYLAR_ASSERT(); // TODO
        }

        QuicSessionEvent SessionSemaphore::wait() {
            SYLAR_ASSERT(Scheduler::GetThis());
            {
                MutexType::Lock lock(m_mutex);
                if (m_events.size() > 0u) {
                    auto ev = m_events.front();
                    m_events.pop_front();
                    return ev;
                }
                m_waiters.push_back(std::make_pair(Scheduler::GetThis(), Fiber::GetThis()));
            }
            Fiber::YeildToHold();
            {
                MutexType::Lock lock(m_mutex);
                //SYLAR_ASSERT(m_events.size() > 0u); // single consume
                auto ev = m_events.front();
                m_events.pop_front();
                return ev;
            }
        }

        void SessionSemaphore::notify(QuicSessionEvent event) {
            MutexType::Lock lock(m_mutex);
            m_events.push_back(event);
            if (!m_waiters.empty()) {
                auto next = m_waiters.front();
                m_waiters.pop_front();
                next.first->schedule(next.second);
            }
        }

        std::string SessionSemaphore::toString() {
            std::stringstream ss;
            ss << "concurrency: " << m_events.size();
            return ss.str(); 
        }

        /// WinUpdateQueue
        void WinUpdateQueue::addStream(QuicStreamId id) {
            MutexType::Lock lock(m_mutex);
            m_queue.insert(id);
        }

        void WinUpdateQueue::addConnection() {
            MutexType::Lock lock(m_mutex);
            m_queued_conn = true;
        }

        void WinUpdateQueue::queueAll() {
            MutexType::Lock lock(m_mutex);
            if (m_queued_conn) {
                auto max_data_frame = std::make_shared<QuicMaxDataFrame>(
                        m_conn_flow_controller->getWinUpdate()
                );
                m_cb(max_data_frame);
                m_queued_conn = false;
            }
            for (const auto &id : m_queue) {
                auto stream = m_streams->getOrOpenReceiveStream(id);
                if (stream == nullptr) {
                    continue;
                }
                uint64_t offset = stream->getWinUpdate();
                SYLAR_LOG_DEBUG(g_logger) << "stream getWinUpdate offset: " << offset;
                if (offset == 0) {
                    continue;
                }
                auto max_stream_data_frame = std::make_shared<QuicMaxStreamDataFrame>(id, offset);
                m_cb(max_stream_data_frame);
            }
            m_queue.clear();
        }

	    /// QuicSession
        void QuicSession::onHasStreamData(QuicStreamId stream_id) {
            addActiveStream(stream_id);
            signalWrite();
        }

        void QuicSession::onStreamCompleted(QuicStreamId stream_id) {
            m_streams->deleteStream(stream_id);
        }

        QuicSession::QuicSession(std::shared_ptr<QuicServer> server, QuicRole role,
                QuicConnectionId::ptr cid, Address::ptr peer_addr) :
                m_server(server),
                m_role(role),
                m_cid(cid),
                m_ssl(false),
                m_peer_addr(peer_addr) {
            m_streams = std::make_shared<QuicStreamManager>(role,
                    std::bind(&QuicSession::newFlowController, this, std::placeholders::_1));
            m_pn_mgr = std::make_shared<PacketNumberManager>(1, ~0ull);
            m_rtt_stats = std::make_shared<RTTStats>();
            m_sent_packet_handler = std::make_shared<SentPacketHandler>(m_rtt_stats);
            m_received_packet_handler = std::make_shared<ReceivedPacketTracker>();
            m_retrans_queue = std::make_shared<RetransmissionQueue>();
            m_conn_flow_controler = std::make_shared<ConnectionFlowController>(
                    1.5 * (1 << 10) * 512,
                    15 * (1 << 20),
                    m_rtt_stats,
                    std::bind(&QuicSession::onHasConnectionWinUpdate, this)
            );
            m_win_update_queue = std::make_shared<WinUpdateQueue>(
                    m_streams,
                    m_conn_flow_controler,
                    std::bind(&QuicSession::queueControlFrame, this, std::placeholders::_1)
            );
            m_is_alive = true;
        }

        QuicSession::~QuicSession() {
            std::cout << "~QuicSession" << std::endl;
        }

        void QuicSession::RetransmissionQueue::addAppData(QuicFrame::ptr frame) {
            SYLAR_LOG_INFO(g_logger) << "add frame to retrans: " << frame->toString();
            m_app_data.push_back(frame);
        }

        QuicFrame::ptr QuicSession::RetransmissionQueue::getAppDataFrame(uint64_t max_len) {
            if (m_app_data.size() == 0) {
                return nullptr;
            }
            auto f = m_app_data.front();
            if (f->size() > max_len) {
                return nullptr;
            }
            m_app_data.pop_front();
            return f;
        }

        int QuicSession::handleFrame(const QuicFrame::ptr &frame, uint64_t now) {
            switch (frame->type()) {
                case QuicFrameType::STREAM : {
                    const auto &stream_frame = std::dynamic_pointer_cast<QuicStreamFrame>(frame);
                    const auto &stream = m_streams->getOrOpenReceiveStream(stream_frame->stream_id());
                    if (stream == nullptr) {
                        SYLAR_LOG_INFO(g_logger) << "handleFrame failed: cant get stream, id: "
                                                 << stream_frame->stream_id();
                        return -1;
                    }
                    auto res = stream->handleStreamFrame(stream_frame);
                    if (res->m_code != 0) {
                        SYLAR_ASSERT(0);
                    }
                    SYLAR_LOG_WARN(g_logger) << "trace now: " << GetCurrentUs()
                                             << " handleStreamFrame offset " << stream_frame->offset();
                    break;
                }
                case QuicFrameType::ACK : {
                    QuicAckFrame::ptr ack_frame = std::dynamic_pointer_cast<QuicAckFrame>(frame);
                    SYLAR_LOG_WARN(g_logger) << "trace now: " << GetCurrentUs()
                                             << " largest_ack: " << ack_frame->largestAcked()
                                             << " delay: " << ack_frame->ack_delay();
                    m_sent_packet_handler->receivedAck(ack_frame, now); // can not set time there!!! TODO
                    break;
                }
                case QuicFrameType::CONNECTION_CLOSE : {
                    QuicConnectionCloseFrame::ptr conn_close_frame = std::dynamic_pointer_cast<QuicConnectionCloseFrame>(frame);
                    if (conn_close_frame == nullptr) {
                        SYLAR_LOG_INFO(g_logger) << "handleFrame failed: cant cast connection close frame";
                        return -1;
                    }
                    if (conn_close_frame->isAppErr()) {
                        // closeRemote(); // TODO
                    }
                    //closeRemote(); // TODO
                    break;
                }
                case QuicFrameType::MAX_DATA : {
                    const auto &max_data_frame = std::dynamic_pointer_cast<QuicMaxDataFrame>(frame);
                    if (max_data_frame == nullptr) {
                        SYLAR_LOG_INFO(g_logger) << "handleFrame failed: cant cast max data frame";
                        return -1;
                    }
                    m_conn_flow_controler->updateSendWin(max_data_frame->maximum_stream_data());
                    break;
                }
                case QuicFrameType::MAX_STREAM_DATA : {
                    const auto &max_stream_data_frame = std::dynamic_pointer_cast<QuicMaxStreamDataFrame>(frame);
                    const auto &stream = m_streams->getOrOpenSendStream(max_stream_data_frame->stream_id());
                    if (stream == nullptr) {
                        SYLAR_LOG_INFO(g_logger) << "handleFrame failed: cant get stream, id: "
                                                 << max_stream_data_frame->stream_id();
                        return -1;
                    }
                    stream->updateSendWin(max_stream_data_frame->maximum_stream_data()) ;
                    break;
                }
                case QuicFrameType::DATA_BLOCKED :
                case QuicFrameType::STREAM_DATA_BLOCKED :
                case QuicFrameType::STREAM_BLOCKED :
                case QuicFrameType::STOP_SENDING : {
                    const auto &stream = m_streams->getOrOpenReceiveStream(frame->stream_id());
                    if (stream == nullptr) {
                        SYLAR_LOG_INFO(g_logger) << "handleFrame failed: cant get stream, id: "
                                                 << frame->stream_id();
                        return -1;
                    }
                    //stream->writeStream()->cancelWrite(); // TODO
                    break;
                }
                case QuicFrameType::RESET_STREAM : {
                    const auto &reset_stream_frame = std::dynamic_pointer_cast<QuicRstStreamFrame>(frame);
                    const auto &stream = m_streams->getOrOpenReceiveStream(reset_stream_frame->stream_id());
                    if (stream == nullptr) {
                        SYLAR_LOG_INFO(g_logger) << "handleFrame failed: cant get stream, id: "
                                                 << reset_stream_frame->stream_id();
                        return -1;
                    }
                    //stream->readStream()->handleRstStreamFrame(reset_stream_frame); // TODO
                    break;
                }
                default: {
                    break;
                }
            }
            return 0;
        }

        int QuicSession::handleUnpackedPacket(const QuicEPacketHeader::ptr &header, const MBuffer::ptr &buffer_block) {
            QuicFrame::ptr frame = nullptr;
            std::vector<QuicFrame::ptr> frames;
            uint64_t now = std::dynamic_pointer_cast<MBuffer_t>(buffer_block)->time;
            bool is_ack_eliciting = false;
            std::string tmp = "";
            while (1) {
                frame = QuicFrameCodec::parseNext(buffer_block);
                if (frame == nullptr) {
                    break;
                }
                if (isFrameAckEliciting(frame)) {
                    is_ack_eliciting = true;
                }
                frames.push_back(frame);
            }
            for (const auto &frame : frames) {
                handleFrame(frame, now);
                tmp += (std::to_string((uint64_t)frame->type()) + " ");
            }
            if (is_ack_eliciting) {
                SYLAR_LOG_DEBUG(g_logger) << "received packet: " << header->toString() << ", ack_eliciting: " << is_ack_eliciting;
            }
            m_received_packet_handler->receivedPacket(header->m_packet_number, now, is_ack_eliciting);
            return 0;
        }

        int QuicSession::handlePacket(const MBuffer::ptr &buffer_block) {
            const auto &dst_cid = QuicConnectionId::parseConnectionId(buffer_block);
            if (dst_cid == nullptr) {
                SYLAR_LOG_INFO(g_logger) << "parseConnectionId failed";
                return -1;
            }
            const auto &header = readPacketHeaderFrom(buffer_block);
            if (header == nullptr) {
                SYLAR_LOG_INFO(g_logger) << "handlePacket failed";
                return -1;
            }
            header->readPacketNumberFrom(buffer_block);
            SYLAR_LOG_INFO(g_logger) << "recv packet num: " << header->m_packet_number;
            //SYLAR_LOG_INFO(g_logger) << header->toString();
            handleUnpackedPacket(header, buffer_block);
            return 0;
        }

        int QuicSession::signalRead(sylar::MBuffer::ptr buffer_block) {
            RWMutexType::WriteLock lock(m_mutex);
            bool empty = m_received_queue.empty();
            if (buffer_block) {
                m_received_queue.push_back(buffer_block);
            }
            lock.unlock();
            if (empty) {
                m_session_sem.notify(QuicSessionEvent::READ);
            }
            return empty;
        }

        void QuicSession::sendPacketBuffer(MBuffer::ptr buffer_block) {
            const auto &server = getServer();
            if (server == nullptr) {
                return;
            }
            server->sendPacket(buffer_block, m_peer_addr);
        }

        bool QuicSession::maybePackProbePacket(uint64_t now) {
            return sendPacket(now);
        }

        void QuicSession::sendProbePacket() {
            MBuffer::ptr buffer = nullptr;
            while (1) {
                uint64_t now = GetCurrentUs();
                bool was_queued = m_sent_packet_handler->queueProbePacket();
                if (!was_queued) {
                    break;
                }
                if (maybePackProbePacket(now)) {
                    break;
                }
            }
        }

        void QuicSession::sendPackets() {
            uint64_t count = 0;
            m_pacing_deadline = 0;
            bool sent_packet = false;
            while (1) {
                bool cont = false;
                uint64_t now = GetCurrentUs();
                PacketSendMode send_mode = m_sent_packet_handler->sendMode();
                if (send_mode == PacketSendMode::PACKET_SEND_ANY &&
                        !m_sent_packet_handler->hasPacingBudget()) {
                    uint64_t deadline = m_sent_packet_handler->timeUntilSend();
                    if (!deadline) {
                        deadline = now + 1;
                        SYLAR_LOG_WARN(g_logger) << "timeUntilSend: imm";
                    } else {
                        SYLAR_LOG_WARN(g_logger) << "timeUntilSend: " << deadline - now;
                    }
                    m_pacing_deadline = deadline;
                    if (sent_packet) {
                        return;
                    }
                    send_mode = PacketSendMode::PACKET_SEND_ACK;
                }
                switch (send_mode) {
                    case PacketSendMode::PACKET_SEND_NONE : {
                        break;
                    }
                    case PacketSendMode::PACKET_SEND_ACK : {
                        break;
                    }
                    case PacketSendMode::PACKET_SEND_PTO_APP_DATA : {
                        sendProbePacket();
                        break;
                    }
                    case PacketSendMode::PACKET_SEND_ANY : {
                        cont = sendPacket(now);
                        SYLAR_LOG_DEBUG(g_logger) << "sentPacket cont: " << cont;
                        count++;
                        break;
                    }
                    default: {
                        break;
                    }
                }
                if (m_received_queue.size() > 0) {
                    break;
                }
                if (!cont || count > 4) {
                    break;
                }
            }
        }

        uint64_t QuicSession::appendControlFrames(std::list<QuicFrame::ptr> &frames, uint64_t max_packet_size) {
            if (m_control_frames.size() == 0) {
                return 0;
            }
            uint64_t payload_len = 0;
            for (auto it = m_control_frames.rbegin(); it != m_control_frames.rend();) {
                auto frame = *it;
                uint64_t frame_len = frame->size();
                if (payload_len + frame_len > max_packet_size) {
                    break;
                }
                frames.push_back(frame);
                SYLAR_LOG_INFO(g_logger) << "append control frame: " << frame->toString();
                payload_len += frame_len;
                it = std::list<QuicFrame::ptr>::reverse_iterator(m_control_frames.erase((++it).base()));
            }
            return payload_len;
        }

        const QuicPacketPayload::ptr QuicSession::composeNextPacket(uint64_t max_payload_size, bool ack_allow) {
            auto payload = std::make_shared<QuicPacketPayload>();
            bool has_retrans = m_retrans_queue->hasAppData();
            if (ack_allow) {
                //bool has_data = m_control_frames.size() > 0 || false;
                bool has_data = m_control_frames.size() > 0 || true;
                bool get_ack_queue = !has_retrans && !has_data;
                SYLAR_LOG_DEBUG(g_logger) << "getAckFrame: " << get_ack_queue
                                         << ", control_frame.size: " << m_control_frames.size()
                                         << ", retrans: " << has_retrans;
                auto ack_frame = m_received_packet_handler->getAckFrame(get_ack_queue);
                if (ack_frame) {
                    payload->ack = ack_frame;
                    payload->length += ack_frame->size();
                }
            }
            if (has_retrans) {
                while(1) {
                    uint64_t remain_len = max_payload_size - payload->length;
                    if (remain_len < 128) {
                        break;
                    }
                    auto frame = m_retrans_queue->getAppDataFrame(remain_len);
                    if (!frame) {
                        break;
                    }
                    payload->frames.push_back(frame);
                    payload->length += frame->size();
                }
            }
            if (true) { // bool has_app_data TODO
                payload->length += appendControlFrames(payload->frames, max_payload_size - payload->length);
                payload->length += popStreamFrames(payload->frames, max_payload_size - payload->length);
            }
            return payload;
        }

        int QuicSession::popStreamFrames(std::list<QuicFrame::ptr> &frames, uint64_t max_packet_size) {
            MutexType::Lock lock(m_active_stream_mutex);
            int payload_len = 0;
            int remain_size = max_packet_size;
            std::list<QuicStreamId> stream_queue;
            m_stream_queue.swap(stream_queue);
            while (!stream_queue.empty()) {
                if (remain_size <= 0) {
                    break;
                }
                QuicStreamId id = stream_queue.front();
                stream_queue.pop_front();
                auto stream = m_streams->getOrOpenSendStream(id);
                if (stream == nullptr) {
                    m_active_streams.erase(id);
                    continue;
                }
                auto res = stream->popStreamFrame(remain_size);
                QuicFrame::ptr frame = std::get<0>(res);
                bool has_more_data = std::get<1>(res);
                if (has_more_data) {
                    m_stream_queue.push_back(id);
                } else {
                    m_active_streams.erase(id);
                }
                if (frame == nullptr) {
                    continue;
                }
                frames.push_back(frame);
                payload_len += frame->size();
                remain_size -= payload_len;
            }
            SYLAR_LOG_DEBUG(g_logger)<< "payload_len: " << payload_len;
            return payload_len;
        }

        static MBuffer::ptr appendPacket(QuicPacketContents::ptr packet) {
            MBuffer::ptr buffer_block = std::make_shared<MBuffer>();
            auto header = packet->header;
            uint64_t pn_len = (int)header->m_packet_number_len;
            if (header->m_is_long_header) {
                header->m_length = pn_len + packet->length;
            }
            header->writeTo(buffer_block);
            if (packet->ack) {
                packet->ack->writeTo(buffer_block);
            }
            for (const auto &frame : packet->frames) {
                frame->writeTo(buffer_block);
                const auto &stream_frame = std::dynamic_pointer_cast<QuicStreamFrame>(frame);
                if (stream_frame) {
                    SYLAR_LOG_WARN(g_logger)<< "trace now: " << GetCurrentUs()
                            << " send offset: " << stream_frame->offset();
                }
            }
            return buffer_block;
        }

        bool QuicSession::sendPacket(uint64_t now) {
            uint64_t offset = m_conn_flow_controler->isNewlyBlocked();
            if (offset) {
                queueControlFrame(std::make_shared<QuicDataBlockedFrame>(offset));
            }
            m_win_update_queue->queueAll();

            uint64_t max_packet_size = 1252;
            QuicPacketContents::ptr packet_content = std::make_shared<QuicPacketContents>();
            packet_content->header = getShortHeader(m_cid, QuicPacketType::INITIAL); // TODO
            uint64_t max_payload_size = max_packet_size - packet_content->header->getLength();
            const auto &payload = composeNextPacket(max_payload_size);
            if (payload->ack == nullptr && payload->frames.size() == 0) {
                return false;
            }
            packet_content->frames = payload->frames;
            packet_content->ack = payload->ack;
            packet_content->length = payload->length;
            packet_content->buffer= appendPacket(packet_content);
            auto packet = std::make_shared<QuicPacket>();
            packet->init(now, packet_content,
                std::bind(&QuicSession::RetransmissionQueue::addAppData, shared_from_this()->m_retrans_queue, std::placeholders::_1));

            m_sent_packet_handler->sentPacket(packet, now);
            SYLAR_LOG_WARN(g_logger)<< "trace now: " << GetCurrentUs()
                    << " session inflight: " << m_sent_packet_handler->bytesInflight();
            sendPacketBuffer(packet_content->buffer);
            if (0) {
                for (const auto &frame : payload->frames) {
                    SYLAR_LOG_WARN(g_logger) << "sent packet num: " << packet_content->header->m_packet_number
                                             << ", frame: " << frame->toString();
                }
            }
            m_pn_mgr->pop();
            SYLAR_LOG_WARN(g_logger) << "trace now: " << GetCurrentUs()
                                     << " send_pn " << packet_content->header->m_packet_number;
            return true;
        }

        void QuicSession::signalWrite() {
            m_session_sem.notify(QuicSessionEvent::WRITE);
        }

        uint64_t QuicSession::nextKeepAliveTime() {
            return 0;
        }

        uint64_t QuicSession::maybeResetTimer() {
            uint64_t now = GetCurrentUs();
            uint64_t deadline = now + 30 * 1000;
            uint64_t ack_alarm = m_received_packet_handler->ackAlarm();
            if (ack_alarm) {
                SYLAR_LOG_INFO(g_logger) << "maybeResetTimer: now: " << now << ", deadline: " << deadline << ", ack_alarm: " << ack_alarm;
                deadline = std::min(deadline, ack_alarm);
            }
            uint64_t loss_time = m_sent_packet_handler->getLossDetectionTimeout();
            if (loss_time) {
                deadline = std::min(deadline, loss_time);
            }
            if (m_pacing_deadline) {
                deadline = std::min(deadline, m_pacing_deadline);
            }
            if (deadline <= now) {
                return 0;
            }
            uint64_t res = deadline - now;
            SYLAR_LOG_DEBUG(g_logger) << "maybeResetTimer: return deadline: " << res
                                     << ", loss_time: " << loss_time
                                     << ", now: " << now;
            return res;
        }

        void QuicSession::run_impl() {
            try {
                while (isAlive()) {
                    const auto &server = getServer();
                    if (server == nullptr) {
                        break;
                    }
                    uint64_t deadline = maybeResetTimer();
                    sylar::Timer::ptr timer = nullptr;
                    if (deadline) {
                        timer = IOManager::GetThis()->addTimer(deadline/1000, [this]() {
                            this->m_session_sem.notify(QuicSessionEvent::NONE);
                        });
                    } else {
                        this->m_session_sem.notify(QuicSessionEvent::NONE);
                    }
                    QuicSessionEvent event = m_session_sem.wait();
                    if (timer) {
                        timer->cancel();
                    }
                    switch (event) {
                        case QuicSessionEvent::READ : {
                            std::list<MBuffer::ptr> packets;
                            {
                                RWMutexType::WriteLock lock(m_mutex);
                                m_received_queue.swap(packets);
                            }
                            for (const auto& p : packets) {
                                handlePacket(p);
                            }
                            break;
                        }
                        case QuicSessionEvent::WRITE : {
                            break;
                        }
                        default : {
                            break;
                        }
                    }

                    if (m_received_queue.size() > 0) {
                        std::list<MBuffer::ptr> packets;
                        {
                            RWMutexType::WriteLock lock(m_mutex);
                            m_received_queue.swap(packets);
                        }
                        for (const auto& p : packets) {
                            handlePacket(p);
                        }
                    }

                    uint64_t now = GetCurrentUs();
                    uint64_t time_out = m_sent_packet_handler->getLossDetectionTimeout();
                    if (time_out && time_out < now) {
                        SYLAR_LOG_INFO(g_logger) << "call onLossDetectionTimeout timeout: " << time_out
                                                 << " < now: " << now;
                        m_sent_packet_handler->onLossDetectionTimeout();
                    }
                    sendPackets();
                }
            } catch (...) {
            }
        }

        void QuicSession::run() {
            sylar::IOManager::GetThis()->schedule(std::bind(&QuicSession::run_impl, shared_from_this()));
        }

        const QuicStream::ptr QuicSession::openStream() {
            return m_streams->openStream();
        }

        const QuicStream::ptr QuicSession::acceptStream() {
            return m_streams->acceptStream();
        }

        StreamFlowController::ptr QuicSession::newFlowController(QuicStreamId stream_id) {
            uint64_t initial_send_win = (1 << 10) * 512;
            return std::make_shared<StreamFlowController>(
                    stream_id,
                    m_conn_flow_controler,
                    std::bind(&QuicSession::onHasStreamWinUpdate, shared_from_this(), std::placeholders::_1),
                    (1 << 10) * 512,
                    (1 << 20) * 6,
                    initial_send_win,
                    m_rtt_stats
            );
        }

        void QuicSession::addActiveStream(QuicStreamId id) {
            MutexType::Lock lock(m_active_stream_mutex);
            if (m_active_streams.find(id) == m_active_streams.end()) {
                m_stream_queue.push_back(id);
                m_active_streams[id] = true;
            }
        }

        const QuicEPacketHeader::ptr QuicSession::getShortHeader(QuicConnectionId::ptr cid,
                                                           QuicPacketType type) {
            QuicPacketNumber pn = m_pn_mgr->peek();
            PacketNumberLen pn_len = PacketNumberManager::GetPacketNumberLengthForHeader(pn);
            uint8_t type_byte = 0x40 | uint8_t((uint8_t)pn_len - 1);
            QuicEPacketHeader::ptr header = std::make_shared<QuicEPacketHeader>(type_byte, false);
            header->m_packet_number = pn;
            header->m_packet_number_len = pn_len;
            header->m_dst_cid = cid;
            header->m_type = type;
            return header;
        }

        const QuicEPacketHeader::ptr QuicSession::getLongHeader(QuicConnectionId::ptr sid,
                    QuicConnectionId::ptr did, QuicPacketType type) {
            QuicPacketNumber pn = m_pn_mgr->peek();
            uint8_t type_byte = 0xc0 | (0x01 << 4);
            QuicEPacketHeader::ptr header = std::make_shared<QuicEPacketHeader>(type_byte, true);
            header->m_packet_number = pn;
            //header->m_packet_number_len = getPacketNumberLength(pn);
            header->m_packet_number_len = PacketNumberLen::PACKET_NUMBER_LEN1; // TODO
            header->m_is_long_header = true;
            header->m_src_cid = sid;
            header->m_dst_cid = did;
            header->m_type = type;
            return header;
        }

        /// QuicSessionManager
        const QuicSession::ptr QuicSessionManager::get(QuicConnectionId::ptr cid) {
            RWMutexType::ReadLock lock(m_mutex);
            const auto &it = m_sessions.find(cid->toHexString());
            return it == m_sessions.end() ? nullptr : it->second;
        }

        void QuicSessionManager::add(QuicSession::ptr session) {
            RWMutexType::WriteLock lock(m_mutex);
            m_sessions[session->getCid()->toHexString()] = session;
        }

        void QuicSessionManager::del(const std::string &cid) {
            RWMutexType::WriteLock lock(m_mutex);
            m_sessions.erase(cid);
        }

        void QuicSessionManager::clear() {
            RWMutexType::WriteLock lock(m_mutex);
            auto sessions = m_sessions;
            lock.unlock();
        }

        void QuicSessionManager::foreach(std::function<void(QuicSession::ptr)> cb) {
            RWMutexType::ReadLock lock(m_mutex);
            auto m = m_sessions;
            lock.unlock();
            for (auto& i : m) {
                cb(i.second);
            }
        }

    }
}

