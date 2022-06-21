#include "quic_packet_sorter.hh"
#include "my_sylar/log.hh"
#include "my_sylar/macro.hh"
#include <sstream>

namespace sylar {
    namespace quic {
        static sylar::Logger::ptr g_logger = SYLAR_LOG_NAME("system");
        static int PacketsBeforeAck = 2;
        /// ReceivedPacketHistory
        bool ReceivedPacketHistory::receivedPacket(QuicPacketNumber pn) {
            if (pn < m_deleted_below) {
                return false;
            }
            auto is_new = addToRanges(pn);
            maybeDeleteOldRanges();
            return is_new;
        }

        bool ReceivedPacketHistory::addToRanges(QuicPacketNumber pn) {
            if (m_ranges.size() == 0) {
                m_ranges.push_back(std::make_shared<PacketInterval>(pn, pn));
                return true;
            }
            for (auto it = m_ranges.rbegin(); it != m_ranges.rend();) {
                if (pn >= (*it)->m_start && pn <= (*it)->m_end) {
                    return false;
                }
                if ((*it)->m_end == pn - 1) {
                    (*it)->m_end = pn;
                    return true;
                }
                if ((*it)->m_start == pn + 1) {
                    (*it)->m_start = pn;
                    auto prev_it = it;
                    prev_it++;
                    if (prev_it != m_ranges.rend() &&
                            (*prev_it)->m_end + 1 == (*it)->m_start) {
                        (*prev_it)->m_end = (*it)->m_end;
                        it = std::list<PacketInterval::ptr>::reverse_iterator(m_ranges.erase((++it).base()));
                    }
                    return true;
                }
                if (pn > (*it)->m_end) {
                    m_ranges.insert((it++).base(), std::make_shared<PacketInterval>(pn, pn));
                    return true;
                }
                ++it;
            }
            m_ranges.push_front(std::make_shared<PacketInterval>(pn, pn));
            return true;
        }

        void ReceivedPacketHistory::maybeDeleteOldRanges() {
            while (m_ranges.size() > MAX_NUMBER_ACK_RANGES) {
                m_ranges.pop_front();
            }
        }

        void ReceivedPacketHistory::deleteBelow(QuicPacketNumber pn) {
            if (pn < m_deleted_below) { // already deleted
                return;
            }
            m_deleted_below = pn;
            for (auto it = m_ranges.begin(); it != m_ranges.end();) {
                if ((*it)->m_end < pn) {
                    SYLAR_LOG_INFO(g_logger) << "deleteBelow: " << (*it)->m_end;
                    m_ranges.erase(it++);
                    SYLAR_LOG_INFO(g_logger) << "after deleteBelow: " << m_ranges.size();
                } else if (pn > (*it)->m_start && pn <= (*it)->m_end) {
                    (*it)->m_start = pn;
                    return;
                } else {
                    ++it;
                }
            }
        }

        std::vector<AckRange::ptr> ReceivedPacketHistory::getAckRanges() {
            std::vector<AckRange::ptr> ack_ranges;
            if (m_ranges.size() == 0) {
                return ack_ranges;
            }
            for (auto it = m_ranges.rbegin(); it != m_ranges.rend();) {
                ack_ranges.push_back(std::make_shared<AckRange>((*it)->m_start, (*it)->m_end));
                ++it;
            }
            return ack_ranges;
        }

        AckRange::ptr ReceivedPacketHistory::getHighestAckRange() {
            AckRange::ptr ack_range = nullptr;
            if (m_ranges.size() > 0) {
                auto packet_interval = m_ranges.back();
                ack_range = std::make_shared<AckRange>(packet_interval->m_start,
                                                       packet_interval->m_end);
            }
            return ack_range;
        }

        bool ReceivedPacketHistory::isPotentiallyDuplicate(QuicPacketNumber pn) {
            if (pn < m_deleted_below) {
                return true;
            }
            for (auto it = m_ranges.rbegin(); it != m_ranges.rend();) {
                if (pn > (*it)->m_end) {
                    return false;
                }
                if (pn <= (*it)->m_end && pn >= (*it)->m_start) {
                    return true;
                }
                ++it;
            }
            return false;
        }

        std::string ReceivedPacketHistory::toString() {
            std::stringstream ss;
            ss << "deleted below: " << m_deleted_below
               << ", size: " << m_ranges.size() << ", ";
            for (auto &it : m_ranges) {
                ss << "[" << it->start() << ", " << it->end() << "] ";
            }
            return ss.str();
        }

        /// ReceivedPacketTracker
        ReceivedPacketTracker::ReceivedPacketTracker() {
            m_packet_history = std::make_shared<ReceivedPacketHistory>();
        }

        void ReceivedPacketTracker::ignoreBelow(QuicPacketNumber pn) {
            if (pn <= m_ignore_below) {
                return;
            }
            m_ignore_below = pn;
            m_packet_history->deleteBelow(pn);
            SYLAR_LOG_INFO(g_logger) << "Ignoring all packets below " << pn;
        }

        bool ReceivedPacketTracker::isMissing(QuicPacketNumber pn) {
            if (m_last_ack == nullptr || pn < m_ignore_below) {
                return false;
            }
            return (pn < m_last_ack->largestAcked()) && 
                    (!m_last_ack->acksPacket(pn));
        }

        bool ReceivedPacketTracker::hasNewMissingPackets() {
            if (m_last_ack == nullptr) {
                return false;
            }
            auto highest_range = m_packet_history->getHighestAckRange();
            return (highest_range->m_smallest > m_last_ack->largestAcked() + 1) &&
                    (highest_range->len() == 1);
        }

        void ReceivedPacketTracker::maybeQueueAck(QuicPacketNumber pn, uint64_t recv_time, bool was_missing) {
            if (m_last_ack == nullptr) {
                if (!m_ack_queued) {
                    SYLAR_LOG_DEBUG(g_logger) << "Queuing ACK because the first packet should be acked";
                }
                m_ack_queued = true;
                return;
            }
            if (m_ack_queued) {
                return;
            }
            m_ack_eliciting_packets_received_since_last_ack++;
            if (was_missing) {
                SYLAR_LOG_DEBUG(g_logger) << "Queuing ACK because packet" << pn << " was missing before";
                m_ack_queued = true;
            }
            if (m_ack_eliciting_packets_received_since_last_ack >= PacketsBeforeAck) {
                SYLAR_LOG_DEBUG(g_logger) << "Queueing ACK because packet " << m_ack_eliciting_packets_received_since_last_ack
                        << " packets were received after the last ACK (using initial threshold: " << PacketsBeforeAck << ")";
                m_ack_queued = true;
            } else if (m_ack_alarm == 0) {
                SYLAR_LOG_DEBUG(g_logger) << "Setting ACK timer to max ack delay: " << MAX_ACK_DELAY;
		        m_ack_alarm = recv_time + MAX_ACK_DELAY;
            }
            if (hasNewMissingPackets()) {
                SYLAR_LOG_DEBUG(g_logger) << "Queuing ACK because there's a new missing packet to report";
		        m_ack_queued = true;
            }
            if (m_ack_queued) {
                m_ack_alarm = 0;
            }
        }

        void ReceivedPacketTracker::receivedPacket(QuicPacketNumber pn, uint64_t recv_time, bool should_instigate_ack) {
            MutexType::Lock lock(m_mutex);
            if (pn < m_ignore_below) {
                return;
            }
            bool is_missing = isMissing(pn);
            if (is_missing) {
                SYLAR_LOG_INFO(g_logger) << "is_missing packet come";
            }
            if (pn >= m_largest_observed) {
                m_largest_observed = pn;
                m_largest_observed_received_time = recv_time;
            }
            if (m_packet_history->receivedPacket(pn) && 
                    should_instigate_ack) {
                m_has_new_ack = true;
            }
            if (should_instigate_ack) {
                maybeQueueAck(pn, recv_time, is_missing);
            }
        }

        QuicAckFrame::ptr ReceivedPacketTracker::getAckFrame(bool only_if_queued) {
            MutexType::Lock lock(m_mutex);
            if (!m_has_new_ack) {
                return nullptr;
            }
            uint64_t now = GetCurrentUs();
            if (only_if_queued) {
                if (!m_ack_queued && 
                    (m_ack_alarm == 0 || m_ack_alarm > now)) {
                    return nullptr;
                }
                SYLAR_LOG_DEBUG(g_logger) << "Sending ACK because the ACK timer expired: "
                                         << ", m_ack_queud: " << m_ack_queued
                                         << ", m_ack_alarm: " << m_ack_alarm
                                         << ", now: " << now;
            }
            m_last_ack = std::make_shared<QuicAckFrame>();
            m_last_ack->setAckRanges(m_packet_history->getAckRanges());
            uint64_t delay = now < m_largest_observed_received_time ? 0 : now - m_largest_observed_received_time;
            m_last_ack->setAckDelay(delay);

            m_ack_alarm = 0;
            m_ack_queued = false;
            m_has_new_ack = false;
            m_ack_eliciting_packets_received_since_last_ack = 0;
            return m_last_ack;
        }

        /// SentPacketHistory
        SentPacketHistory::SentPacketHistory(RTTStats::ptr rtt_stats)
                : m_rtt_stats(rtt_stats) {
            m_highest_sent = 0;
        }

        void SentPacketHistory::sentPacket(QuicPacket::ptr packet, bool is_ack_eliciting, uint64_t now) {
            MutexType::Lock lock(m_mutex);
            if (packet->packetNumber() < m_highest_sent) {
                SYLAR_LOG_INFO(g_logger) << "non-sequential packet number use";
                SYLAR_ASSERT(0);
            }
            for (auto pn = m_highest_sent + 1; pn < packet->packetNumber(); pn++) {
                auto p = std::make_shared<QuicPacket>();
                p->setPacketNumber(pn);
                p->setTime(now);
                p->setSkip();
                m_packet_list.push_back(p);
                m_packet_map[pn] = --(m_packet_list.end());
            }
            m_highest_sent = packet->packetNumber();
            if (is_ack_eliciting) {
                m_packet_list.push_back(packet);
                m_packet_map[packet->packetNumber()] = --(m_packet_list.end());
            }
        }

        void SentPacketHistory::Iterate(std::function<bool(QuicPacket::ptr)> cb) {
            MutexType::Lock lock(m_mutex);
            for (const auto &packet : m_packet_list) {
                if (!cb(packet)) {
                    return;
                }
            }
        }

        QuicPacket::ptr SentPacketHistory::firstOutstanding() {
            MutexType::Lock lock(m_mutex);
            for (const auto &packet : m_packet_list) {
                if (!packet->declaredLost() &&
                    !packet->skippedPacket()) {
                    return packet;
                }
            }
            return nullptr;
        }

        bool SentPacketHistory::remove(QuicPacketNumber pn) {
            MutexType::Lock lock(m_mutex);
            auto it = m_packet_map.find(pn);
            if (it == m_packet_map.end()) {
                SYLAR_LOG_INFO(g_logger) << "packet " << pn << " not found in sent packet history";
                return false;
            }
            m_packet_list.erase(it->second);
            m_packet_map.erase(it->first);
            return true;
        }

        void SentPacketHistory::deleteOldPackets(uint64_t now) {
            MutexType::Lock lock(m_mutex);
            uint64_t max_age = 3 * m_rtt_stats->PTO(false);
            for (auto it = m_packet_list.begin(); it != m_packet_list.end();) {
                QuicPacket::ptr packet = *it;
                if ((now - max_age) < packet->sendTime()) {
                    break;
                }
                if (!packet->skippedPacket() && !packet->declaredLost()) {
                    ++it;
                    continue;
                }
                m_packet_map.erase(packet->packetNumber());
                m_packet_list.erase(it++);
            }
        }

        /// SentPacketHandler
        SentPacketHandler::SentPacketHandler(const RTTStats::ptr &rtt)
                : m_rtt_stats(rtt) {
            m_data_packets.m_history = std::make_shared<SentPacketHistory>(m_rtt_stats);
            m_congestion = std::make_shared<CubicSender>(GetCurrentUs(), rtt, true, 1452);
        }

        void SentPacketHandler::removeFromBytesInflight(QuicPacket::ptr packet) {
            if (packet->includedInBytesInflight()) {
                if (packet->len() > m_bytes_inflight) {
                    SYLAR_LOG_INFO(g_logger) << "negative bytes_in_flight";
                    SYLAR_ASSERT(0);
                }
                m_bytes_inflight -= packet->len();
                packet->setIncludedInBytesInflight(false);
            }
        }

        void SentPacketHandler::dropPackets() {
        }

        bool SentPacketHandler::sentPacketImpl(QuicPacket::ptr packet) {
            m_data_packets.m_largest_sent = packet->packetNumber();
            bool is_ack_eliciting = packet->frames().size() > 0;
            if (is_ack_eliciting) {
                uint64_t packet_send_time = packet->sendTime();
                if (m_data_packets.m_last_ack_eliciting_packet_time) {
                    m_send_interval = packet_send_time - m_data_packets.m_last_ack_eliciting_packet_time;
                }
                m_data_packets.m_last_ack_eliciting_packet_time = packet_send_time;
                packet->setIncludedInBytesInflight(true);
                m_bytes_inflight += packet->len();
                if (m_num_probes_to_send > 0) {
                    m_num_probes_to_send--;
                }
            }
            m_congestion->onPacketSent(packet->sendTime(), m_bytes_inflight,
                    packet->packetNumber(), packet->len(), is_ack_eliciting);
            return is_ack_eliciting;
        }

        bool SentPacketHandler::isAmplificationLimited() {
            return m_bytes_sent >= m_bytes_received * amplicationFactor;
        }

        bool SentPacketHandler::hasOutstandingPackets() {
            return m_data_packets.m_history->hasOutstandingPackets();
        }

        void SentPacketHandler::setLossDetectionTimer(int phase) {
            uint64_t old_alarm = m_alarm;
            uint64_t loss_time = m_data_packets.m_loss_time;
            if (loss_time) {
                SYLAR_LOG_INFO(g_logger) << "has Schrodinger’s packet! can not be there!";
                SYLAR_ASSERT(1);
                m_alarm = loss_time;
                return;
            }
            // isAmplificationLimited TODO
            if (!hasOutstandingPackets()) {
                m_alarm = 0;
                if (old_alarm) {
                    SYLAR_LOG_INFO(g_logger) << "Canceling loss detection timer. No packets in fligth.";
                }
                return;
            }
            // PTO alarm
            uint64_t pto = 0;
            uint64_t rtt_pto = m_rtt_stats->PTO(false);
            if (m_data_packets.m_last_ack_eliciting_packet_time) {
                pto =  m_data_packets.m_last_ack_eliciting_packet_time +
                        (rtt_pto << m_PTO_count);
            }
            SYLAR_LOG_WARN(g_logger) << "sldt phase: " << phase
                      << ", last_ack_elicit_time: " << m_data_packets.m_last_ack_eliciting_packet_time
                      << ", pto/m_alarm: " << pto
                      << ", [rtt->pto: " << rtt_pto << ", pto_count: " << m_PTO_count << "]"
                      << ", packet_interval: " << m_send_interval;
            m_alarm = pto;
        }

        void SentPacketHandler::sentPacket(QuicPacket::ptr packet, uint64_t now) {
            now = GetCurrentUs();
            m_bytes_sent += packet->len();
            bool is_ack_eliciting = sentPacketImpl(packet);
            packet->setTime(now);
            m_data_packets.m_history->sentPacket(packet, is_ack_eliciting, now);
            if (is_ack_eliciting) {
                setLossDetectionTimer(0);
            }
        }

        bool SentPacketHandler::queueProbePacket() {
            auto packet = m_data_packets.m_history->firstOutstanding();
            if (packet == nullptr) {
                return false;
            }
            SYLAR_LOG_INFO(g_logger) << "queueProbePacket: packet " << packet->packetNumber()
                                      << " pto lost! will retrans!!!";
            queueFramesForRetransmission(packet);
            packet->setLost();
            removeFromBytesInflight(packet);
            return true; 
        }

        void SentPacketHandler::queueFramesForRetransmission(QuicPacket::ptr packet) {
            if (packet->frames().size() == 0) {
                SYLAR_LOG_INFO(g_logger) << "no frames";
                SYLAR_ASSERT(0);
            }
            for (const auto &frame : packet->frames()) {
                frame->onLost(frame);
            }
            packet->clear_frames(); // TODO how to release mem ?
        }

        bool SentPacketHandler::detectLostPackets(uint64_t now) {
            m_data_packets.m_loss_time = 0;
            float max_rtt = float(std::max(m_rtt_stats->latestRTT(), m_rtt_stats->smoothedRTT()));
            float loss_delay = max_rtt * timeThreshold;
            loss_delay = loss_delay > 1.0 ? loss_delay : 1.0; // 1ms
            uint64_t lost_send_time = now - (uint64_t)(std::ceil(loss_delay));
            SYLAR_LOG_DEBUG(g_logger) << "dlp max_rtt: " << max_rtt << ", loss_delay: " << loss_delay;
            uint64_t priori_inflight = m_bytes_inflight;
            m_data_packets.m_history->Iterate([&] (QuicPacket::ptr packet) -> bool {
                if (packet->packetNumber() > m_data_packets.m_largest_acked) {
                    return false;
                }
                if (packet->declaredLost() || packet->skippedPacket()) {
                    return true;
                }
                bool packet_lost;
                int reason = 0;
                if (packet->sendTime() < lost_send_time) {
                    packet_lost = true;
                    reason = 1;
                } else if (m_data_packets.m_largest_acked >= packet->packetNumber() + packetThreshold) {
                    packet_lost = true;
                    reason = 2;
                } else if (!m_data_packets.m_loss_time) {
                    uint64_t loss_time = packet->sendTime() + (uint64_t)(std::ceil(loss_delay));
                    m_data_packets.m_loss_time = loss_time;
                    reason = 3;
                    SYLAR_LOG_INFO(g_logger) << "detectLostPackets, has Schrodinger’s packet! packet->sendtime: " << packet->sendTime()
                        << "loss_delay: " << loss_delay;
                }
                if (packet_lost) {
                    SYLAR_LOG_INFO(g_logger) << "detectLostPackets: packet " << packet->packetNumber() 
                                             << " lost!, reason: " << reason << ", will retrans!!!";
                    packet->setLost();
                    removeFromBytesInflight(packet);
                    queueFramesForRetransmission(packet);
                    m_congestion->onPacketLost(packet->packetNumber(), packet->len(), priori_inflight);
                }
                return true; 
            });
            return true;
        }

        std::vector<QuicPacket::ptr> SentPacketHandler::detectAndRemoveAckedPackets(QuicAckFrame::ptr frame) {
            std::vector<QuicPacket::ptr>().swap(m_acked_packets);
            SYLAR_ASSERT(m_acked_packets.size() == 0);
            size_t ack_range_idx = 0;
            auto lowest_acked = frame->lowestAcked();
            auto largest_acked = frame->largestAcked();
            m_data_packets.m_history->Iterate([&](QuicPacket::ptr packet) -> bool {
                if (packet->packetNumber() < lowest_acked) {
                    return true;
                }
                if (packet->packetNumber() > largest_acked) {
                    return false;
                }
                if (frame->hasMissingRanges()) {
                    const auto &ack_ranges = frame->ackRanges();
                    auto ack_range =
                            ack_ranges[ack_ranges.size() - 1 - ack_range_idx];
                    while (ack_range->m_largest < packet->packetNumber() &&
                            ack_range_idx < ack_ranges.size() - 1) {
                        ack_range_idx++;
                        ack_range = ack_ranges[ack_ranges.size() - 1 - ack_range_idx];
                    }
                    if (packet->packetNumber() < ack_range->m_smallest) {
                        return true;
                    }
                    if (packet->packetNumber() > ack_range->m_largest) {
                        return false;
                    }
                }
                if (packet->skippedPacket()) {
                    return false;
                }
                m_acked_packets.push_back(packet);
                return true;
            });
            for (const auto &packet : m_acked_packets) {
                if (packet->largestAcked() != ~0ULL) {
                    m_lowest_not_confirmed_acked =
                            std::max(m_lowest_not_confirmed_acked, packet->largestAcked() + 1);
                }
                for (const auto &frame : packet->frames()) {
                    SYLAR_LOG_INFO(g_logger) << "onAcked, pn: " << packet->packetNumber() << ", frame: " << frame->toString();
                    frame->onAcked(frame);
                }
                if (!m_data_packets.m_history->remove(packet->packetNumber())) {
                    return std::vector<QuicPacket::ptr>();
                }
            }
            return m_acked_packets;
        }

        bool SentPacketHandler::receivedAck(QuicAckFrame::ptr frame, uint64_t recv_time) {
            QuicPacketNumber largest_acked = frame->largestAcked();
            if (largest_acked > m_data_packets.m_largest_sent) {
                SYLAR_LOG_INFO(g_logger) << "Received ACK for an unsent packet";
                return false;
            }
            m_data_packets.m_largest_acked = std::max(m_data_packets.m_largest_acked,
                    largest_acked);
            uint64_t prior_inflight = m_bytes_inflight;
            auto acked_packets = detectAndRemoveAckedPackets(frame);
            if (acked_packets.size() == 0) {
                return false;
            }
            if (acked_packets.size()) {
                auto packet = acked_packets[acked_packets.size() - 1];
                if (packet->packetNumber() == frame->largestAcked()) {
                    uint64_t ack_delay = std::min(frame->ack_delay(), m_rtt_stats->maxAckDelay());
                    uint64_t real_rtt = recv_time - packet->sendTime();
                    m_rtt_stats->updateRTT(real_rtt, ack_delay, recv_time);
                    m_congestion->maybeExitSlowStart();
                }
            }
            if (!detectLostPackets(recv_time)) {
                SYLAR_LOG_INFO(g_logger) << "after detectLostPackets m_data_packets.m_loss_time:" << m_data_packets.m_loss_time;
                return false;
            }
            SYLAR_LOG_DEBUG(g_logger) << "after detectLostPackets m_data_packets.m_loss_time:" << m_data_packets.m_loss_time;
            bool acked_1RTT_packet = false;
            for (const auto &packet : acked_packets) {
                if (packet->includedInBytesInflight() && !packet->declaredLost()) {
                    m_congestion->onPacketAcked(packet->packetNumber(), packet->len(), prior_inflight, recv_time);
                }
                //SYLAR_LOG_INFO(g_logger) << "acked_packets.size: " << acked_packets.size() << ", infly: " << m_bytes_inflight;
                removeFromBytesInflight(packet);
            }
            m_PTO_count = 0;
            m_num_probes_to_send = 0;
            m_data_packets.m_history->deleteOldPackets(recv_time);
            setLossDetectionTimer(1);
            return acked_1RTT_packet;
        }

        bool SentPacketHandler::onLossDetectionTimeout() {
            std::shared_ptr<char> buffer(new char[1], [this](char* ptr) {
                delete[] ptr;
                this->setLossDetectionTimer(2);
            });

            uint64_t earliest_loss_time = m_data_packets.m_loss_time;
            if (earliest_loss_time) {
                return detectLostPackets(GetCurrentUs());
            }
            if (m_bytes_inflight == 0 && false) {
                m_PTO_count++;
                m_num_probes_to_send ++;
                return true;
            }
            if (!m_data_packets.m_history->hasOutstandingPackets()) {
                return false;
            }
            m_PTO_count++;
            SYLAR_LOG_DEBUG(g_logger) << "onLossDetectionTimeout: pto timeout, retrans";
            m_num_probes_to_send += 2;
            return true;
        }

        PacketSendMode SentPacketHandler::sendMode() {
            uint64_t num_tracked_packets = m_data_packets.m_history->len();
            if (num_tracked_packets >= 1024 * 1024 * 4) {
                return PacketSendMode::PACKET_SEND_NONE;
            }
            if (m_num_probes_to_send > 0) {
                return PacketSendMode::PACKET_SEND_PTO_APP_DATA;
            }
            if (!m_congestion->canSend(m_bytes_inflight)) {
                return PacketSendMode::PACKET_SEND_ACK;
            }
            return PacketSendMode::PACKET_SEND_ANY;
        }

    }
}
