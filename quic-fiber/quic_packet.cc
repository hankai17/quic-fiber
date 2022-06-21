#include "my_sylar/log.hh"
#include "my_sylar/macro.hh"
#include "my_sylar/util.hh"
#include "my_sylar/scheduler.hh"
#include "my_sylar/iomanager.hh"
#include "my_sylar/mbuffer.hh"
#include "my_sylar/address.hh"
#include "my_sylar/util.hh"
#include "my_sylar/timer.hh"

#include "quic-fiber/quic_type.hh"
#include "quic-fiber/quic_packet.hh"

namespace sylar {
    namespace quic {
        static sylar::Logger::ptr g_logger = SYLAR_LOG_NAME("system");

        static int read_cid(MBuffer::ptr buffer_block, QuicPacketHeader *header) {
            int ret = 0;
            int parsed_len = 0;
            ret = stream_read_assert(buffer_block, 1);
            if (ret < 0) {
                SYLAR_LOG_INFO(g_logger) << "read_cid failed, ret: " << ret << ", " << strerror(errno);
                return -1;
            }
            uint8_t dst_cid_len = buffer_block->readFUint8();
            buffer_block->consume(1);
            parsed_len += 1;
            ret = stream_read_assert(buffer_block, dst_cid_len);
            if (ret < 0) {
                SYLAR_LOG_INFO(g_logger) << "read_cid failed, ret: " << ret << ", " << strerror(errno);
                return -1;
            }
            std::string cid = buffer_block->toString();
            header->m_dst_cid = std::make_shared<QuicConnectionId>((const uint8_t *)cid.c_str(), dst_cid_len);
            buffer_block->consume(dst_cid_len);
            parsed_len += dst_cid_len;

            uint8_t src_cid_len = buffer_block->readFUint8();
            buffer_block->consume(1);
            parsed_len += 1;
            ret = stream_read_assert(buffer_block, src_cid_len);
            if (ret < 0) {
                SYLAR_LOG_INFO(g_logger) << "read_cid failed, ret: " << ret << ", " << strerror(errno);
                return -1;
            }
            cid = buffer_block->toString();
            header->m_src_cid = std::make_shared<QuicConnectionId>((const uint8_t *)cid.c_str(), src_cid_len);
            buffer_block->consume(src_cid_len);
            parsed_len += src_cid_len;
            return parsed_len;
        }

        QuicEPacketHeader::ptr readPacketHeaderFrom(const MBuffer::ptr &buffer_block, size_t cid_len) {
            try {
                int ret = stream_read_assert(buffer_block, 1);
                if (ret < 0) {
                    SYLAR_LOG_INFO(g_logger) << "readFrom failed, ret: " << ret << ", " << strerror(errno);
                    return nullptr;
                }
                uint8_t type_byte = buffer_block->readFUint8();
                buffer_block->consume(1);

                QuicEPacketHeader::ptr header(
                        new QuicEPacketHeader(type_byte, (type_byte & 0x80) > 0));
                if (!header->m_is_long_header) {
                    if ((header->m_type_byte & 0x40) == 0) {
                        SYLAR_LOG_INFO(g_logger) << "readFrom failed, ret: " << ret << ", " << strerror(errno);
                        return nullptr;
                    }
                    header->readShortHeaderFrom(buffer_block, cid_len);
                    return header;
                }
                header->readLongHeaderFrom(buffer_block);
                return header;
            } catch (std::exception &e) {
                SYLAR_LOG_INFO(g_logger) << "readFrom failed";
            } catch (...) {
                SYLAR_LOG_INFO(g_logger) << "readFrom failed";
            }
            return nullptr;
        }

        QuicPacketHeader::QuicPacketHeader(uint8_t type_byte, bool is_long_header)
                : m_type_byte(type_byte),
                  m_is_long_header(is_long_header) {
        }

        int QuicPacketHeader::readShortHeaderFrom(MBuffer::ptr buffer_block, size_t cid_len) {
            int ret = stream_read_assert(buffer_block, cid_len);
            if (ret < 0) {
                SYLAR_LOG_INFO(g_logger) << "readShortHeaderFrom failed, ret: " << ret << ", " << strerror(errno);
                return 0;
            }
            std::string cid = "";
            cid.resize(cid_len);
            buffer_block->read(&cid[0], cid.size());
            buffer_block->consume(cid_len);
            m_parsed_len += cid_len;
            m_dst_cid = std::make_shared<QuicConnectionId>((const uint8_t *)cid.c_str(), cid.size());
            return 0;
        }

        int QuicPacketHeader::readLongHeaderFrom(MBuffer::ptr buffer_block) {
            try {
                int ret = stream_read_assert(buffer_block, 4);
                if (ret < 0) {
                    SYLAR_LOG_INFO(g_logger) << "readLongHeaderFrom failed, ret: " << ret << ", " << strerror(errno);
                    return -1;
                }
                m_version = buffer_block->readFUint32();
                buffer_block->consume(4);
                m_parsed_len += 4;
                if (m_version != 0 && (m_type_byte & 0x40) == 0) {
                    SYLAR_LOG_INFO(g_logger) << "readLongHeaderFrom failed, ret: " << ret << ", " << strerror(errno);
                    return -1;
                }
                ret = read_cid(buffer_block, this);
                if (ret <= 0) {
                    return -1;
                }
                m_parsed_len += ret;
                if (m_version == 0) {
                    SYLAR_LOG_INFO(g_logger) << "readLongHeaderFrom failed, ret: " << ret << ", " << strerror(errno);
                    return -1;
                }
                switch ((m_type_byte & 0x30) >> 4) {
                    case 0x0: {
                        m_type = QuicPacketType::INITIAL;
                        break;
                    }
                    case 0x1: {
                        m_type = QuicPacketType::ZERO_RTT_PROTECTED;
                        break;
                    }
                    case 0x2: {
                        m_type = QuicPacketType::HANDSHAKE;
                        break;
                    }
                    case 0x3: {
                        m_type = QuicPacketType::RETRY;
                        break;
                    }
                }
                size_t field_len = 0;
                if (m_type == QuicPacketType::RETRY) {
                    uint64_t token_len = buffer_block->readAvailable() - 16;
                    if (token_len <= 0) {
                        return -1;
                    }
                    m_token.resize(token_len);
                    buffer_block->copyOut(&m_token[0], token_len);
                    buffer_block->consume(token_len);
                    m_parsed_len += token_len;
                }
                if (m_type == QuicPacketType::INITIAL) {
                    size_t token_len = 0;
                    if (!read_varint(buffer_block, token_len, field_len)) {
                        return -1;
                    }
                    m_parsed_len += field_len;
                    m_token.resize(token_len);
                    ret = stream_read_assert(buffer_block, token_len);
                    if (ret < 0) {
                        SYLAR_LOG_INFO(g_logger) << "readLongHeaderFrom failed, ret: " << ret << ", " << strerror(errno);
                        return -1;
                    }
                    buffer_block->copyOut(&m_token[0], m_token.size());
                    buffer_block->consume(m_token.size());
                    m_parsed_len += token_len;
                }
                read_varint(buffer_block, m_length, field_len);
                m_parsed_len += field_len;
            } catch (std::exception &e) {
                SYLAR_LOG_INFO(g_logger) << "readLongHeaderFrom failed";
            } catch (...) {
                SYLAR_LOG_INFO(g_logger) << "readLongHeaderFrom failed";
            }
            return 0;
        }

        /// QuicEPacketHeader
        int QuicEPacketHeader::readPacketNumberFrom(const MBuffer::ptr &buffer_block) {
            int packet_number_len = (m_type_byte & 0x3) + 1;
            switch (packet_number_len) {
                case 1 : {
                    int ret = stream_read_assert(buffer_block, 1);
                    if (ret < 0) {
                        SYLAR_LOG_INFO(g_logger) << "readPacketNumberFrom failed, ret: " << ret << ", " << strerror(errno);
                        return -1;
                    }
                    m_packet_number_len = PacketNumberLen::PACKET_NUMBER_LEN1;
                    m_packet_number = buffer_block->readFUint8();
                    buffer_block->consume(1);
                    break;
                }
                case 2 : {
                    int ret = stream_read_assert(buffer_block, 2);
                    if (ret < 0) {
                        SYLAR_LOG_INFO(g_logger) << "readPacketNumberFrom failed, ret: " << ret << ", " << strerror(errno);
                        return -1;
                    }
                    m_packet_number_len = PacketNumberLen::PACKET_NUMBER_LEN2;
                    m_packet_number = buffer_block->readFUint16();
                    buffer_block->consume(2);
                    break;
                }
                case 3 : {
                    int ret = stream_read_assert(buffer_block, 3);
                    if (ret < 0) {
                        SYLAR_LOG_INFO(g_logger) << "readPacketNumberFrom failed, ret: " << ret << ", " << strerror(errno);
                        return -1;
                    }
                    m_packet_number_len = PacketNumberLen::PACKET_NUMBER_LEN3;
                    m_packet_number = buffer_block->readFUint24();
                    buffer_block->consume(3);
                    break;
                }
                case 4 : {
                    int ret = stream_read_assert(buffer_block, 4);
                    if (ret < 0) {
                        SYLAR_LOG_INFO(g_logger) << "readPacketNumberFrom failed, ret: " << ret << ", " << strerror(errno);
                        return -1;
                    }
                    m_packet_number_len = PacketNumberLen::PACKET_NUMBER_LEN4;
                    m_packet_number = buffer_block->readFUint32();
                    buffer_block->consume(4);
                    break;
                }
                default: {
                    SYLAR_LOG_INFO(g_logger) << "readPacketNumberFrom failed" << ", " << strerror(errno);
                    return -1;
                }
            }
            return 0;
        }

        int QuicEPacketHeader::writePacketNumberTo(const MBuffer::ptr &buffer_block) {
            switch ((int)m_packet_number_len) {
                case 1 : {
                    buffer_block->writeFuint8(m_packet_number);
                    break;
                }
                case 2 : {
                    buffer_block->writeFuint16(m_packet_number);
                    break;
                }
                case 3 : {
                    buffer_block->writeFuint24(m_packet_number);
                    break;
                }
                case 4 : {
                    buffer_block->writeInt32(m_packet_number);
                    break;
                }
                default: {
                    return -1;
                }
            }
            return 0;
        }

        int QuicEPacketHeader::writeLongHeaderTo(const MBuffer::ptr &buffer_block) {
            uint8_t packet_type = 0;
            switch (m_type) {
                case QuicPacketType::INITIAL: {
                    packet_type = 0x0;
                    break;
                }
                case QuicPacketType::ZERO_RTT_PROTECTED: {
                    packet_type = 0x01;
                    break;
                }
                case QuicPacketType::HANDSHAKE: {
                    packet_type = 0x02;
                    break;
                }
                case QuicPacketType::RETRY: {
                    packet_type = 0x03;
                    break;
                }
                default: {
                    return -1;
                }
            }
            uint8_t type_byte = 0xc0 | (packet_type << 4);
            if (m_type != QuicPacketType::RETRY) {
                type_byte |= uint8_t((int)m_packet_number_len - 1);
            }
            buffer_block->writeFuint8(type_byte);
            buffer_block->writeFuint32(m_version);
            buffer_block->writeFuint8(m_dst_cid->length());
            buffer_block->copyIn(std::string((char*)(const uint8_t*)*m_dst_cid, m_dst_cid->length()));
            buffer_block->writeFuint8(m_src_cid->length());
            buffer_block->copyIn(std::string((char*)(const uint8_t*)*m_src_cid, m_src_cid->length()));

            switch (m_type) {
                case QuicPacketType::RETRY: {
                    buffer_block->copyIn(m_token);
                    return 0;
                }
                case QuicPacketType::INITIAL: {
                    buffer_block->var_encode(m_token.size());
                    buffer_block->copyIn(m_token);
                }
                default: {
                    break;
                }
            }
            buffer_block->var_encode(m_length);
            return writePacketNumberTo(buffer_block);
        }

        int QuicEPacketHeader::writeShortHeaderTo(const MBuffer::ptr &buffer_block) {
            uint8_t type_byte = 0x40 | uint8_t((int)m_packet_number_len - 1);
            if (m_key_phase == QuicKeyPhase::PHASE_1) {
                type_byte |= (1 << 2);
            }
            buffer_block->writeFuint8(type_byte);
            buffer_block->copyIn(std::string((char *)(const uint8_t*)*m_dst_cid, m_dst_cid->length()));
            return writePacketNumberTo(buffer_block);
        }

        int QuicEPacketHeader::writeTo(const MBuffer::ptr &buffer_block) {
            if (m_is_long_header) {
                return writeLongHeaderTo(buffer_block);
            }
            return writeShortHeaderTo(buffer_block);
        }

        uint64_t QuicEPacketHeader::getLength() {
            if (m_is_long_header) {
                uint64_t len = 1 /*type byte*/ + 4 /* version */
                        + 1 /* dst_cid_len */ + m_dst_cid->length() /* dst_cid */
                        + 1 /* src_cid_len */ + m_src_cid->length() /* src_cid */
                        + (int)m_packet_number_len + 2 /* length */;
                if (m_type == QuicPacketType::INITIAL) {
                    len += (MBuffer::var_size(m_token.length())
                            + m_token.length());
                }
                return len;
            }
            uint64_t len = 1 /* type byte*/ + m_dst_cid->length();
            len += (int)m_packet_number_len;
            return len;
        }

        std::string QuicEPacketHeader::toString() const {
            std::stringstream ss;
            if (m_is_long_header) {
                ss << "long header, type_byte: " << std::hex << std::setw(2) << (int)m_type_byte
                        << ", type: " << packetTypeString(m_type)
                        << ", version: " << m_version
                        << ", dcid_len: " << (int)m_dst_cid->length() << ", dcid: " << m_dst_cid->toHexString()
                        << ", scid_len: " << (int)m_src_cid->length() << ", scid: " << m_src_cid->toHexString();
                if (m_type == QuicPacketType::RETRY) {
                    // TODO
                    return ss.str();
                }
                if (m_type == QuicPacketType::INITIAL) {
                    ss << ", token_len: " << m_token.size() << ", token: " << m_token;
                }
                ss << ", length: " << m_length;
                ss << ", packet_number_len: " << (int)m_packet_number_len << ", packet_number: " << m_packet_number;
            } else {
                ss << "short header, type_byte: " << std::hex << std::setw(2) << (int)m_type_byte
                        << ", type: " << packetTypeString(m_type)
                        << ", dcid_len: " << (int)m_dst_cid->length() << ", dcid: " << m_dst_cid->toHexString()
                        << ", packet_number: " << m_packet_number;
            }
            return ss.str();
        }

        /// QuicPacket
        void QuicPacket::init(uint64_t now, QuicPacketContents::ptr packet,
                const std::function<void(QuicFrame::ptr)> &lost_fun) {
            m_pn = packet->header->m_packet_number;
            m_largest_acked = ~0ull;
            if (packet->ack) {
                m_largest_acked = packet->ack->largestAcked();
            }
            for (const auto &frame : packet->frames) {
                if (!frame->lostCb()) {
                    frame->setOnLost(lost_fun);
                }
            }
            m_frames = packet->frames;
            m_length = packet->buffer->readAvailable();
            m_send_time = now;
        }

        uint64_t QuicPacket::len() {
            return m_length;
        }

        /// QuicPacketCodec
        static QuicPacketNumber unpackHeader(MBuffer::ptr buffer_block,
                QuicPacketHeader::ptr header) {
            QuicPacketNumber no = buffer_block->readFUint32();
            buffer_block->consume(4);
            return no;
        }

        QuicPacket::ptr QuicPacketCodec::readFrom(MBuffer::ptr buffer_block,
                QuicPacketHeader::ptr header) {
            return nullptr;
        }

        /// PacketNumberManager
        PacketNumberLen PacketNumberManager::GetPacketNumberLengthForHeader(QuicPacketNumber pn) {
            if (pn < (1 << (16 - 1))) {
                return PacketNumberLen::PACKET_NUMBER_LEN2;
            }
            if (pn < (1 << (24 - 1))) {
                return PacketNumberLen::PACKET_NUMBER_LEN3;
            }
            return PacketNumberLen::PACKET_NUMBER_LEN4;
        }

        uint16_t PacketNumberManager::getRandomNumber() {
            std::random_device rnd;
            uint32_t x = rnd();
            return x % 2^16;
        }

        void PacketNumberManager::generateNewSkip() {
            QuicPacketNumber num = getRandomNumber();
            QuicPacketNumber skip = num * (m_average_period - 1) / (((1 << 16) - 1)/2);
            m_next_to_skip = m_next + 2 + skip;
        }

        QuicPacketNumber PacketNumberManager::peek() const {
            return m_next;
        }

        QuicPacketNumber PacketNumberManager::pop() {
            QuicPacketNumber next = m_next;
            m_next++;
            return next;
        }

        /// RetransmissionQueue
        void RetransmissionQueue::addAppData(QuicFrame::ptr frame) {
            m_app_data.push_back(frame);
        }

        QuicFrame::ptr RetransmissionQueue::getAppDataFrame() {
            if (m_app_data.size() == 0) {
                return nullptr;
            }
            QuicFrame::ptr frame = m_app_data.front();
            m_app_data.pop_front();
            return frame;
        }

        /// QuicPacketPack
        int QuicPacketPack::composeNextPacket(QuicSndStream::ptr send_stream, std::deque<QuicFrame::ptr> &frames) {
            return 0;
        }

        size_t QuicPacketPack::packetLength(QuicEPacketHeader::ptr header,
                const std::deque<QuicFrame::ptr> &payload) {
            size_t padding_len = 0;
            uint64_t pn_len = (int)header->m_packet_number_len;
            if (payload.size() < 4 - pn_len) {
                padding_len = 4 - pn_len - payload.size();
            }
            return header->getLength() + payload.size() + padding_len;
        }

        MBuffer::ptr QuicPacketPack::dump_into_packet_buffer(QuicEPacketHeader::ptr header,
                std::list<QuicFrame::ptr> frames, size_t payload_len) {
            MBuffer::ptr buffer_block = std::make_shared<MBuffer>();
            uint64_t pn_len = (int)header->m_packet_number_len;
            if (header->m_is_long_header) {
                header->m_length = pn_len + payload_len;
            }
            header->writeTo(buffer_block);

            for (auto &i : frames) {
                i->writeTo(buffer_block);
            }
            return buffer_block;
        }

        MBuffer::ptr QuicPacketPack::packPacket(PacketNumberManager::ptr pnm, QuicSndStream::ptr send_stream) {
            return nullptr;
        }

        /// PacketNumberLength
        PacketNumberLen PacketNumberLength::getPacketNumberLengthForHeader(QuicPacketNumber packet_num, 
                QuicPacketNumber least_unacked) {
            uint64_t diff = (uint64_t)(packet_num - least_unacked);
            if (diff < (1 << ((uint8_t)PacketNumberLen::PACKET_NUMBER_LEN2 * 8 - 1))) {
                return PacketNumberLen::PACKET_NUMBER_LEN2;
            }
            return PacketNumberLen::PACKET_NUMBER_LEN4;
        }

        PacketNumberLen PacketNumberLength::getPacketNumberLength(QuicPacketNumber packet_num) {
            if (packet_num < (1 << ((uint8_t)PacketNumberLen::PACKET_NUMBER_LEN1 * 8))) {
                return PacketNumberLen::PACKET_NUMBER_LEN1;
            }
            if (packet_num < (1 << ((uint8_t)PacketNumberLen::PACKET_NUMBER_LEN2 * 8))) {
                return PacketNumberLen::PACKET_NUMBER_LEN2;
            }
            if (packet_num < (1UL << ((uint8_t)PacketNumberLen::PACKET_NUMBER_LEN3 * 8))) {
                return PacketNumberLen::PACKET_NUMBER_LEN3;
            }
            return PacketNumberLen::PACKET_NUMBER_LEN4;
        }

    }
}
