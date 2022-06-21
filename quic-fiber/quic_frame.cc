#include <stdio.h>
#include "my_sylar/macro.hh"
#include "quic_frame.hh"

namespace sylar {
    namespace quic {
        static sylar::Logger::ptr g_logger = SYLAR_LOG_NAME("system");

        QuicFrameType QuicFrame::type(const uint8_t *buf) {
            if (buf[0] >= static_cast<uint8_t>(QuicFrameType::UNKNOWN)) {
                return QuicFrameType::UNKNOWN;
            } else if (static_cast<uint8_t>(QuicFrameType::ACK) <= buf[0] &&
                       buf[0] < static_cast<uint8_t>(QuicFrameType::RESET_STREAM)) {
                return QuicFrameType::ACK;
            } else if (static_cast<uint8_t>(QuicFrameType::STREAM) <= buf[0] &&
                       buf[0] < static_cast<uint8_t>(QuicFrameType::MAX_DATA)) {
                return QuicFrameType::STREAM;
            } else if (static_cast<uint8_t>(QuicFrameType::MAX_STREAMS) <= buf[0] &&
                       buf[0] < static_cast<uint8_t>(QuicFrameType::DATA_BLOCKED)) {
                return QuicFrameType::MAX_STREAMS;
            } else if (static_cast<uint8_t>(QuicFrameType::STREAM_BLOCKED) <= buf[0] &&
                       buf[0] < static_cast<uint8_t>(QuicFrameType::NEW_CONNECTION_ID)) {
                return QuicFrameType::STREAM_BLOCKED;
            } else if (static_cast<uint8_t>(QuicFrameType::CONNECTION_CLOSE) <= buf[0] &&
                       buf[0] < static_cast<uint8_t>(QuicFrameType::HANDSHAKE_DONE)) {
                return QuicFrameType::CONNECTION_CLOSE;
            } else {
                return static_cast<QuicFrameType>(buf[0]);
            }
        }

        std::string QuicFrame::toString() const {
            return std::string("");
        };

        /// QuicStreamFrame
        bool QuicStreamFrame::readTypeByte(uint8_t type_byte) {
            if (type_byte) {
                m_has_fin = (type_byte & 0x1) > 0;
                m_has_length_field = (type_byte & 0x2) > 0;
                m_has_offset_field = (type_byte & 0x4) > 0;
            }
            return true;
        }

        bool QuicStreamFrame::readFrom(MBuffer::ptr buffer_block) {
            int ret = 0;
            size_t streamid_len = 0;
            if (!read_varint(buffer_block, m_stream_id, streamid_len)) {
                return false;
            }
            size_t offset_len = 0;
            if (m_has_offset_field && 
                    !read_varint(buffer_block, m_offset, offset_len)) {
                return false;
            }
            size_t data_len = 0;
            uint64_t len = 0;
            if (m_has_length_field &&
                    !read_varint(buffer_block, data_len, len)) {
                return false;
            }
            ret = stream_read_assert(buffer_block, data_len);
            if (ret < 0) {
                SYLAR_LOG_INFO(g_logger) << "stream bufferRead failed, ret: " << ret << ", " << strerror(errno);
                return false;
            }
            if (m_data == nullptr) {
                m_data = std::make_shared<MBuffer>();
            }
            m_data->copyIn(*buffer_block.get(), data_len);
            buffer_block->consume(data_len);

            m_valid = true;
            m_size = 1 + streamid_len + offset_len + data_len + len;
            return true;
        }

        bool QuicStreamFrame::writeTo(MBuffer::ptr buffer_block) {
            try {
                uint8_t type_byte = static_cast<uint8_t>(QuicFrameType::STREAM);
                if (has_offset_field()) {
                    type_byte ^= 0x04;
                }
                if (has_length_field()) {
                    type_byte ^= 0x02;
                }
                if (has_fin_flag()) {
                    type_byte ^= 0x01;
                }
                buffer_block->writeFuint8(type_byte);
                buffer_block->var_encode(m_stream_id);
                if (has_offset_field()) {
                    buffer_block->var_encode(m_offset);
                }
                if (has_length_field()) {
                    buffer_block->var_encode(m_data ? m_data->readAvailable() : 0);
                }
                if (m_data && m_data->readAvailable() > 0) {
                    buffer_block->copyIn(*m_data.get(), m_data->readAvailable());
                }
                return true;
            } catch(...) {
                SYLAR_LOG_WARN(g_logger) << "write DataFrame fail, " << toString();
            }
            return false;
        }

        size_t QuicStreamFrame::size() const {
            if (m_size) {
                return m_size;
            }
            size_t size     = 1;
            size_t data_len = m_data ? m_data->readAvailable() : 0;

            size += MBuffer::var_size(m_stream_id);
            if (has_offset_field()) {
                size += MBuffer::var_size(m_offset);
            }
            if (has_length_field()) {
                size += MBuffer::var_size(data_len);
                size += data_len;
            }
            return size;
        }

        std::string QuicStreamFrame::toString() const {
            std::stringstream ss;
            ss << "[StreamFrame size: " << size() << ", id: " << m_stream_id 
                    << ", offset: " << m_offset << ", data_len: " << m_data->readAvailable()
                    << ", fin: " << has_fin_flag() << "]";
            return ss.str();
        }

        QuicOffset QuicStreamFrame::offset() const {
            if (has_offset_field()) {
                return m_offset;
            }
            return 0;
        }

        QuicStreamFrame::ptr QuicStreamFrame::maybeSplitOffFrame(size_t max_bytes) {
            if (m_data->readAvailable() <= max_bytes) {
                return nullptr;
            }
            QuicStreamFrame::ptr frame = std::make_shared<QuicStreamFrame>();
            MBuffer::ptr data = std::make_shared<MBuffer>();

            frame->set_stream_id(m_stream_id);
            frame->set_offset(m_offset);
            m_data->copyOut(*data.get(), max_bytes);
            m_data->consume(max_bytes);
            frame->set_data(data);
            m_offset += max_bytes;
            return frame;
        }

        uint64_t QuicStreamFrame::maxDataLen(uint64_t max_size) {
            size_t header_len = 1;

            header_len += MBuffer::var_size(m_stream_id);
            if (has_offset_field()) {
                header_len += MBuffer::var_size(m_offset);
            }
            if (has_length_field()) {
                header_len += 1;
            }
            if (header_len > max_size) {
                return 0;
            }
            uint64_t max_data_len = max_size - header_len;
            if (has_length_field() &&
                    MBuffer::var_size(max_data_len) != 1) {
                max_data_len--;
            }
            return max_data_len;
        }

        /// QuicCryptoFrame
        bool QuicCryptoFrame::readFrom(MBuffer::ptr buffer_block) {
            int ret = 0;
            size_t offset_len = 0;
            if (!read_varint(buffer_block, m_offset, offset_len)) {
                return false;
            }
            size_t data_len = 0;
            uint64_t len = 0;
            if (!read_varint(buffer_block, data_len, len)) {
                return false;
            }
            ret = stream_read_assert(buffer_block, data_len);
            if (ret < 0) {
                SYLAR_LOG_INFO(g_logger) << "stream bufferRead failed, ret: " << ret << ", " << strerror(errno);
                return false;
            }
            m_data.resize(data_len);
            buffer_block->copyOut(&m_data[0], m_data.size());
            buffer_block->consume(m_data.size());
            m_valid = true;
            m_size = 1 + offset_len + data_len + len;
            return true;
        }

        bool QuicCryptoFrame::writeTo(MBuffer::ptr buffer_block) {
            try {
                uint8_t type_byte = static_cast<uint8_t>(QuicFrameType::CRYPTO);
                buffer_block->writeFuint8(type_byte);
                buffer_block->var_encode(m_offset);
                buffer_block->var_encode(m_data.size());
                buffer_block->write(m_data.c_str(), m_data.size());
                return true;
            } catch(...) {
                SYLAR_LOG_WARN(g_logger) << "write DataFrame fail, " << toString();
            }
            return false;
        }

        size_t QuicCryptoFrame::size() const {
            if (this->m_size) {
                return this->m_size;
            }
            return 1 + m_data.size() + MBuffer::var_size(m_offset) +
                    MBuffer::var_size(m_data.size());
        }

        std::string QuicCryptoFrame::toString() const {
            std::stringstream ss;
            ss << "[CryptoFrame size: " << size() << ", offset: " << m_offset
               << ", data_len: " << m_data.size() << "]";
            return ss.str();
        }

        /// QuicAckFrame
        QuicAckFrame::QuicAckFrame(const std::vector<AckRange::ptr> &ack_ranges) {
            for (size_t i = 0; i < ack_ranges.size(); i++) {
                m_ack_ranges.push_back(ack_ranges[i]);
            }
        }

        bool QuicAckFrame::readTypeByte(uint8_t type_byte) {
            if (type_byte) {
                m_has_ecn = type_byte == static_cast<uint8_t>(QuicFrameType::ACK_WITH_ECN);
            }
            return true;
        }

        bool QuicAckFrame::readFrom(MBuffer::ptr buffer_block) {
            uint64_t largest = 0;
            size_t largest_ack_len = 0;
            if (!read_varint(buffer_block, largest, largest_ack_len)) {
                return false;
            }
            size_t ack_delay_len = 0;
            if (!read_varint(buffer_block, m_ack_delay, ack_delay_len)) {
                return false;
            }
            uint64_t ack_block_count = 0;
            size_t ack_block_count_len = 0;
            if (!read_varint(buffer_block, ack_block_count, ack_block_count_len)) {
                return false;
            }
            uint64_t first_ack_block = 0;
            size_t first_ack_block_len = 0;
            if (!read_varint(buffer_block, first_ack_block, first_ack_block_len)) {
                return false;
            }
            QuicPacketNumber smallest = largest - first_ack_block;
            m_ack_ranges.push_back(std::make_shared<AckRange>(smallest, largest));
            for (size_t i = 0; i < ack_block_count; i++) {
                uint64_t gap = 0;
                size_t gap_len = 0;
                uint64_t ack_block = 0;
                size_t ack_block_len = 0;

                if (!read_varint(buffer_block, gap, gap_len)) {
                    return false;
                }
                if (gap == 0) {
                    //SYLAR_ASSERT(0);
                }
                uint64_t largest = smallest - gap - 2;
                if (!read_varint(buffer_block, ack_block, ack_block_len)) {
                    return false;
                }
                smallest = largest - ack_block;
                m_ack_ranges.push_back(std::make_shared<AckRange>(smallest, largest));
            }
            if (m_has_ecn) {
                size_t ecn_count_len = 0;
                m_ecn_section = std::make_shared<EcnSection>();
                if (!read_varint(buffer_block, m_ecn_section->m_ect0_count, ecn_count_len)) {
                    return false;
                }
                if (!read_varint(buffer_block, m_ecn_section->m_ect1_count, ecn_count_len)) {
                    return false;
                }
                if (!read_varint(buffer_block, m_ecn_section->m_ecn_ce_count, ecn_count_len)) {
                    return false;
                }
            }
            m_valid = true;
            //m_size = 1 + streamid_len + offset_len + data_len + len;
            return true;
        }

        bool QuicAckFrame::writeTo(MBuffer::ptr buffer_block) {
            try {
                uint8_t type_byte = static_cast<uint8_t>(QuicFrameType::ACK);
                buffer_block->writeFuint8(type_byte);
                buffer_block->var_encode(largestAcked());
                buffer_block->var_encode(m_ack_delay);
                int ack_block_count = numEncodableAckRanges();
                buffer_block->var_encode(ack_block_count - 1);
                buffer_block->var_encode(encodeAckRange(0).len);
                for (auto i = 1; i < ack_block_count; i++) {
                    buffer_block->var_encode(encodeAckRange(i).gap);
                    buffer_block->var_encode(encodeAckRange(i).len);
                }
                return true;
            } catch(...) {
                SYLAR_LOG_WARN(g_logger) << "write DataFrame fail, " << toString();
            }
            return false;
        }

        size_t QuicAckFrame::size() const {
            if (m_size) {
                return m_size;
            }
            size_t pre_len = 1 + MBuffer::var_size(largestAcked()) +
                            MBuffer::var_size(m_ack_delay) +
                            MBuffer::var_size(m_ack_ranges.size() - 1) +
                            MBuffer::var_size(encodeAckRange(0).len);
            for (size_t i = 1; i < m_ack_ranges.size(); i++) {
                pre_len += MBuffer::var_size(encodeAckRange(i).gap);
                pre_len += MBuffer::var_size(encodeAckRange(i).len);
            }
            return pre_len;
        }

        std::string QuicAckFrame::toString() const {
#if 0
            std::stringstream ss;
            ss << "[AckFrame size: " << size() << ", largest_ack: " << largestAcked()
               << ", delay: " << ack_delay() << ", block_count: " << m_ack_ranges.size()
               << ", first_block [" << encodeAckRange(0).gap << ": " << encodeAckRange(0).len << "]";
            ss << ", [";
            for (size_t i = 1; i < m_ack_ranges.size(); i++) {
                ss << << encodeAckRange(i).gap << ": " << encodeAckRange(i).len << ", ";
            }
            ss << "]]";
            return ss.str();
#else
            std::stringstream ss;
            ss << "AckFrame size: " << size() << ", largest_ack: " << largestAcked()
               << ", delay: " << ack_delay() << ", block_count: " << m_ack_ranges.size() << ": ";
            for (size_t i = 0; i < m_ack_ranges.size(); i++) {
                ss << "[" << m_ack_ranges[i]->m_largest << ": " << m_ack_ranges[i]->m_smallest << "], ";
            }
            return ss.str();
#endif
        }
            
        QuicAckFrame::GapLenEntry QuicAckFrame::encodeAckRange(size_t idx) const {
            if (idx == 0) {
                return GapLenEntry {0, uint64_t(m_ack_ranges[0]->m_largest - m_ack_ranges[0]->m_smallest)};
            }
            return GapLenEntry {
                        uint64_t(m_ack_ranges[idx-1]->m_smallest - m_ack_ranges[idx]->m_largest - 2),
                        uint64_t(m_ack_ranges[idx]->m_largest - m_ack_ranges[idx]->m_smallest)
                    };
        }

        uint64_t QuicAckFrame::encodeAckDelay(uint64_t ack_delay) {
            return ack_delay;
        }
        
        int QuicAckFrame::numEncodableAckRanges() {
            uint64_t length = 1 + MBuffer::var_size(largestAcked()) + MBuffer::var_size(m_ack_delay);
            length += 2;
            for (size_t i = 1; i < m_ack_ranges.size(); i++) {
                GapLenEntry entry = encodeAckRange(i);
                uint64_t range_len = MBuffer::var_size(entry.gap) + MBuffer::var_size(entry.len);
                if (length + range_len > 1024) { // TODO
                    return i - 1;
                }
                length += range_len;
            }
            return m_ack_ranges.size();
        }

        QuicPacketNumber QuicAckFrame::lowestAcked() {
            return m_ack_ranges[m_ack_ranges.size() - 1]->m_smallest;
        }

        bool QuicAckFrame::acksPacket(QuicPacketNumber pn) {
            if (pn < lowestAcked() || 
                    pn > largestAcked()) {
                return false;
            }
            size_t i = 0;
            for (; i < m_ack_ranges.size(); i++) {
                if (pn >= m_ack_ranges[i]->m_smallest) {
                    break;
                }
            }
            return pn <= m_ack_ranges[i]->m_largest;
        }

        /// QuicRstStreamFrame
        size_t QuicRstStreamFrame::size() const {
            if (this->m_size) {
                return m_size;
            }
            return 1 + MBuffer::var_size(this->m_stream_id)  + MBuffer::var_size(this->m_error_code) +
                    MBuffer::var_size(this->m_final_offset);
        }

        bool QuicRstStreamFrame::readFrom(MBuffer::ptr buffer_block) {
            size_t streamid_len = 0;
            if (!read_varint(buffer_block, m_stream_id, streamid_len)) {
                return false;
            }
            size_t offset_len = 0;
            if (!read_varint(buffer_block, m_final_offset, offset_len)) {
                return false;
            }
            size_t error_code_len = 0;
            if (!read_varint(buffer_block, m_error_code, error_code_len)) {
                return false;
            }
            m_valid = true;
            m_size = 1 + streamid_len + error_code_len + offset_len;
            return true;
        }

        bool QuicRstStreamFrame::writeTo(MBuffer::ptr buffer_block) {
            try {
                uint8_t type_byte = static_cast<uint8_t>(QuicFrameType::RESET_STREAM);
                buffer_block->writeFuint8(type_byte);
                buffer_block->var_encode(m_stream_id);
                buffer_block->var_encode(m_final_offset);
                buffer_block->var_encode(m_error_code);
                return true;
            } catch(...) {
                SYLAR_LOG_WARN(g_logger) << "write DataFrame fail, " << toString();
            }
            return false;
        }

        std::string QuicRstStreamFrame::toString() const {
            std::stringstream ss;
            ss << "[RstFrame size: " << size() << ", stream_id: " << m_stream_id
               << ", error_code: " << m_error_code << ", final_offset: " << m_final_offset;
            return ss.str();
        }

        /// QuicPingFrame
        bool QuicPingFrame::readFrom(MBuffer::ptr buffer_block) {
            return true;
        }

        bool QuicPingFrame::writeTo(MBuffer::ptr buffer_block) {
            try {
                uint8_t type_byte = static_cast<uint8_t>(QuicFrameType::PING);
                buffer_block->writeFuint8(type_byte);
                return true;
            } catch(...) {
                SYLAR_LOG_WARN(g_logger) << "write DataFrame fail, " << toString();
            }
            return false;
        }

        size_t QuicPingFrame::size() const {
            return 1;
        }

        std::string QuicPingFrame::toString() const {
            std::stringstream ss;
            ss << "[PingFrame size: " << size() << "]";
            return ss.str();
        }

        /// PaddingFrame
        bool QuicPaddingFrame::readFrom(MBuffer::ptr buffer_block) {
            return true;
        }

        bool QuicPaddingFrame::writeTo(MBuffer::ptr buffer_block) {
            try {
                uint8_t type_byte = static_cast<uint8_t>(QuicFrameType::PADDING);
                buffer_block->writeFuint8(type_byte);
                return true;
            } catch(...) {
                SYLAR_LOG_WARN(g_logger) << "write DataFrame fail, " << toString();
            }
            return false;
        }

        std::string QuicPaddingFrame::toString() const {
            std::stringstream ss;
            ss << "[PADDING_STREAM size: " << this->size() << "]";
            return ss.str();
        }

        /// ConnectionCloseFrame
        bool QuicConnectionCloseFrame::readTypeByte(uint8_t type_byte) {
            if (type_byte == 0x1c) {
                if (m_frame_type == QuicFrameType::PADDING) {
                    m_frame_type = QuicFrameType::UNKNOWN;
                }
            }
            if (type_byte == 0x1d) {
                m_is_application_error = true;
            }
            return true;
        }

        bool QuicConnectionCloseFrame::readFrom(MBuffer::ptr buffer_block) {
            int ret = 0;
            size_t error_code_len = 0;
            if (!read_varint(buffer_block, m_error_code, error_code_len)) {
                return false;
            }
            if (!m_is_application_error) {
                size_t frame_type_len = 0;
                uint64_t frame_type = 0;
                if (!read_varint(buffer_block, frame_type, frame_type_len)) {
                    return false;
                }
                m_frame_type = (QuicFrameType)frame_type;
            }
            size_t reason_phase_len = 0;
            if (!read_varint(buffer_block, m_reason_phrase_len, reason_phase_len)) {
                return false;
            }
            ret = stream_read_assert(buffer_block, reason_phase_len);
            if (ret < 0) {
                SYLAR_LOG_INFO(g_logger) << "stream bufferRead failed, ret: " << ret << ", " << strerror(errno);
                return false;
            }
            m_reason_phrase.resize(m_reason_phrase_len);
            buffer_block->copyOut(&m_reason_phrase[0], m_reason_phrase.size());
            buffer_block->consume(m_reason_phrase.size());
            m_valid = true;
            //m_size = 1 + error_code_len + field_len + reason_phase_len + m_reason_phrase_len;
            return true;
        }

        bool QuicConnectionCloseFrame::writeTo(MBuffer::ptr buffer_block) {
            try {
                uint8_t type_byte = static_cast<uint8_t>(QuicFrameType::CONNECTION_CLOSE);
                if (m_is_application_error) {
                    type_byte = 0x1d;
                }
                buffer_block->writeFuint8(type_byte);
                buffer_block->var_encode(m_error_code);
                if (!m_is_application_error) {
                    buffer_block->var_encode(static_cast<uint64_t>(m_frame_type));
                }
                if (m_frame_type == QuicFrameType::UNKNOWN) {
                    m_frame_type = QuicFrameType::PADDING;
                }
                buffer_block->var_encode(m_reason_phrase_len);
                buffer_block->write(m_reason_phrase.c_str(), m_reason_phrase.size());
                return true;
            } catch(...) {
                SYLAR_LOG_WARN(g_logger) << "write DataFrame fail, " << toString();
            }
            return false;
        }

        size_t QuicConnectionCloseFrame::size() const {
            if (this->m_size) {
                return this->m_size;
            }
            size_t length = 0;
            length = 1 + MBuffer::var_size(sizeof(QuicTransErrorCode)) +
                    MBuffer::var_size(this->m_reason_phrase_len) + this->m_reason_phrase_len;
            if (m_is_application_error) {
                length += MBuffer::var_size(sizeof(QuicFrameType));
            }
            return length;
        }

        std::string QuicConnectionCloseFrame::toString() const {
            std::stringstream ss;
            ss << "[ConnectionCloseFrame: size: " << size() << ", code: "
                    << QuicDebugNames::error_code(this->error_code()) << ", frame_type: "
                    << QuicDebugNames::frame_type(this->frame_type());
            return ss.str();
        }

        /// QuicMaxDataFrame
        bool QuicMaxDataFrame::readFrom(MBuffer::ptr buffer_block) {
            size_t maximum_data_len = 0;
            if (!read_varint(buffer_block, m_maximum_data, maximum_data_len)) {
                return false;
            }
            m_valid = true;
            m_size = 1 + maximum_data_len;
            return true;
        }

        bool QuicMaxDataFrame::writeTo(MBuffer::ptr buffer_block) {
            try {
                uint8_t type_byte = static_cast<uint8_t>(QuicFrameType::MAX_DATA);
                buffer_block->writeFuint8(type_byte);
                buffer_block->var_encode(m_maximum_data);
                return true;
            } catch(...) {
                SYLAR_LOG_WARN(g_logger) << "write DataFrame fail, " << toString();
            }
            return false;
        }

        size_t QuicMaxDataFrame::size() const {
            if (this->m_size) {
                return m_size;
            }
            return sizeof(QuicFrameType) + MBuffer::var_size(this->m_maximum_data);
        }

        std::string QuicMaxDataFrame::toString() const {
            std::stringstream ss;
            ss << "[MAXDATA size: " << size() << ", maximum: " << m_maximum_data << "]";
            return ss.str();
        }

        /// MaxStreamDataFrame
        bool QuicMaxStreamDataFrame::readFrom(MBuffer::ptr buffer_block) {
            size_t streamid_len = 0;
            if (!read_varint(buffer_block, m_stream_id, streamid_len)) {
                return false;
            }
            size_t maximum_data_len = 0;
            if (!read_varint(buffer_block, m_maximum_stream_data, maximum_data_len)) {
                return false;
            }
            m_valid = true;
            m_size = 1 + streamid_len + maximum_data_len;
            return true;
        }

        bool QuicMaxStreamDataFrame::writeTo(MBuffer::ptr buffer_block) {
            try {
                uint8_t type_byte = static_cast<uint8_t>(QuicFrameType::MAX_STREAM_DATA);
                buffer_block->writeFuint8(type_byte);
                buffer_block->var_encode(m_stream_id);
                buffer_block->var_encode(m_maximum_stream_data);
                return true;
            } catch(...) {
                SYLAR_LOG_WARN(g_logger) << "write DataFrame fail, " << toString();
            }
            return false;
        }

        size_t QuicMaxStreamDataFrame::size() const {
            if (this->m_size) {
                return this->m_size;
            }
            return sizeof(QuicFrameType) + MBuffer::var_size(this->m_maximum_stream_data) +
                MBuffer::var_size(this->m_stream_id);
        }

        std::string QuicMaxStreamDataFrame::toString() const {
            std::stringstream ss;
            ss << "[MAX_STREAM_DATA size: " << size() << ", stream_id: " << m_stream_id
                    << ", maximum: " << m_maximum_stream_data << "]";
            return ss.str();
        }

        /// MaxStreamFrame
        QuicMaxStreamsFrame::QuicMaxStreamsFrame(QuicStreamType type, QuicStreamNum max_num)
            : m_type(type), m_maximum_streams(max_num) {
        }

        bool QuicMaxStreamsFrame::readFrom(MBuffer::ptr buffer_block) {
            size_t maximum_data_len = 0;
            if (!read_varint(buffer_block, m_maximum_streams, maximum_data_len)) {
                return false;
            }
            m_valid = true;
            m_size = 1 + maximum_data_len;
            return true;
        }

        bool QuicMaxStreamsFrame::writeTo(MBuffer::ptr buffer_block) {
            try {
                uint8_t type_byte = static_cast<uint8_t>(QuicFrameType::MAX_STREAMS);
                buffer_block->writeFuint8(type_byte);
                buffer_block->var_encode(m_maximum_streams);
                return true;
            } catch(...) {
                SYLAR_LOG_WARN(g_logger) << "write DataFrame fail, " << toString();
            }
            return false;
        }

        size_t QuicMaxStreamsFrame::size() const {
            if (this->m_size) {
                return this->m_size;
            }
            return sizeof(QuicFrameType) + MBuffer::var_size(this->m_maximum_streams);
        }

        std::string QuicMaxStreamsFrame::toString() const {
            std::stringstream ss;
            ss << "[MAX_STREAMS size: " << size() << ", maximum: " << m_maximum_streams << "]";
            return ss.str();
        }

        /// QuicDataBlockFrame
        bool QuicDataBlockedFrame::readFrom(MBuffer::ptr buffer_block) {
            size_t offset_len = 0;
            if (!read_varint(buffer_block, m_offset, offset_len)) {
                return false;
            }
            m_valid = true;
            m_size = 1 + offset_len;
            return true;
        }

        bool QuicDataBlockedFrame::writeTo(MBuffer::ptr buffer_block) {
            try {
                uint8_t type_byte = static_cast<uint8_t>(QuicFrameType::DATA_BLOCKED);
                buffer_block->writeFuint8(type_byte);
                buffer_block->var_encode(m_offset);
                return true;
            } catch(...) {
                SYLAR_LOG_WARN(g_logger) << "write DataFrame fail, " << toString();
            }
            return false;
        }

        size_t QuicDataBlockedFrame::size() const {
            if (this->m_size) {
                return this->m_size;
            }
            return sizeof(QuicFrameType) + MBuffer::var_size(this->m_offset);
        }

        std::string QuicDataBlockedFrame::toString() const {
            std::stringstream ss;
            ss << "[DataBlocked size: " << size() << ", offset: " << m_offset << "]";
            return ss.str();
        }

        /// StreamDataBlockedFrame
        bool QuicStreamDataBlockedFrame::readFrom(MBuffer::ptr buffer_block) {
            size_t streamid_len = 0;
            if (!read_varint(buffer_block, m_stream_id, streamid_len)) {
                return false;
            }
            size_t offset_len = 0;
            if (!read_varint(buffer_block, m_offset, offset_len)) {
                return false;
            }
            m_valid = true;
            m_size = 1 + streamid_len + offset_len;
            return true;
        }

        bool QuicStreamDataBlockedFrame::writeTo(MBuffer::ptr buffer_block) {
            try {
                uint8_t type_byte = static_cast<uint8_t>(QuicFrameType::STREAM_DATA_BLOCKED);
                buffer_block->writeFuint8(type_byte);
                buffer_block->var_encode(m_stream_id);
                buffer_block->var_encode(m_offset);
                return true;
            } catch(...) {
                SYLAR_LOG_WARN(g_logger) << "write DataFrame fail, " << toString();
            }
            return false;
        }

        size_t QuicStreamDataBlockedFrame::size() const {
            if (this->m_size) {
                return this->m_size;
            }
            return sizeof(QuicFrameType) + MBuffer::var_size(this->m_offset) +
                MBuffer::var_size(this->m_stream_id);
        }

        std::string QuicStreamDataBlockedFrame::toString() const {
            std::stringstream ss;
            ss << "[StreamDataBlocked size: " << size() << ", stream_id: " << m_stream_id
                    << ", offset: " << m_offset << "]";
            return ss.str();
        }

        /// StreamsBlockFrame
        QuicStreamsBlockedFrame::QuicStreamsBlockedFrame(QuicStreamType type, QuicStreamNum num)
            : m_stream_type(type),
              m_stream_limit(num) {
        }

        bool QuicStreamsBlockedFrame::readTypeByte(uint8_t type_byte) {
            if (type_byte == 0x16) {
                m_stream_type = QuicStreamType::QuicStreamTypeBidi;
                return true;
            }
            m_stream_type = QuicStreamType::QuicStreamTypeUni;
            return true;
        }

        bool QuicStreamsBlockedFrame::readFrom(MBuffer::ptr buffer_block) {
            size_t stream_limit_len = 0;
            if (!read_varint(buffer_block, m_stream_limit, stream_limit_len)) {
                return false;
            }
            m_valid = true;
            m_size = 1 + stream_limit_len;
            return true;
        }

        bool QuicStreamsBlockedFrame::writeTo(MBuffer::ptr buffer_block) {
            try {
                uint8_t type_byte;
                if (m_stream_type == QuicStreamType::QuicStreamTypeBidi) {
                    type_byte = static_cast<uint8_t>(QuicFrameType::STREAM_BLOCKED);
                } else {
                    type_byte = static_cast<uint8_t>(QuicFrameType::STREAM_BLOCKED) + 1;
                }
                buffer_block->writeFuint8(type_byte);
                buffer_block->var_encode(m_stream_limit);
                return true;
            } catch(...) {
                SYLAR_LOG_WARN(g_logger) << "write DataFrame fail, " << toString();
            }
            return false;
        }

        size_t QuicStreamsBlockedFrame::size() const {
            if (this->m_size) {
                return this->m_size;
            }
            return sizeof(QuicFrameType) + MBuffer::var_size(this->m_stream_limit);
        }

        std::string QuicStreamsBlockedFrame::toString() const {
            std::stringstream ss;
            ss << "[STREAMS_BLOCK_FRAME size: " << size() << ", stream_limit: "
                    << m_stream_limit << "]";
            return ss.str();
        }

        /// QuicNewConnectionIdFrame
        bool QuicNewConnectionIdFrame::readFrom(MBuffer::ptr buffer_block) {
            int ret = 0;
            size_t seq_len = 0;
            if (!read_varint(buffer_block, m_sequence, seq_len)) {
                return false;
            }
            size_t retire_prior_len = 0;
            if (!read_varint(buffer_block, m_retire_prior_to, retire_prior_len)) {
                return false;
            }
            size_t cid_len = buffer_block->readFUint8();
            buffer_block->consume(1);
            ret = stream_read_assert(buffer_block, cid_len);
            if (ret < 0) {
                return false;
            }
            m_connection_id = QuicConnectionId((uint8_t*)(buffer_block->toString().c_str()), cid_len);
            buffer_block->consume(cid_len);
            ret = stream_read_assert(buffer_block, QuicStatelessResetToken::LEN);
            if (ret < 0) {
                return false;
            }
            m_stateless_reset_token = QuicStatelessResetToken((uint8_t*)(buffer_block->toString().c_str()));
            m_valid = true;
            m_size = 1 + seq_len + retire_prior_len + 1 + cid_len + QuicStatelessResetToken::LEN;
            return true;
        }

        bool QuicNewConnectionIdFrame::writeTo(MBuffer::ptr buffer_block) {
            try {
                uint8_t type_byte = static_cast<uint8_t>(QuicFrameType::NEW_CONNECTION_ID);
                buffer_block->writeFuint8(type_byte);
                buffer_block->var_encode(m_sequence);
                buffer_block->var_encode(m_retire_prior_to);
                buffer_block->var_encode(m_connection_id.length());
                buffer_block->write(m_connection_id, m_connection_id.length());
                buffer_block->write(m_stateless_reset_token.buf(), QuicStatelessResetToken::LEN);
                return true;
            } catch(...) {
                SYLAR_LOG_WARN(g_logger) << "write DataFrame fail, " << toString();
            }
            return false;
        }

        size_t QuicNewConnectionIdFrame::size() const {
            if (m_size) {
                return m_size;
            }
            return sizeof(QuicFrameType) + MBuffer::var_size(m_sequence)
                    + MBuffer::var_size(m_retire_prior_to) + 1 + m_connection_id.length()
                    + QuicStatelessResetToken::LEN;
        }

        std::string QuicNewConnectionIdFrame::toString() const {
            std::stringstream ss;
            ss << "[NEW_CONNECTION_ID size: " << size() << ", seq: " << sequence()
                    << ", rpt: " << retire_prior_to() << ", cid: " << connection_id().toHexString().c_str()
                    << "]";
            return ss.str();
        }

        /// StopSendingFrame
        bool QuicStopSendingFrame::readFrom(MBuffer::ptr buffer_block) {
            size_t streamid_len = 0;
            if (!read_varint(buffer_block, m_stream_id, streamid_len)) {
                return false;
            }
            size_t error_code_len = 0;
            if (!read_varint(buffer_block, m_error_code, error_code_len)) {
                return false;
            }
            m_valid = true;
            m_size = 1 + streamid_len + error_code_len;
            return true;
        }

        bool QuicStopSendingFrame::writeTo(MBuffer::ptr buffer_block) {
            try {
                uint8_t type_byte = static_cast<uint8_t>(QuicFrameType::STOP_SENDING);
                buffer_block->writeFuint8(type_byte);
                buffer_block->var_encode(m_stream_id);
                buffer_block->var_encode(m_error_code);
                return true;
            } catch(...) {
                SYLAR_LOG_WARN(g_logger) << "write DataFrame fail, " << toString();
            }
            return false;
        }

        size_t QuicStopSendingFrame::size() const {
            if (this->m_size) {
                return this->m_size;
            }
            return sizeof(QuicFrameType) + MBuffer::var_size(this->m_stream_id) +
           MBuffer::var_size(this->m_error_code);
        }

        std::string QuicStopSendingFrame::toString() const {
            std::stringstream ss;
            ss << "[STOP_SENDING size: " << size() << ", stream_id: " << stream_id()
                    << ", error_code: " << error_code() << "]";
            return ss.str();
        }

        /// PathChallengeFrame
        bool QuicPathChallengeFrame::readFrom(MBuffer::ptr buffer_block) {
            int ret = stream_read_assert(buffer_block, QuicPathChallengeFrame::DATA_LEN);
            if (ret < 0) {
                return false;
            }
            m_data = std::string((char*)(buffer_block->toString().c_str()), QuicPathChallengeFrame::DATA_LEN);
            m_valid = true;
            m_size = 1 + QuicPathChallengeFrame::DATA_LEN;
            return true;
        }

        bool QuicPathChallengeFrame::writeTo(MBuffer::ptr buffer_block) {
            try {
                uint8_t type_byte = static_cast<uint8_t>(QuicFrameType::PATH_CHALLENGE);
                buffer_block->writeFuint8(type_byte);
                buffer_block->write(m_data.c_str(), QuicPathChallengeFrame::DATA_LEN);
                return true;
            } catch(...) {
                SYLAR_LOG_WARN(g_logger) << "write DataFrame fail, " << toString();
            }
            return false;
        }

        size_t QuicPathChallengeFrame::size() const {
            if (this->m_size) {
                return this->m_size;
            }
            return 1 + QuicPathChallengeFrame::DATA_LEN;
        }

        std::string QuicPathChallengeFrame::toString() const {
            std::stringstream ss;
            ss << "[PathChallenge size: " << size() << ", data: " << m_data << "]";
            return ss.str();
        }

        /// PathResponseFrame
        bool QuicPathResponseFrame::readFrom(MBuffer::ptr buffer_block) {
            int ret = stream_read_assert(buffer_block, QuicPathResponseFrame::DATA_LEN);
            if (ret < 0) {
                return false;
            }
            m_data = std::string((char*)(buffer_block->toString().c_str()), QuicPathResponseFrame::DATA_LEN);
            m_valid = true;
            m_size = 1 + QuicPathResponseFrame::DATA_LEN;
            return true;
        }

        bool QuicPathResponseFrame::writeTo(MBuffer::ptr buffer_block) {
            try {
                uint8_t type_byte = static_cast<uint8_t>(QuicFrameType::PATH_RESPONSE);
                buffer_block->writeFuint8(type_byte);
                buffer_block->write(m_data.c_str(), QuicPathResponseFrame::DATA_LEN);
                return true;
            } catch(...) {
                SYLAR_LOG_WARN(g_logger) << "write DataFrame fail, " << toString();
            }
            return false;
        }

        size_t QuicPathResponseFrame::size() const {
            return 1 + 8;
        }

        std::string QuicPathResponseFrame::toString() const {
            std::stringstream ss;
            ss << "[PathResponse size: " << size() << ", data: " << m_data << "]";
            return ss.str();
        }

        /// NewTokenFrame
        bool QuicNewTokenFrame::readFrom(MBuffer::ptr buffer_block) {
            size_t token_len = 0;
            if (!read_varint(buffer_block, m_token_len, token_len)) {
                return false;
            }
            int ret = stream_read_assert(buffer_block, m_token_len);
            if (ret < 0) {
                SYLAR_LOG_INFO(g_logger) << "stream bufferRead failed, ret: " << ret << ", " << strerror(errno);
                return false;
            }
            m_token.resize(m_token_len);
            buffer_block->copyOut(&m_token[0], m_token.size());
            buffer_block->consume(m_token.size());
            m_valid = true;
            m_size = 1 + token_len + m_token_len;
            return true;
        }

        bool QuicNewTokenFrame::writeTo(MBuffer::ptr buffer_block) {
            try {
                uint8_t type_byte = static_cast<uint8_t>(QuicFrameType::NEW_TOKEN);
                buffer_block->writeFuint8(type_byte);
                buffer_block->var_encode(m_token_len);
                buffer_block->write(m_token.c_str(), m_token.size());
                return true;
            } catch(...) {
                SYLAR_LOG_WARN(g_logger) << "write DataFrame fail, " << toString();
            }
            return false;
        }

        size_t QuicNewTokenFrame::size() const {
            if (this->m_size) {
                return this->m_size;
            }
            return 1 + MBuffer::var_size(this->m_token_len) + this->token_length();
        }

        std::string QuicNewTokenFrame::toString() const {
            std::stringstream ss;
            ss << "[NEW_TOKEN size: " << size() << ", token: " << m_token << "]";
            return ss.str();
        }

        /// RetireConnectionIdFrame
        bool QuicRetireConnectionIdFrame::readFrom(MBuffer::ptr buffer_block) {
            size_t seq_num_len = 0;
            if (!read_varint(buffer_block, m_seq_num, seq_num_len)) {
                return false;
            }
            m_valid = true;
            m_size = 1 + seq_num_len;
            return true;
        }

        bool QuicRetireConnectionIdFrame::writeTo(MBuffer::ptr buffer_block) {
            try {
                uint8_t type_byte = static_cast<uint8_t>(QuicFrameType::RETIRE_CONNECTION_ID);
                buffer_block->writeFuint8(type_byte);
                buffer_block->var_encode(m_seq_num);
                return true;
            } catch(...) {
                SYLAR_LOG_WARN(g_logger) << "write DataFrame fail, " << toString();
            }
            return false;
        }

        size_t QuicRetireConnectionIdFrame::size() const {
            if (this->m_size) {
                return this->m_size;
            }
            return sizeof(QuicFrameType) + MBuffer::var_size(this->m_seq_num);
        }

        std::string QuicRetireConnectionIdFrame::toString() const {
            std::stringstream ss;
            ss << "[RETIRE_CONNECTION_ID size: " << size() << ", seq num: " << m_seq_num << "]";
            return ss.str();
        }

        /// HandshakeDoneFrame
        bool QuicHandshakeDoneFrame::readFrom(MBuffer::ptr buffer_block) {
            m_valid = true;
            m_size = 1;
            return true;
        }

        bool QuicHandshakeDoneFrame::writeTo(MBuffer::ptr buffer_block) {
            try {
                uint8_t type_byte = static_cast<uint8_t>(QuicFrameType::HANDSHAKE_DONE);
                buffer_block->writeFuint8(type_byte);
                return true;
            } catch(...) {
                SYLAR_LOG_WARN(g_logger) << "write DataFrame fail, " << toString();
            }
            return false;
        }

        size_t QuicHandshakeDoneFrame::size() const {
            return 1;
        }

        std::string QuicHandshakeDoneFrame::toString() const {
            std::stringstream ss;
            ss << "[HANDSHAKE_DONE size: " << size() << "]";
            return ss.str();
        }

        /// QuicFrameCodec
        QuicFrame::ptr QuicFrameCodec::parseNext(const MBuffer::ptr &buffer_block, QuicEncryptionLevel level) {
            while (1) {
                int ret = stream_read_assert(buffer_block, 1);
                if (ret < 0) {
                    return nullptr;
                }
                uint8_t type_byte = buffer_block->readFUint8();
                /*
                std::cout << std::setw(2) << std::setfill('0') << std::hex
                 << "type_byte: " << (int)type_byte << std::endl;
                */
                buffer_block->consume(1);
                if (type_byte == 0x0) { // PADDING frame
                    continue;
                }
                return parseFrame(buffer_block, type_byte, level);
            }
            return nullptr;
        }

        QuicFrame::ptr QuicFrameCodec::parseFrame(const MBuffer::ptr &buffer_block, uint8_t type_byte, QuicEncryptionLevel level) {
            QuicFrame::ptr frame = nullptr;
            if ((type_byte & 0xf8) == 0x8) {
                frame = std::make_shared<QuicStreamFrame>();
                frame->readTypeByte(type_byte);
                if (!frame->readFrom(buffer_block)) {
                    SYLAR_LOG_INFO(g_logger) << "parse buffer_block frame failed";
                    return nullptr;
                }
                return frame;
            } else {
                switch (type_byte) {
                    case 0x1: {
                        frame = std::make_shared<QuicPingFrame>();
                        if (!frame->readFrom(buffer_block)) {
                            SYLAR_LOG_INFO(g_logger) << "parse ping frame failed";
                            return nullptr;
                        }
                        break;
                    }
                    case 0x2:
                    case 0x3: {
                        // m_ack_delay_exponent =
                        // ecnLevel
                        frame = std::make_shared<QuicAckFrame>();
                        frame->readTypeByte(type_byte);
                        if (!frame->readFrom(buffer_block)) {
                            SYLAR_LOG_INFO(g_logger) << "parse ack frame failed";
                            return nullptr;
                        }
                        break;
                    }
                    case 0x4: {
                        frame = std::make_shared<QuicRstStreamFrame>();
                        if (!frame->readFrom(buffer_block)) {
                            SYLAR_LOG_INFO(g_logger) << "parse rst buffer_block frame failed";
                            return nullptr;
                        }
                        break;
                    }
                    case 0x5: {
                        frame = std::make_shared<QuicStopSendingFrame>();
                        if (!frame->readFrom(buffer_block)) {
                            SYLAR_LOG_INFO(g_logger) << "parse stop sending frame failed";
                            return nullptr;
                        }
                        break;
                    }
                    case 0x6: {
                        frame = std::make_shared<QuicCryptoFrame>();
                        if (!frame->readFrom(buffer_block)) {
                            SYLAR_LOG_INFO(g_logger) << "parse crypto frame failed";
                            return nullptr;
                        }
                        break;
                    }
                    case 0x7: {
                        frame = std::make_shared<QuicNewTokenFrame>();
                        if (!frame->readFrom(buffer_block)) {
                            SYLAR_LOG_INFO(g_logger) << "parse new token frame failed";
                            return nullptr;
                        }
                        break;
                    }
                    case 0x10: {
                        frame = std::make_shared<QuicMaxDataFrame>();
                        if (!frame->readFrom(buffer_block)) {
                            SYLAR_LOG_INFO(g_logger) << "parse max data frame failed";
                            return nullptr;
                        }
                        break;
                    }
                    case 0x11: {
                        frame = std::make_shared<QuicMaxStreamDataFrame>();
                        if (!frame->readFrom(buffer_block)) {
                            SYLAR_LOG_INFO(g_logger) << "parse max buffer_block data frame failed";
                            return nullptr;
                        }
                        break;
                    }
                    case 0x12:
                    case 0x13: {
                        frame = std::make_shared<QuicMaxStreamsFrame>();
                        if (!frame->readFrom(buffer_block)) {
                            SYLAR_LOG_INFO(g_logger) << "parse max buffer_block frame failed";
                            return nullptr;
                        }
                        break;
                    }
                    case 0x14: {
                        frame = std::make_shared<QuicDataBlockedFrame>();
                        if (!frame->readFrom(buffer_block)) {
                            SYLAR_LOG_INFO(g_logger) << "parse data blocked frame failed";
                            return nullptr;
                        }
                        break;
                    }
                    case 0x15: {
                        frame = std::make_shared<QuicStreamDataBlockedFrame>();
                        if (!frame->readFrom(buffer_block)) {
                            SYLAR_LOG_INFO(g_logger) << "parse buffer_block data blocked frame failed";
                            return nullptr;
                        }
                        break;
                    }
                    case 0x16:
                    case 0x17: {
                        frame = std::make_shared<QuicStreamsBlockedFrame>();
                        frame->readTypeByte(type_byte);
                        if (!frame->readFrom(buffer_block)) {
                            SYLAR_LOG_INFO(g_logger) << "parse buffer_block blocked frame failed";
                            return nullptr;
                        }
                        break;
                    }
                    case 0x18: {
                        frame = std::make_shared<QuicNewConnectionIdFrame>();
                        if (!frame->readFrom(buffer_block)) {
                            SYLAR_LOG_INFO(g_logger) << "parse new connectionId frame failed";
                            return nullptr;
                        }
                        break;
                    }
                    case 0x19: {
                        frame = std::make_shared<QuicRetireConnectionIdFrame>();
                        if (!frame->readFrom(buffer_block)) {
                            SYLAR_LOG_INFO(g_logger) << "parse retire connectionId frame failed";
                            return nullptr;
                        }
                        break;
                    }
                    case 0x1a: {
                        frame = std::make_shared<QuicPathChallengeFrame>();
                        if (!frame->readFrom(buffer_block)) {
                            SYLAR_LOG_INFO(g_logger) << "parse path challenge frame failed";
                            return nullptr;
                        }
                        break;
                    }
                    case 0x1b: {
                        frame = std::make_shared<QuicPathResponseFrame>();
                        if (!frame->readFrom(buffer_block)) {
                            SYLAR_LOG_INFO(g_logger) << "parse path response frame failed";
                            return nullptr;
                        }
                        break;
                    }
                    case 0x1c:
                    case 0x1d: {
                        frame = std::make_shared<QuicConnectionCloseFrame>();
                        frame->readTypeByte(type_byte);
                        if (!frame->readFrom(buffer_block)) {
                            SYLAR_LOG_INFO(g_logger) << "parse connection close frame failed";
                            return nullptr;
                        }
                        break;
                    }
                    case 0x1e: {
                        frame = std::make_shared<QuicHandshakeDoneFrame>();
                        if (!frame->readFrom(buffer_block)) {
                            SYLAR_LOG_INFO(g_logger) << "parse handshake done frame failed";
                            return nullptr;
                        }
                        break;
                    }
                    case 0x30:
                    case 0x31: {
                        /*
                        if (m_support_datagrams) {
                            // TODO frame = parseDataGramFrame()
                        }
                         */
                        break;
                    }
                    default:
                        break;
                }
                return frame;
            }
        }

        bool isFrameAckEliciting(const QuicFrame::ptr &frame) {
            bool is_ack = false;
            bool is_conn_close = false;
            switch ((int)frame->type()) {
                case 0x2:
                case 0x3: {
                    is_ack = true;
                    break;
                }
                case 0x1c:
                case 0x1d: {
                    is_conn_close = true;
                    break;
                }
                default:
                    break;
            }
            return !is_ack && !is_conn_close; 
        }

        bool hasAckElicitingFrames(const std::list<QuicFrame::ptr> &frames) {
            for (const auto &frame : frames) {
                if (isFrameAckEliciting(frame)) {
                    return true;
                }
            }
            return false;
        }
    }
}
