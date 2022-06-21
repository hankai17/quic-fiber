#include "quic_type.hh"
#include "my_sylar/macro.hh"
#include "my_sylar/stream.hh"

#include <random>

namespace sylar {
    namespace quic {

        std::string packetTypeString(QuicPacketType type) {
            if (type == QuicPacketType::INITIAL) {
                return "INITIAL";
            } else if (type == QuicPacketType::ZERO_RTT_PROTECTED) {
                return "0RTT";
            } else if (type == QuicPacketType::HANDSHAKE) {
                return "HANDSHAKE";
            } else if (type == QuicPacketType::RETRY) {
                return "RETRY";
            } else if (type == QuicPacketType::VERSION_NEGOTIATION) {
                return "VERSION_NEGOTIATION";
            } else if (type == QuicPacketType::PROTECTED) {
                return "PROTECTED";
            } else if (type == QuicPacketType::STATELESS_RESET) {
                return "STATELESS_RESET";
            } else {
                return "UNDEFINED";
            }
        }

        QuicRole QuicRoleOpposite(QuicRole role) {
            if (role == QuicRole::QUIC_ROLE_NONE) {
                return QuicRole::QUIC_ROLE_NONE;
            }
            if (role == QuicRole::QUIC_ROLE_CLIENT) {
                return QuicRole::QUIC_ROLE_SERVER;
            } else {
                return QuicRole::QUIC_ROLE_CLIENT;
            }
        }

        QuicStatelessResetToken::QuicStatelessResetToken(const QuicConnectionId &conn_id, uint32_t instance_id) {
            //uint64_t data = conn_id ^ instance_id;
            // CryptoHash hash;
            //static constexpr char STATELESS_RESET_TOKEN_KEY[] = "stateless_token_reset_key";
            // TODO
            //size_t dumy;
            //QuicIntUtil::write_uint_as_nbytes()
            return;
        }

        uint64_t QuicStatelessResetToken::hashcode() const {
            return (static_cast<uint64_t>(this->m_token[0]) << 56) + (static_cast<uint64_t>(this->m_token[1]) << 48) +
                   (static_cast<uint64_t>(this->m_token[2]) << 40) + (static_cast<uint64_t>(this->m_token[3]) << 32) +
                   (static_cast<uint64_t>(this->m_token[4]) << 24) + (static_cast<uint64_t>(this->m_token[5]) << 16) +
                   (static_cast<uint64_t>(this->m_token[6]) << 8) + (static_cast<uint64_t>(this->m_token[7]));
        }

        std::string  QuicStatelessResetToken::hex() const {
            std::stringstream ss;
            ss << "0x";
            for (auto i = 0; i < QuicStatelessResetToken::LEN; i++) {
                ss << std::setfill('0') << std::setw(2) << std::hex;
                ss << std::hex << static_cast<int>(this->m_token[i]);
            }
            return ss.str();
        }

        uint8_t QuicConnectionId::SCID_LEN = 8;
        constexpr int QuicConnectionId::MIN_LENGTH_FOR_INITIAL;
        constexpr int QuicConnectionId::MAX_LENGTH;
        constexpr size_t QuicConnectionId::MAX_HEX_STR_LENGTH;

        QuicConnectionId::ptr QuicConnectionId::parseConnectionId(const MBuffer::ptr &buffer_block) {
            QuicConnectionId::ptr cid = nullptr;
            if (buffer_block->readAvailable() == 0) {
                return nullptr;
            }
            bool is_long_header = (buffer_block->toString()[0] & 0x80) > 0;
            if (!is_long_header) {
                cid = std::make_shared<QuicConnectionId>((const uint8_t*)&buffer_block->toString().c_str()[1], 4);
                return cid;
            }
            if (buffer_block->readAvailable() < 6) { // 1 + 4 + 1(n) + n
                return nullptr;
            }
            uint8_t dst_cid_len;
            memcpy(&dst_cid_len, &buffer_block->toString()[5], 1);
            if ((int)buffer_block->readAvailable() < 6 + dst_cid_len) {
                return nullptr;
            }
            cid = std::make_shared<QuicConnectionId>((const uint8_t*)&buffer_block->toString().c_str()[6],
                                                     dst_cid_len);
            return cid;
        }

        void QuicConnectionId::randomize() {
            std::random_device rnd;
            uint32_t x = rnd();
            for (int i = QuicConnectionId::SCID_LEN - 1; i >= 0; i--) {
                if (i % 4 == 0) {
                    x = rnd();
                }
                this->m_id[i] = (x >> (8 * (i % 4))) & 0xFF;
            }
            this->m_len = QuicConnectionId::SCID_LEN;
        }

        QuicConnectionId QuicConnectionId::ZERO() {
            uint8_t zero[MAX_LENGTH] = {0};
            return QuicConnectionId(zero, 0);
        }

        QuicConnectionId::QuicConnectionId() {
            this->randomize();
        }

        QuicConnectionId::QuicConnectionId(const uint8_t *buf, uint8_t len)
                : m_len(len) {
            SYLAR_ASSERT(len <= QuicConnectionId::MAX_LENGTH);
            memcpy(this->m_id, buf, std::min(static_cast<int>(len),
            QuicConnectionId::MAX_LENGTH));
        }

        bool QuicConnectionId::is_zero() const {
            for (int i = sizeof(this->m_id) - 1; i >= 0; i--) {
                if (this->m_id[i]) {
                    return false;
                }
            }
            return true;
        }

        uint64_t QuicConnectionId::hashcode() const {
            return (static_cast<uint64_t>(this->m_id[0]) << 56) + (static_cast<uint64_t>(this->m_id[1]) << 48) +
                   (static_cast<uint64_t>(this->m_id[2]) << 40) + (static_cast<uint64_t>(this->m_id[3]) << 32) +
                   (static_cast<uint64_t>(this->m_id[4]) << 24) + (static_cast<uint64_t>(this->m_id[5]) << 16) +
                   (static_cast<uint64_t>(this->m_id[6]) << 8) + (static_cast<uint64_t>(this->m_id[7]));
        }

        uint32_t QuicConnectionId::h32() const {
            return static_cast<uint32_t>(QuicIntUtil::read_nbytes_as_uint(this->m_id, 4));
        }

        std::string QuicConnectionId::toHexString() const {
            std::stringstream ss;
            for (auto i = 0; i < m_len; i++) {
                if(i > 0 && i % 32 == 0) {
                    ss << std::endl;
                }
                ss << std::setw(2) << std::setfill('0') << std::hex
                   << (int)(uint8_t)m_id[i] << " ";
            }
            return ss.str();
        }

        uint8_t QuicConnectionId::length() const {
            return m_len;
        }

        QuicFiveTuple::QuicFiveTuple(IPAddress::ptr src, IPAddress::ptr dst, int protocol)
                : m_source(src),
                  m_destination(dst),
                  m_protocol(protocol) {
            this->m_hash_code = src->getPort() + dst->getPort() + protocol;
        };

        void QuicFiveTuple::update(IPAddress::ptr src, IPAddress::ptr dst, int protocol) {
            this->m_source      = src;
            this->m_destination = dst;
            this->m_protocol    = protocol;
            this->m_hash_code = src->getPort() + dst->getPort() + protocol;
        }

        const char *QuicDebugNames::frame_type(QuicFrameType type) {
            switch (type) {
                case QuicFrameType::PADDING:
                    return "PADDING";
                case QuicFrameType::PING:
                    return "PING";
                case QuicFrameType::ACK:
                    return "ACK";
                case QuicFrameType::ACK_WITH_ECN:
                    return "ACK_WITH_ECN";
                case QuicFrameType::RESET_STREAM:
                    return "RESET_STREAM";
                case QuicFrameType::STOP_SENDING:
                    return "STOP_SENDING";
                case QuicFrameType::CRYPTO:
                    return "CRYPTO";
                case QuicFrameType::NEW_TOKEN:
                    return "NEW_TOKEN";
                case QuicFrameType::STREAM:
                    return "STREAM";
                case QuicFrameType::MAX_DATA:
                    return "MAX_DATA";
                case QuicFrameType::MAX_STREAM_DATA:
                    return "MAX_STREAM_DATA";
                case QuicFrameType::MAX_STREAMS:
                    return "MAX_STREAMS";
                case QuicFrameType::DATA_BLOCKED:
                    return "DATA_BLOCKED";
                case QuicFrameType::STREAM_DATA_BLOCKED:
                    return "STREAM_DATA_BLOCKED";
                case QuicFrameType::STREAM_BLOCKED:
                    return "STREAM_BLOCKED";
                case QuicFrameType::NEW_CONNECTION_ID:
                    return "NEW_CONNECTION_ID";
                case QuicFrameType::RETIRE_CONNECTION_ID:
                    return "RETIRE_CONNECTION_ID";
                case QuicFrameType::PATH_CHALLENGE:
                    return "PATH_CHALLENGE";
                case QuicFrameType::PATH_RESPONSE:
                    return "PATH_RESPONSE";
                case QuicFrameType::CONNECTION_CLOSE:
                    return "CONNECTION_CLOSE";
                case QuicFrameType::HANDSHAKE_DONE:
                    return "HANDSHAKE_DONE";
                default:
                    return "UNKNOWN";
            }
        }

        const char *QuicDebugNames::error_code(uint16_t code) {
            switch (code) {
                case static_cast<uint16_t>(QuicTransErrorCode::NO_ERROR):
                    return "NO_ERROR";
                case static_cast<uint16_t>(QuicTransErrorCode::INTERNAL_ERROR):
                    return "INTERNAL_ERROR";
                case static_cast<uint16_t>(QuicTransErrorCode::CONNECTION_REFUSED):
                    return "CONNECTION_REFUSED";
                case static_cast<uint16_t>(QuicTransErrorCode::FLOW_CONTROL_ERROR):
                    return "FLOW_CONTROL_ERROR";
                case static_cast<uint16_t>(QuicTransErrorCode::STREAM_LIMIT_ERROR):
                    return "STREAM_LIMIT_ERROR";
                case static_cast<uint16_t>(QuicTransErrorCode::STREAM_STATE_ERROR):
                    return "STREAM_STATE_ERROR";
                case static_cast<uint16_t>(QuicTransErrorCode::FINAL_SIZE_ERROR):
                    return "FINAL_SIZE_ERROR";
                case static_cast<uint16_t>(QuicTransErrorCode::FRAME_ENCODING_ERROR):
                    return "FRAME_ENCODING_ERROR";
                case static_cast<uint16_t>(QuicTransErrorCode::TRANSPORT_PARAMETER_ERROR):
                    return "TRANSPORT_PARAMETER_ERROR";
                case static_cast<uint16_t>(QuicTransErrorCode::CONNECTION_ID_LIMIT_ERROR):
                    return "CONNECTION_ID_LIMIT_ERROR";
                case static_cast<uint16_t>(QuicTransErrorCode::PROTOCOL_VIOLATION):
                    return "PROTOCOL_VIOLATION";
                case static_cast<uint16_t>(QuicTransErrorCode::INVALID_TOKEN):
                    return "INVALID_TOKEN";
                case static_cast<uint16_t>(QuicTransErrorCode::APPLICATION_ERROR):
                    return "APPLICATION_ERROR";
                case static_cast<uint16_t>(QuicTransErrorCode::CRYPTO_BUFFER_EXCEEDED):
                    return "CRYPTO_BUFFER_EXCEEDED";
                default:
                    if (0x0100 <= code && code <= 0x01FF) {
                        return "CRYPTO_ERROR";
                    }
            }
            return "UNKNOW";
        }

        void write_QuicStreamId(QuicStreamId stream_id, uint8_t *buf, size_t *len) {
            QuicIntUtil::write_QuicVariableInt(stream_id, buf, len);
        }

        void write_QUicOffset(QuicOffset offset, uint8_t *buf, size_t *len) {
            QuicIntUtil::write_QuicVariableInt(offset, buf, len);
        }

        int QuicVariableInt::size(const uint8_t *src) {
            return static_cast<size_t>(1 << (src[0] >> 6));
        }

        size_t QuicVariableInt::size(const std::string &src) {
            return QuicVariableInt::size((uint8_t *)src.c_str());
        }

        size_t QuicVariableInt::size(uint64_t src) {
            uint8_t flag = 0;
            if (src > 4611686018427387903) {
                return 0;
            } else if (src > 1073741823) {
                flag = 0x03;
            } else if (src > 16383) {
                flag = 0x02;
            } else if (src > 63) {
                flag = 0x01;
            } else {
                flag = 0x00;
            }
            return 1 << flag;
        }

        int QuicVariableInt::encode(uint8_t *dst, size_t dst_len, size_t &len, uint64_t src) {
            uint8_t flag = 0;
            if (src > 4611686018427387903) {
                return 1;
            } else if (src > 1073741823) {
                flag = 0x03;
            } else if (src > 16383) {
                flag = 0x02;
            } else if (src > 63) {
                flag = 0x01;
            } else {
                flag = 0x00;
            }
            len = 1 << flag;
            if (len > dst_len) {
                return 1;
            }
            size_t dummy = 0;
            QuicIntUtil::write_uint_as_nbytes(src, len, dst, &dummy);
            dst[0] |= (flag << 6);
            return 0;
        }

        int QuicVariableInt::decode(uint64_t &dst, size_t &len, const uint8_t *src, size_t src_len) {
            if (src_len < 1) {
                return -1;
            }
            len = 1 << (src[0] >> 6);
            if (src_len < len) {
                return 1;
            }
            uint8_t buf[8] = {0};
            memcpy(buf, src, len);
            buf[0] &= 0x3f;
            dst = QuicIntUtil::read_nbytes_as_uint(buf, len);
            return 0;
        }

        uint64_t QuicIntUtil::read_QuicVariableInt(const uint8_t *buf, size_t buf_len) {
            uint64_t dst = 0;
            size_t len = 0;
            QuicVariableInt::decode(dst, len, buf, buf_len);
            return dst;
        }

        void QuicIntUtil::write_QuicVariableInt(uint64_t data, uint8_t *buf, size_t *len) {
            QuicVariableInt::encode(buf, 8, *len, data);
        }

        uint64_t QuicIntUtil::read_nbytes_as_uint(const uint8_t *buf, uint8_t n) {
            uint64_t value = 0;
            memcpy(&value, buf, n);
            return be64toh(value << (64 - n * 8));
        }

        void QuicIntUtil::write_uint_as_nbytes(uint64_t value, uint8_t n, uint8_t *buf, size_t *len) {
            value = htobe64(value) >> (64 - n * 8);
            memcpy(buf, reinterpret_cast<uint8_t *>(&value), n);
            *len = n;
        }

        // buffer_assert
        int stream_read_assert(MBuffer::ptr buffer_block, size_t len) {
            int ret = buffer_block->readAvailable() >= len ? 1 : -1;
            if (ret <= 0) {
                return -1;
            }
            return 0;
        }

        bool read_varint(MBuffer::ptr buffer_block, uint64_t &field, size_t &field_len) {
            int ret = stream_read_assert(buffer_block, 1);
            if (ret < 0) {
                return false;
            }
            field_len = MBuffer::var_size(buffer_block->toString());
            ret = stream_read_assert(buffer_block, field_len);
            if (ret < 0) {
                return false;
            }
            field = MBuffer::read_QuicVariableInt(buffer_block->toChar(), field_len);
            buffer_block->consume(field_len);
            return true;
        }

        bool read_varstring(MBuffer::ptr buffer_block, std::string &field) {
            return true;
        }
}
}
