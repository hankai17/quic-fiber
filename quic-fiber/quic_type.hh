#ifndef __QUIC_TYPE_HH__
#define __QUIC_TYPE_HH__

#include "my_sylar/address.hh"
#include "my_sylar/stream.hh"

namespace sylar {
    namespace quic {

        using QuicStreamNum     = uint64_t;
        using QuicStreamId      = uint64_t;
        using QuicPacketNumber  = uint64_t;
        using QuicVersion       = uint32_t;
        using QuicOffset        = uint64_t;
        using QuicFrameId       = uint64_t;
        using QuicAppErrCode    = uint64_t;

        class QuicConnectionId;


        enum class QuicRole {
            QUIC_ROLE_NONE   = -1,
            QUIC_ROLE_CLIENT = 0,
            QUIC_ROLE_SERVER,
        };

        QuicRole QuicRoleOpposite(QuicRole role);

        enum class QuicStreamType : uint8_t {
            QuicStreamTypeUni  = 0,
            QuicStreamTypeBidi = 1,
        };

        enum class QuicSessionEvent : uint8_t {
            NONE = 0,
            READ = 1,
            WRITE = 2,
        };

        enum class QuicEncryptionLevel {
            NONE        = -1,
            INITIAL     = 0,
            ZERO_RTT    = 1,
            HANDSHAKE   = 2,
            ONE_RTT     = 3,
        };

        enum class QuicFrameType : uint8_t {
            PADDING = 0x0,
            PING,
            ACK,
            ACK_WITH_ECN,
            RESET_STREAM,
            STOP_SENDING,
            CRYPTO,
            NEW_TOKEN,
            STREAM, // 0x08 - 0x0f
            MAX_DATA = 0x10,
            MAX_STREAM_DATA,
            MAX_STREAMS,
            DATA_BLOCKED = 0x14,
            STREAM_DATA_BLOCKED,
            STREAM_BLOCKED,
            NEW_CONNECTION_ID = 0x18,
            RETIRE_CONNECTION_ID = 0x19,
            PATH_CHALLENGE = 0x1a,
            PATH_RESPONSE = 0x1b,
            CONNECTION_CLOSE,
            HANDSHAKE_DONE = 0x1e,
            UNKNOWN = 0x1f,
        };

        enum class QuicTransErrorCode : uint64_t {
            NO_ERROR = 0x0,
            INTERNAL_ERROR,
            CONNECTION_REFUSED,
            FLOW_CONTROL_ERROR,
            STREAM_LIMIT_ERROR,
            STREAM_STATE_ERROR,
            FINAL_SIZE_ERROR,
            FRAME_ENCODING_ERROR,
            TRANSPORT_PARAMETER_ERROR,
            CONNECTION_ID_LIMIT_ERROR,
            PROTOCOL_VIOLATION,
            INVALID_TOKEN,
            APPLICATION_ERROR,
            CRYPTO_BUFFER_EXCEEDED,
            KEY_UPGRADE_ERROR,
            AEAD_LIMIT_REACHED,
            NO_VIABLE_PATH,
            CRYPTO_ERROR,
        };

        enum class QuicErrorClass {
            UNDEFINED,
            TRANSPORT,
            APPLICATION,
        };

        enum class QuicPacketType : uint8_t {
            INITIAL = 0x00,
            ZERO_RTT_PROTECTED = 0x01,
            HANDSHAKE = 0x02,
            RETRY = 0x03,
            VERSION_NEGOTIATION = 0xF0,
            PROTECTED,
            STATELESS_RESET,
            UNINITIALIZED = 0xFF,
        };

        enum class QuicKeyPhase : int {
            PHASE_0 = 0,
            PHASE_1,
            INITIAL,
            ZERO_RTT,
            HANDSHAKE,
        };

        enum class QuicStreamDirection : uint8_t {
            UNKNOWN = 0,
            SEND,
            RECEIVE,
            BIDIRECTIONAL,
        };

        enum class PacketNumberLen : uint8_t {
            PACKET_NUMBER_LEN_INVALID = 0,
            PACKET_NUMBER_LEN1 = 1,
            PACKET_NUMBER_LEN2 = 2,
            PACKET_NUMBER_LEN3 = 3,
            PACKET_NUMBER_LEN4 = 4,
        };

        enum class PacketSendMode : uint8_t {
            PACKET_SEND_NONE = 0,
            PACKET_SEND_ACK,
            PACKET_SEND_PTO_APP_DATA,
            PACKET_SEND_ANY,
        };

        std::string packetTypeString(QuicPacketType type);

        class QuicError {
        public:
            typedef std::shared_ptr<QuicError> ptr;
            virtual ~QuicError() {};

            QuicErrorClass m_cls = QuicErrorClass::UNDEFINED;
            uint16_t m_code      = 0;
            const char *m_msg    = nullptr;
        protected:
            QuicError() {};
            QuicError(QuicErrorClass error_class,
                      uint16_t error_code,
                      const char *error_msg = nullptr)
                    : m_cls(error_class),
                      m_code(error_code),
                      m_msg(error_msg) {};
        };

        class QuicConnectionError : public QuicError {
        public:
            typedef std::shared_ptr<QuicConnectionError> ptr;
            QuicConnectionError() : QuicError() {};
            QuicConnectionError(QuicTransErrorCode error_code,
                                const char *error_msg = nullptr,
                                QuicFrameType frame_type = QuicFrameType::UNKNOWN)
                    : QuicError(QuicErrorClass::TRANSPORT, static_cast<uint16_t>(error_code), error_msg),
                      m_frame_type(frame_type) {};

            QuicConnectionError(QuicErrorClass error_class,
                                uint16_t error_code, const char *error_msg = nullptr,
                                QuicFrameType frame_type = QuicFrameType::UNKNOWN)
                    : QuicError(error_class, error_code, error_msg),
                      m_frame_type(frame_type) {};

            QuicFrameType frame_type() const;
        private:
            QuicFrameType m_frame_type = QuicFrameType::UNKNOWN;
        };

        class QuicStatelessResetToken {
        public:
            typedef std::shared_ptr<QuicStatelessResetToken> ptr;
            constexpr static int8_t LEN = 16;
            QuicStatelessResetToken() {}
            QuicStatelessResetToken(const QuicConnectionId &conn_id, uint32_t instance_id);
            QuicStatelessResetToken(const uint8_t *buf) { memcpy(this->m_token, buf, QuicStatelessResetToken::LEN); }

            operator uint64_t() const { return this->hashcode(); }
            bool operator==(const QuicStatelessResetToken &x) const {
                return memcmp(this->m_token, x.m_token, QuicStatelessResetToken::LEN) == 0;
            }
            bool operator!=(const QuicStatelessResetToken &x) const {
                return memcmp(this->m_token, x.m_token, QuicStatelessResetToken::LEN) != 0;
            }
            const uint8_t *buf() const { return m_token; }
            std::string hex() const;

        private:
            uint8_t m_token[LEN] = {0};
            void m_generate(uint64_t data);
            uint64_t hashcode() const;
        };

        class QuicConnectionId {
        public:
            typedef std::shared_ptr<QuicConnectionId> ptr;
            static uint8_t SCID_LEN;
            static constexpr int MIN_LENGTH_FOR_INITIAL = 8;
            static constexpr int MAX_LENGTH             = 20;
            static constexpr size_t MAX_HEX_STR_LENGTH  = MAX_LENGTH * 2 + 1;
            static QuicConnectionId ZERO();
            static QuicConnectionId::ptr parseConnectionId(const MBuffer::ptr &buffer_block);
            QuicConnectionId();
            QuicConnectionId(const uint8_t *buf, uint8_t len);

            explicit operator bool() const { return true; }
            operator uint64_t() const { return this->hashcode(); }
            operator const uint8_t *() const { return this->m_id; }
            bool operator==(const QuicConnectionId &x) const {
                if (this->m_len != x.m_len) {
                    return false;
                }
                return memcmp(this->m_id, x.m_id, this->m_len) == 0;
            }
            bool operator!=(const QuicConnectionId &x) const {
                if (this->m_len != x.m_len) {
                    return true;
                }
                return memcmp(this->m_id, x.m_id, this->m_len) != 0;
            }

            uint32_t h32() const;
            std::string toHexString() const;
            uint8_t length() const;
            bool is_zero() const;
            void randomize();

        private:
            uint64_t    hashcode() const;
            uint8_t     m_id[20];
            uint8_t     m_len = 0;
        };

        class QuicFiveTuple {
        public:
            typedef std::shared_ptr<QuicFiveTuple> ptr;
            QuicFiveTuple() {};
            QuicFiveTuple(IPAddress::ptr src, IPAddress::ptr dst, int protocol);
            void update(IPAddress::ptr src, IPAddress::ptr dst, int protocol);
            IPAddress::ptr source() const { return m_source; }
            IPAddress::ptr destination() const { return m_destination; }
            int protocol() const { return m_protocol; }
        private:
            IPAddress::ptr  m_source;
            IPAddress::ptr  m_destination;
            int             m_protocol;
            uint64_t        m_hash_code = 0;
        };

        class QuicDebugNames {
        public:
            static const char *frame_type(QuicFrameType type);
            static const char *error_code(uint16_t code);
        };

        void write_QuicStreamId(QuicStreamId stream_id, uint8_t *buf, size_t *len);
        void write_QUicOffset(QuicOffset offset, uint8_t *buf, size_t *len);

        class QuicVariableInt {
        public:
            static int size(const uint8_t *src);
            static size_t size(const std::string &src);
            static size_t size(uint64_t src);
            static int encode(uint8_t *dst, size_t dst_len, size_t &len, uint64_t src);
            static int decode(uint64_t &dst, size_t &len, const uint8_t *src, size_t src_len = 8);
        };

        class QuicIntUtil {
        public:
            static uint64_t read_QuicVariableInt(const uint8_t *buf, size_t buf_len);
            static void write_QuicVariableInt(uint64_t data, uint8_t *buf, size_t *len);
            static uint64_t read_nbytes_as_uint(const uint8_t *buf, uint8_t n);
            static void write_uint_as_nbytes(uint64_t value, uint8_t n, uint8_t *buf, size_t *len);
        };

        struct AckRange {
            typedef std::shared_ptr<AckRange> ptr;
            AckRange(QuicPacketNumber start, QuicPacketNumber end)
                    : m_smallest(start), m_largest(end) {}
            uint64_t len() const { return m_largest - m_smallest + 1; }
            QuicPacketNumber m_smallest;
            QuicPacketNumber m_largest;
        };


        int stream_read_assert(MBuffer::ptr stream, size_t len);
        bool read_varint(MBuffer::ptr stream, uint64_t &field, size_t &field_len);
        bool read_varstring(MBuffer::ptr buffer_block, std::string &field);

    }
}

#endif

