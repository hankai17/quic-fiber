#ifndef __QUIC_PACKET_HH__
#define __QUIC_PACKET_HH__

#include "my_sylar/bytearray.hh"
#include "my_sylar/stream.hh"
#include "quic-fiber/quic_type.hh"
#include "quic-fiber/quic_frame.hh"
#include "quic-fiber/quic_stream.hh"

#include <random>
#include <deque>
#include <vector>
#include <functional>

/*
Long
Initial Packet {
  Header Form (1) = 1,
  Fixed Bit (1) = 1,
  Long Packet Type (2) = 0,
  Reserved Bits (2),
  Packet Number Length (2),
  Version (32),
  Destination Connection ID Length (8),
  Destination Connection ID (0..160),
  Source Connection ID Length (8),
  Source Connection ID (0..160),
  Token Length (i),
  Token (..),
  Length (i),
  Packet Number (8..32),
  Packet Payload (8..),
}

0-RTT Packet {
  Header Form (1) = 1,
  Fixed Bit (1) = 1,
  Long Packet Type (2) = 1,
  Reserved Bits (2),
  Packet Number Length (2),
  Version (32),
  Destination Connection ID Length (8),
  Destination Connection ID (0..160),
  Source Connection ID Length (8),
  Source Connection ID (0..160),
  Length (i),
  Packet Number (8..32),
  Packet Payload (8..),
}

Handshake Packet {
  Header Form (1) = 1,
  Fixed Bit (1) = 1,
  Long Packet Type (2) = 2,
  Reserved Bits (2),
  Packet Number Length (2),
  Version (32),
  Destination Connection ID Length (8),
  Destination Connection ID (0..160),
  Source Connection ID Length (8),
  Source Connection ID (0..160),
  Length (i),
  Packet Number (8..32),
  Packet Payload (8..),
}

Retry Packet {
  Header Form (1) = 1,
  Fixed Bit (1) = 1,
  Long Packet Type (2) = 3,
  Unused (4),
  Version (32),
  Destination Connection ID Length (8),
  Destination Connection ID (0..160),
  Source Connection ID Length (8),
  Source Connection ID (0..160),
  Retry Token (..),
  Retry Integrity Tag (128),
}

Short
1-RTT Packet {
  Header Form (1) = 0,
  Fixed Bit (1) = 1,
  Spin Bit (1),
  Reserved Bits (2),
  Key Phase (1),
  Packet Number Length (2),
  Destination Connection ID (0..160),
  Packet Number (8..32),
  Packet Payload (8..),
}
*/

/*
Type-Specific Bits (4),
Long Packet Type (2),
Fixed Bit (1) = 1,
Header Form (1) = 1,

Long Header Packet {
  Header Form (1) = 1,
  Fixed Bit (1) = 1,
  Long Packet Type (2),
  Type-Specific Bits (4),
  Version (32),
  Destination Connection ID Length (8),
  Destination Connection ID (0..160),
  Source Connection ID Length (8),
  Source Connection ID (0..160),
  Type-Specific Payload (..),
}
*/

namespace sylar {
    namespace quic {

        static constexpr QuicVersion gQUIC_VERSION0 = 0x51303030;
        static constexpr QuicVersion gQUIC_MAX_VERSION = 0x51303439;
        static constexpr QuicVersion VERSION_39 = gQUIC_VERSION0 + 3 * 0x100 + 0x9;
        static constexpr QuicVersion VERSION_TLS = 101;
        static constexpr QuicVersion VERSION_WHATEVER = 0;
        static constexpr QuicVersion VERSION_UNKNOWN = -1;
        static constexpr QuicVersion SUPPORT_VERSIONS[] = { VERSION_39 };

        struct QuicPacketHeader {
        public:
            typedef std::shared_ptr<QuicPacketHeader> ptr;

            QuicPacketHeader(uint8_t type_byte, bool is_long);
            int readShortHeaderFrom(MBuffer::ptr buffer_block, size_t cid_len);
            int readLongHeaderFrom(MBuffer::ptr buffer_block);

            uint8_t m_type_byte = 0;
            bool m_is_long_header = false;
            QuicPacketType m_type;
            QuicVersion m_version;
            QuicConnectionId::ptr m_src_cid = nullptr;
            QuicConnectionId::ptr m_dst_cid = nullptr;
            uint64_t m_length = 0;
            std::string m_token = "";
            uint64_t m_parsed_len = 0;
        };

        struct QuicEPacketHeader : public QuicPacketHeader {
        public:
            typedef std::shared_ptr<QuicEPacketHeader> ptr;

            QuicEPacketHeader(uint8_t type_byte, bool is_long) : QuicPacketHeader(type_byte, is_long) {}
            int readPacketNumberFrom(const MBuffer::ptr &buffer_block);
            int writePacketNumberTo(const MBuffer::ptr &buffer_block);
            int writeLongHeaderTo(const MBuffer::ptr &buffer_block);
            int writeShortHeaderTo(const MBuffer::ptr &buffer_block);
            int writeTo(const MBuffer::ptr &buffer_block);
            uint64_t getLength();
            std::string toString() const;

            QuicKeyPhase        m_key_phase;
            PacketNumberLen     m_packet_number_len;
            QuicPacketNumber    m_packet_number;
        };

        QuicEPacketHeader::ptr readPacketHeaderFrom(const MBuffer::ptr &buffer_block, size_t default_cid_len = 4);

        struct QuicPacketContents {
            typedef std::shared_ptr<QuicPacketContents> ptr;
            QuicEPacketHeader::ptr header = nullptr;
            QuicAckFrame::ptr ack = nullptr;
            std::list<QuicFrame::ptr> frames;
            uint64_t length = 0;
            MBuffer::ptr buffer = nullptr;
        };

        class QuicPacket { // used for ackhandler
        public:
            typedef std::shared_ptr<QuicPacket> ptr;
            static constexpr int MAX_INSTANCE_SIZE = 1024;
            static constexpr size_t MAX_PACKET_HEADER_LEN = 256;
            struct FrameCtx {
                QuicFrame::ptr frame;
                std::function<void()> on_acked_cb;
                std::function<void()> on_lost_cb;
            };

            void init(uint64_t now, QuicPacketContents::ptr packet_content,
                    const std::function<void(QuicFrame::ptr)> &lost_fun);
            QuicPacket() {};
            QuicPacketNumber packetNumber() const { return m_pn; }
            void setPacketNumber(QuicPacketNumber no) { m_pn = no; }
            //const std::string &data() const { return m_data; }
            uint64_t sendTime() const { return m_send_time; }
            const std::list<QuicFrame::ptr> &frames() const { return m_frames; }
            std::list<QuicFrame::ptr> &frames() { return m_frames; }
            void clear_frames() { m_frames.clear(); }
            uint64_t len();
            bool skippedPacket() const { return m_skipped_packet; }
            bool declaredLost() const { return m_declared_lost; }
            bool includedInBytesInflight() const { return m_includedInBytesInflight; }
            QuicPacketNumber largestAcked() const { return m_largest_acked; }

            void setTime(uint64_t time) { m_send_time = time; }
            void setSkip(bool val = true) { m_skipped_packet = val; }
            void setLost(bool val = true) { m_declared_lost = val; }
            void setIncludedInBytesInflight(bool val) { m_includedInBytesInflight = val; }
            void setLargestAcked(QuicPacketNumber pn) { m_largest_acked = pn; }

        private:
            QuicPacketNumber m_pn;
            std::list<QuicFrame::ptr> m_frames;
            QuicPacketNumber m_largest_acked = 0;
            uint64_t m_length = 0;
            uint64_t m_send_time = 0;
            bool m_includedInBytesInflight = false;
            bool m_declared_lost = false;
            bool m_skipped_packet = false;
        };

        class PacketNumberManager {
        public:
            typedef std::shared_ptr<PacketNumberManager> ptr;
            PacketNumberManager(QuicPacketNumber initial, QuicPacketNumber average)
                    : m_next(initial), m_average_period(average) {}
            static PacketNumberLen GetPacketNumberLengthForHeader(QuicPacketNumber pn);
            uint16_t getRandomNumber();
            void generateNewSkip();
            QuicPacketNumber peek() const;
            QuicPacketNumber pop();

        private:
            QuicPacketNumber m_next;
            QuicPacketNumber m_next_to_skip;
            QuicPacketNumber m_average_period;
        };

        class PacketNumberLength {
        public:
            static PacketNumberLen getPacketNumberLengthForHeader(QuicPacketNumber packet_num, 
                    QuicPacketNumber least_unacked);
            static PacketNumberLen getPacketNumberLength(QuicPacketNumber packet_num);
        };

        struct RetransmissionQueue {
        public:
            typedef std::shared_ptr<RetransmissionQueue> ptr;
            void addInitail(QuicFrame::ptr frame);
            void addHandshake(QuicFrame::ptr frame);
            void addAppData(QuicFrame::ptr frame);
            bool hasInitialData() const;
            bool hasHandshakeData() const;
            bool hasAppData() const;

            QuicFrame::ptr getInitialFrame();
            QuicFrame::ptr getHandshakeFrame();
            QuicFrame::ptr getAppDataFrame();
            void dropPackets(QuicEncryptionLevel level);

            std::deque<QuicFrame::ptr> m_initial;
            std::deque<QuicCryptoFrame::ptr> m_initial_crypto_data;
            std::deque<QuicFrame::ptr> m_handshake;
            std::deque<QuicCryptoFrame::ptr> m_handshake_crypto_data;
            std::deque<QuicFrame::ptr> m_app_data;
            QuicVersion m_version;
        };

        class QuicPacketCodec {
        public:
            typedef std::shared_ptr<QuicPacketCodec> ptr;

            static QuicPacket::ptr readFrom(MBuffer::ptr buffer_block, QuicPacketHeader::ptr header);
            int32_t serializeTo(MBuffer::ptr buffer_block, QuicFrame::ptr frame);
        };

        class QuicPacketPack {
        public:
            typedef std::shared_ptr<QuicPacketPack> ptr;

            static size_t packetLength(QuicEPacketHeader::ptr header,
                    const std::deque<QuicFrame::ptr> &payload);
            static int composeNextPacket(QuicSndStream::ptr send_stream,
                    std::deque<QuicFrame::ptr> &frames); // 从send_stream中取出frames集
            static MBuffer::ptr packPacket(PacketNumberManager::ptr pnm, QuicSndStream::ptr send_stream);
            static MBuffer::ptr dump_into_packet_buffer(QuicEPacketHeader::ptr header,
                                                    std::list<QuicFrame::ptr> frames, size_t payload_len);
        private:
        };

        struct QuicPackedPacket {
            MBuffer::ptr buffer;
            QuicPacketContents::ptr packet_content;
        };

    }
}

#endif

