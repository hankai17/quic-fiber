#ifndef __QUIC_FRAME_HH__
#define __QUIC_FRAME_HH__

#include "my_sylar/bytearray.hh"
#include "my_sylar/mbuffer.hh"
#include "my_sylar/stream.hh"
#include "quic-fiber/quic_type.hh"
#include <list>

namespace sylar {
    namespace quic {

        class QuicFrame {
        public:
            typedef std::shared_ptr<QuicFrame> ptr;
            constexpr static int MAX_INSTANCE_SIZE = 256;
            static QuicFrameType type(const uint8_t *buf);

            virtual ~QuicFrame() {};
            virtual bool readTypeByte(uint8_t type_byte) { return true; }
            virtual bool readFrom(MBuffer::ptr buffer_block) = 0;
            virtual bool writeTo(MBuffer::ptr buffer_block) = 0;
            virtual QuicFrameType type() const = 0;
            virtual size_t size() const = 0;
            virtual std::string toString() const = 0;
            virtual bool is_probing_frame() const { return false; }
            virtual bool is_flow_controlled() const { return false; }

            void setOnLost(const std::function<void(QuicFrame::ptr)> &cb) { m_lost_cb = cb; }
            void setOnAcked(const std::function<void(QuicFrame::ptr)> &cb) { m_acked_cb = cb; }
            void onLost(QuicFrame::ptr frame) { if (m_lost_cb) m_lost_cb(frame); }
            void onAcked(QuicFrame::ptr frame) { if (m_acked_cb) m_acked_cb(frame); }
            const std::function<void(QuicFrame::ptr)> &lostCb() const { return m_lost_cb; }

            bool valid() const { return m_valid; }
            QuicStreamId stream_id() const { return m_stream_id; }
            bool ack_eliciting() const;

        protected:
            QuicFrame(QuicStreamId id = 0) : m_stream_id(id) {};
            QuicStreamId m_stream_id;
            size_t m_size = 0;
            bool m_valid = false;

            std::function<void(QuicFrame::ptr)> m_lost_cb = nullptr;
            std::function<void(QuicFrame::ptr)> m_acked_cb = nullptr;
        };

        /*STREAM Frame {
          Type (i) = 0x08..0x0f,
          Stream ID (i),
          [Offset (i)],
          [Length (i)],
          Stream Data (..),
        }*/
        class QuicStreamFrame : public QuicFrame {
        public:
            typedef std::shared_ptr<QuicStreamFrame> ptr;
            static constexpr uint8_t MAX_HEADER_SIZE = 32;
            QuicStreamFrame() { m_data = std::make_shared<MBuffer>(); }

            virtual bool readTypeByte(uint8_t type_byte) override;
            virtual bool readFrom(MBuffer::ptr buffer_block) override;
            virtual bool writeTo(MBuffer::ptr buffer_block) override;
            virtual QuicFrameType type() const override { return QuicFrameType::STREAM; }
            virtual size_t size() const override;
            virtual std::string toString() const override;

            QuicStreamId stream_id() const { return m_stream_id; }
            QuicOffset offset() const;
            const MBuffer::ptr &data() const { return m_data; }
            void set_stream_id(QuicStreamId stream_id) { m_stream_id = stream_id; }
            void set_offset(QuicOffset offset) { m_offset = offset; m_has_offset_field = true; }
            void set_data(const MBuffer::ptr &data) { m_data = data; m_has_length_field = true; }
            void set_fin_flag() { m_has_fin = true; }
            QuicStreamFrame::ptr maybeSplitOffFrame(size_t max_bytes);
            uint64_t maxDataLen(uint64_t max_size);

            bool has_fin_flag() const { return m_has_fin; }
            bool has_offset_field() const { return m_has_offset_field; }
            bool has_length_field() const { return m_has_length_field; }

        private:
            MBuffer::ptr m_data = nullptr;
            QuicOffset m_offset = 0;
            bool m_has_fin = false;
            bool m_has_offset_field = true;
            bool m_has_length_field = true;
        };

        /*CRYPTO Frame {
          Type (i) = 0x06,
          Offset (i),
          Length (i),
          Crypto Data (..),
        }*/
        class QuicCryptoFrame : public QuicFrame {
        public:
            typedef std::shared_ptr<QuicCryptoFrame> ptr;
            static constexpr uint8_t MAX_HEADER_SIZE = 16;

            virtual bool readFrom(MBuffer::ptr buffer_block) override;
            virtual bool writeTo(MBuffer::ptr buffer_block) override;
            virtual QuicFrameType type() const override { return QuicFrameType::CRYPTO; }
            virtual size_t size() const override;
            virtual std::string toString() const override;

            QuicOffset offset() const { return m_offset; }
            std::string data() const { return m_data; } 
        private:
            QuicOffset m_offset = 0;
            std::string m_data  = "";
        };

        /*ACK Frame {
          Type (i) = 0x02..0x03,
          Largest Acknowledged (i),
          ACK Delay (i),
          ACK Range Count (i),
          First ACK Range (i),
          ACK Range (..) ...,
          [ECN Counts (..)],
        }*/

        class QuicAckFrame : public QuicFrame {
        public:
            typedef std::shared_ptr<QuicAckFrame> ptr;
            /*ACK Range {
              Gap (i),
              ACK Range Length (i),
            }*/
            struct GapLenEntry {
                uint64_t gap;
                uint64_t len;
            };
            struct EcnSection {
            public:
                typedef std::shared_ptr<QuicAckFrame::EcnSection> ptr;
                size_t size() const { return m_size; }
                bool vaild() const { return m_valid; }
                uint64_t ect0_count() const { return m_ect0_count; }
                uint64_t ect1_count() const { return m_ect1_count; }
                uint64_t ecn_ce_count() const { return m_ecn_ce_count; }

                bool m_valid = false;
                size_t m_size = 0;
                uint64_t m_ect0_count = 0;
                uint64_t m_ect1_count = 0;
                uint64_t m_ecn_ce_count = 0;
            };

            QuicAckFrame() {};
            QuicAckFrame(const std::vector<AckRange::ptr> &ack_ranges);
            virtual bool readTypeByte(uint8_t type_byte) override;
            virtual bool readFrom(MBuffer::ptr buffer_block) override;
            virtual bool writeTo(MBuffer::ptr buffer_block) override;
            virtual QuicFrameType type() const override { return QuicFrameType::ACK; }
            virtual size_t size() const override;
            virtual std::string toString() const override;

            uint64_t encodeAckDelay(uint64_t ack_delay);
            int numEncodableAckRanges();
            bool acksPacket(QuicPacketNumber pn);
            QuicPacketNumber lowestAcked();
            GapLenEntry encodeAckRange(size_t idx) const;
            QuicPacketNumber largestAcked() const { return m_ack_ranges[0]->m_largest; }
            const std::vector<AckRange::ptr> &ackRanges() const { return m_ack_ranges; }
            std::vector<AckRange::ptr> &ackRanges() { return m_ack_ranges; }

            bool hasMissingRanges() const { return m_ack_ranges.size() > 1; }
            uint64_t ack_delay() const { return m_ack_delay; }
            const EcnSection::ptr ecn_section() const { return m_ecn_section; }
            EcnSection::ptr ecn_section() { return m_ecn_section; }
            void setAckRanges(const std::vector<AckRange::ptr> &ack_ranges) { m_ack_ranges = ack_ranges; }
            void setAckDelay(uint64_t time) { m_ack_delay = time; }
        private:
            std::vector<AckRange::ptr> m_ack_ranges;
            MBuffer::ptr m_block;
            uint64_t m_ack_delay = 0;
            bool m_has_ecn = false;
            EcnSection::ptr m_ecn_section = nullptr;
        };

        /*RESET_STREAM Frame {
          Type (i) = 0x04,
          Stream ID (i),
          Application Protocol Error Code (i),
          Final Size (i),
        }*/
        class QuicRstStreamFrame : public QuicFrame {
        public:
            typedef std::shared_ptr<QuicRstStreamFrame> ptr;

            QuicRstStreamFrame() {}
            QuicRstStreamFrame(QuicStreamId stream_id, QuicOffset offset, QuicAppErrCode err_code = 0)
                        : QuicFrame(stream_id), m_final_offset(offset), m_error_code(err_code) {}
            virtual bool readFrom(MBuffer::ptr buffer_block) override;
            virtual bool writeTo(MBuffer::ptr buffer_block) override;
            virtual QuicFrameType type() const override { return QuicFrameType::RESET_STREAM; }
            virtual size_t size() const override;
            virtual std::string toString() const override;

            QuicAppErrCode error_code() const { return m_error_code; }
            QuicStreamId stream_id() const { return m_stream_id; }
            QuicOffset final_offset() const { return m_final_offset; }
        private:
            QuicOffset m_final_offset = 0;
            QuicAppErrCode m_error_code = 0;
        };

        /*PING Frame {
          Type (i) = 0x01,
        }*/
        class QuicPingFrame : public QuicFrame {
        public:
            typedef std::shared_ptr<QuicPingFrame> ptr;

            virtual bool readFrom(MBuffer::ptr buffer_block) override;
            virtual bool writeTo(MBuffer::ptr buffer_block) override;
            virtual QuicFrameType type() const override { return QuicFrameType::PING; }
            virtual size_t size() const override;
            virtual std::string toString() const override;
        };

        /*PADDING Frame {
          Type (i) = 0x00,
        }*/
        class QuicPaddingFrame : public QuicFrame {
        public:
            typedef std::shared_ptr<QuicPaddingFrame> ptr;

            virtual bool readFrom(MBuffer::ptr buffer_block) override;
            virtual bool writeTo(MBuffer::ptr buffer_block) override;
            virtual QuicFrameType type() const override { return QuicFrameType::PADDING; }
            virtual size_t size() const override { return m_size; }
            virtual std::string toString() const override;
        private:
            size_t m_size = 0;
        };

        /*CONNECTION_CLOSE Frame {
          Type (i) = 0x1c..0x1d,
          Error Code (i),
          [Frame Type (i)],
          Reason Phrase Length (i),
          Reason Phrase (..),
        }*/
        class QuicConnectionCloseFrame : public QuicFrame {
        public:
            typedef std::shared_ptr<QuicConnectionCloseFrame> ptr;

            virtual bool readTypeByte(uint8_t type_byte) override;
            virtual bool readFrom(MBuffer::ptr buffer_block) override;
            virtual bool writeTo(MBuffer::ptr buffer_block) override;
            virtual QuicFrameType type() const override { return QuicFrameType::CONNECTION_CLOSE; }
            virtual size_t size() const override;
            virtual std::string toString() const override;

            uint16_t error_code() const { return m_error_code; }
            QuicFrameType frame_type() const { return m_frame_type; }
            uint64_t reason_phrase_length() const { return m_reason_phrase_len; }
            const char *reason_phrase() const { return m_reason_phrase.c_str(); }
            void setAppErr(bool err) { m_is_application_error = err; }
            bool isAppErr() const { return m_is_application_error; }
        private:
            uint8_t m_type = 0;
            uint64_t m_error_code;
            QuicFrameType m_frame_type = QuicFrameType::UNKNOWN;
            uint64_t m_reason_phrase_len = 0;
            std::string m_reason_phrase = "";
            bool m_is_application_error = false;
        };

        /*MAX_DATA Frame {
          Type (i) = 0x10,
          Maximum Data (i),
        }*/
        class QuicMaxDataFrame : public QuicFrame {
        public:
            typedef std::shared_ptr<QuicMaxDataFrame> ptr;
            QuicMaxDataFrame() {};
            QuicMaxDataFrame(uint64_t maximum_data)
                    : m_maximum_data(maximum_data) {}
            virtual bool readFrom(MBuffer::ptr buffer_block) override;
            virtual bool writeTo(MBuffer::ptr buffer_block) override;
            virtual QuicFrameType type() const override { return QuicFrameType::MAX_DATA; }
            virtual size_t size() const override;
            virtual std::string toString() const override;
            void setMaxData(uint64_t v) { m_maximum_data = v; }
            uint64_t maximum_stream_data() const { return m_maximum_data; }
        private:
            uint64_t m_maximum_data = 0;
        };

        /*MAX_STREAM_DATA Frame {
          Type (i) = 0x11,
          Stream ID (i),
          Maximum Stream Data (i),
        }*/
        class QuicMaxStreamDataFrame : public QuicFrame {
        public:
            typedef std::shared_ptr<QuicMaxStreamDataFrame> ptr;
            QuicMaxStreamDataFrame() {};
            QuicMaxStreamDataFrame(QuicStreamId id, uint64_t offset)
                    : QuicFrame(id), m_maximum_stream_data(offset) {}
            virtual bool readFrom(MBuffer::ptr buffer_block) override;
            virtual bool writeTo(MBuffer::ptr buffer_block) override;
            virtual QuicFrameType type() const override { return QuicFrameType::MAX_STREAM_DATA; }
            virtual size_t size() const override;
            virtual std::string toString() const override;

            QuicStreamId stream_id() const { return m_stream_id; }
            uint64_t maximum_stream_data() const { return m_maximum_stream_data; }
        private:
            uint64_t m_maximum_stream_data = 0;
        };

        /*MAX_STREAMS Frame {
          Type (i) = 0x12..0x13,
          Maximum Streams (i),
        }*/
        class QuicMaxStreamsFrame : public QuicFrame {
        public:
            typedef std::shared_ptr<QuicMaxStreamsFrame> ptr;

            QuicMaxStreamsFrame() {}
            QuicMaxStreamsFrame(QuicStreamType type, QuicStreamNum max_num);
            virtual bool readFrom(MBuffer::ptr buffer_block) override;
            virtual bool writeTo(MBuffer::ptr buffer_block) override;
            virtual QuicFrameType type() const override { return QuicFrameType::MAX_STREAMS; }
            virtual size_t size() const override;
            virtual std::string toString() const override;

            uint64_t maximum_streams() const { return m_maximum_streams; }
        private:
            QuicStreamType m_type;
            uint64_t m_maximum_streams = 0;
        };

        /*DATA_BLOCKED Frame {
          Type (i) = 0x14,
          Maximum Data (i),
        }*/
        class QuicDataBlockedFrame : public QuicFrame {
        public:
            typedef std::shared_ptr<QuicDataBlockedFrame> ptr;
            QuicDataBlockedFrame(QuicOffset offset = 0) : m_offset(offset) {}
            virtual bool readFrom(MBuffer::ptr buffer_block) override;
            virtual bool writeTo(MBuffer::ptr buffer_block) override;
            virtual QuicFrameType type() const override { return QuicFrameType::DATA_BLOCKED; }
            virtual size_t size() const override;
            virtual std::string toString() const override;

            QuicOffset offset() const { return m_offset; }
        private:
            QuicOffset  m_offset = 0;
        };

        /*STREAM_DATA_BLOCKED Frame {
          Type (i) = 0x15,
          Stream ID (i),
          Maximum Stream Data (i),
        }*/
        class QuicStreamDataBlockedFrame : public QuicFrame {
        public:
            typedef std::shared_ptr<QuicStreamDataBlockedFrame> ptr;
            QuicStreamDataBlockedFrame() {}
            QuicStreamDataBlockedFrame(QuicStreamId stream_id, QuicOffset offset) : QuicFrame(stream_id), m_offset(offset) {}
            virtual bool readFrom(MBuffer::ptr buffer_block) override;
            virtual bool writeTo(MBuffer::ptr buffer_block) override;
            virtual QuicFrameType type() const override { return QuicFrameType::STREAM_DATA_BLOCKED; }
            virtual size_t size() const override;
            virtual std::string toString() const override;

            QuicStreamId stream_id() const { return m_stream_id; }
            QuicOffset offset() const { return m_offset; }
        private:
            QuicOffset m_offset = 0;
        };

        /*STREAMS_BLOCKED Frame {
          Type (i) = 0x16..0x17,
          Maximum Streams (i),
        }*/
        class QuicStreamsBlockedFrame : public QuicFrame {
        public:
            typedef std::shared_ptr<QuicStreamsBlockedFrame> ptr;
            QuicStreamsBlockedFrame() {}
            QuicStreamsBlockedFrame(QuicStreamType type, QuicStreamNum num);
            virtual bool readTypeByte(uint8_t type_byte) override;
            virtual bool readFrom(MBuffer::ptr buffer_block) override;
            virtual bool writeTo(MBuffer::ptr buffer_block) override;
            virtual QuicFrameType type() const override { return QuicFrameType::STREAM_BLOCKED; }
            virtual size_t size() const override;
            virtual std::string toString() const override;
        private:
            QuicStreamType m_stream_type;
            QuicStreamNum m_stream_limit;
        };

        /*NEW_CONNECTION_ID Frame {
          Type (i) = 0x18,
          Sequence Number (i),
          Retire Prior To (i),
          Length (8),
          Connection ID (8..160),
          Stateless Reset Token (128),
        }*/
        class QuicNewConnectionIdFrame : public QuicFrame {
        public:
            typedef std::shared_ptr<QuicNewConnectionIdFrame> ptr;

            virtual bool readFrom(MBuffer::ptr buffer_block) override;
            virtual bool writeTo(MBuffer::ptr buffer_block) override;
            virtual QuicFrameType type() const override { return QuicFrameType::NEW_CONNECTION_ID; }
            virtual size_t size() const override;
            virtual std::string toString() const override;

            uint64_t sequence() const { return m_sequence; }
            uint64_t retire_prior_to() const { return m_retire_prior_to; }
            QuicConnectionId connection_id() const { return m_connection_id; }
        private:
            uint64_t m_sequence = 0;
            uint64_t m_retire_prior_to = 0;
            QuicConnectionId m_connection_id = QuicConnectionId::ZERO();
            QuicStatelessResetToken m_stateless_reset_token;
        };

        /*STOP_SENDING Frame {
          Type (i) = 0x05,
          Stream ID (i),
          Application Protocol Error Code (i),
        }*/
        class QuicStopSendingFrame : public QuicFrame {
        public:
            typedef std::shared_ptr<QuicStopSendingFrame> ptr;

            virtual bool readFrom(MBuffer::ptr buffer_block) override;
            virtual bool writeTo(MBuffer::ptr buffer_block) override;
            virtual QuicFrameType type() const override { return QuicFrameType::STOP_SENDING; }
            virtual size_t size() const override;
            virtual std::string toString() const override;

            QuicStreamId stream_id() const { return m_stream_id; }
            QuicAppErrCode error_code() const { return m_error_code; }
        private:
            QuicAppErrCode m_error_code = 0;
        };

        /*PATH_CHALLENGE Frame {
          ype (i) = 0x1a,
          Data (64),
        }*/
        class QuicPathChallengeFrame : public QuicFrame {
        public:
            typedef std::shared_ptr<QuicPathChallengeFrame> ptr;
            static constexpr uint8_t DATA_LEN = 8;

            virtual bool readFrom(MBuffer::ptr buffer_block) override;
            virtual bool writeTo(MBuffer::ptr buffer_block) override;
            virtual QuicFrameType type() const override { return QuicFrameType::PATH_CHALLENGE; }
            virtual size_t size() const override;
            virtual std::string toString() const override;

            const uint8_t *data() const { return (uint8_t*)m_data.c_str(); }
        private:
            std::string m_data = "";
        };

        /*PATH_RESPONSE Frame {
          Type (i) = 0x1b,
          Data (64),
        }*/
        class QuicPathResponseFrame : public QuicFrame {
        public:
            typedef std::shared_ptr<QuicPathResponseFrame> ptr;
            static constexpr uint8_t DATA_LEN = 8;

            virtual bool readFrom(MBuffer::ptr buffer_block) override;
            virtual bool writeTo(MBuffer::ptr buffer_block) override;
            virtual QuicFrameType type() const override { return QuicFrameType::PATH_RESPONSE; }
            virtual size_t size() const override;
            virtual std::string toString() const override;

            const uint8_t *data() const { return (uint8_t*)m_data.c_str(); }
        private:
            std::string m_data = "";
        };

        /*NEW_TOKEN Frame {
          Type (i) = 0x07,
          Token Length (i),
          Token (..),
        }*/
        class QuicNewTokenFrame : public QuicFrame {
        public:
            typedef std::shared_ptr<QuicNewTokenFrame> ptr;

            virtual bool readFrom(MBuffer::ptr buffer_block) override;
            virtual bool writeTo(MBuffer::ptr buffer_block) override;
            virtual QuicFrameType type() const override { return QuicFrameType::NEW_TOKEN; }
            virtual size_t size() const override;
            virtual std::string toString() const override;

            const uint8_t *token() const { return (uint8_t*)m_token.c_str(); }
            uint64_t token_length() const { return m_token_len; }
        private:
            std::string m_token = "";
            uint64_t m_token_len = 0;
        };

        /*RETIRE_CONNECTION_ID Frame {
          Type (i) = 0x19,
          Sequence Number (i),
        }*/
        class QuicRetireConnectionIdFrame : public QuicFrame {
        public:
            typedef std::shared_ptr<QuicRetireConnectionIdFrame> ptr;

            virtual bool readFrom(MBuffer::ptr buffer_block) override;
            virtual bool writeTo(MBuffer::ptr buffer_block) override;
            virtual QuicFrameType type() const override { return QuicFrameType::RETIRE_CONNECTION_ID; }
            virtual size_t size() const override;
            virtual std::string toString() const override;

            uint64_t seq_num() const { return m_seq_num; }
        private:
            uint64_t m_seq_num = 0;
        };

        /*HANDSHAKE_DONE Frame {
          Type (i) = 0x1e,
        }*/
        class QuicHandshakeDoneFrame : public QuicFrame {
        public:
            typedef std::shared_ptr<QuicHandshakeDoneFrame> ptr;

            virtual bool readFrom(MBuffer::ptr buffer_block) override;
            virtual bool writeTo(MBuffer::ptr buffer_block) override;
            virtual QuicFrameType type() const override { return QuicFrameType::HANDSHAKE_DONE; }
            virtual size_t size() const override;
            virtual std::string toString() const override;
        };

        class QuicUnknownFrame : public QuicFrame {
        public:
            typedef std::shared_ptr<QuicUnknownFrame> ptr;

            virtual bool readFrom(MBuffer::ptr buffer_block) override { return false; }
            virtual bool writeTo(MBuffer::ptr buffer_block) override;
            virtual QuicFrameType type() const override { return QuicFrameType::UNKNOWN; }
            virtual size_t size() const override { return 0; }
            virtual std::string toString() const override { return std::string(""); }
        };

        class QuicFrameFactory {
        public:
            static QuicFrame *create(uint8_t *buf, const uint8_t *src, size_t len);
        private:
        };

        class QuicFrameCodec {
        public:
            typedef std::shared_ptr<QuicFrameCodec> ptr;
            static QuicFrame::ptr parseNext(const MBuffer::ptr &buffer_block, QuicEncryptionLevel level = QuicEncryptionLevel::NONE);
            static QuicFrame::ptr parseFrame(const MBuffer::ptr &buffer_block, uint8_t type_byte, QuicEncryptionLevel level = QuicEncryptionLevel::NONE);
            static int32_t serializeTo(MBuffer::ptr buffer_block, QuicFrame::ptr frame) { return 0; }
        };

        bool isFrameAckEliciting(const QuicFrame::ptr &frame);
        bool hasAckElicitingFrames(const std::list<QuicFrame::ptr> &frames);

        struct QuicPacketPayload {
            typedef std::shared_ptr<QuicPacketPayload> ptr;
            std::list<QuicFrame::ptr> frames;
            QuicAckFrame::ptr ack;
            uint64_t length;
        };

        class StreamSender {
        public:
            typedef std::shared_ptr<StreamSender> ptr;
            virtual void onHasStreamData(QuicStreamId stream_id) = 0;
            virtual void onStreamCompleted(QuicStreamId stream_id) = 0;
            virtual void queueControlFrame(QuicFrame::ptr frame) = 0;
        private:
        };

    }
}
#endif

