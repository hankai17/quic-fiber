#ifndef __QUIC_STREAM_HH__
#define __QUIC_STREAM_HH__

#include "my_sylar/thread.hh"
#include "my_sylar/stream.hh"
#include "my_sylar/mbuffer.hh"
#include "quic-fiber/quic_type.hh"
#include "quic-fiber/quic_frame.hh"
#include "quic-fiber/quic_frame_sorter.hh"
#include "quic-fiber/quic_flow_control.hh"

#include <memory>
#include <list>
#include <utility>
#include <functional>
#include <queue>
#include <unordered_map>

namespace sylar {
    namespace quic {
        class QuicSession;
        struct timer_info {
            int cancelled = 0;
        };

        class QuicStreamNumber {
        public:
            static QuicStreamId streamID(QuicStreamNum num, QuicStreamType type, QuicRole role);
        };

        QuicRole StreamIdInitialedBy(QuicStreamId id);
        QuicStreamType StreamIdType(QuicStreamId id);
        QuicStreamNum StreamID2Num(QuicStreamId id);

        class QuicConnectionInfo {
        public:
            typedef std::shared_ptr<QuicConnectionInfo> ptr;
        private:
        };

        class QuicStreamResult {
        public:
            typedef std::shared_ptr<QuicStreamResult> ptr;

            enum class Error {
                OK                      = 0,
                STREAM_EOF              = 1,
                CANCEL_READ             = 2,
                RESET_BY_REMOTE         = 3,
                SHUTDOWN                = 4,
                TIMEOUT                 = 5,
                /// write
                WRITE_ON_CLOSED_STREAM  = 10,
                CANCEL_WRITE            = 11,
                WRITE_BUFFER_EMPTY      = 12,
                UNKNOW
            };

            QuicStreamResult(bool completed, int bytes, int result, const std::string &err = "")
                : m_stream_completed(completed), m_bytes_rw(bytes), 
                  m_result(result), m_error(err) {}
            std::string toString() const;
            //std::string QuicStreamErrorToString(QuicStreamError error);

            bool isCompleted() const { return m_stream_completed; }
            int bytes_rw() const { return m_bytes_rw; }
            int err_no() const { return m_result; }
            std::string strerr() const { return m_error; }

        private:
            bool m_stream_completed = false;
            int m_bytes_rw = 0;
            int m_result = 0;
            std::string m_error = "";
        };

        class QuicRcvStream : public std::enable_shared_from_this<QuicRcvStream> {
        public:
            typedef std::shared_ptr<QuicRcvStream> ptr;
            typedef Mutex MutexType;

            QuicRcvStream(QuicStreamId stream_id, std::weak_ptr<StreamSender> sender,
                    const StreamFlowController::ptr &fc);
            virtual ~QuicRcvStream() {}
            std::string toString() const;

            const QuicConnectionError::ptr handleStreamFrame(const QuicStreamFrame::ptr &frame);
            const QuicConnectionError::ptr handleRstStreamFrame(const QuicRstStreamFrame::ptr &frame);
            void dequeueNextFrame();
            void waitRead();
            void signalRead();

            void cancelRead();
            void closeForShutdown();
            const QuicStreamResult::ptr read(const MBuffer::ptr &buffer_block, size_t length);

            QuicStreamId stream_id() const { return m_stream_id; }
            void set_stream_id(QuicStreamId id) { m_stream_id = id; }
            const FrameSorter &getFrameSorter() const { return m_received_frame_queue; }
            const StreamFlowController::ptr &getFlowController() const { return m_flow_controller; }
            uint64_t getWinUpdate();
        private:
            int m_pop_failed_count = 0;
            MutexType m_mutex;
            QuicStreamId m_stream_id = 0;
            QuicOffset m_read_offset = 0;
            QuicOffset m_final_offset = ~0ull;
            MBuffer::ptr m_current_frame = nullptr;
            std::function<void()> m_current_frame_done_cb = nullptr;
            bool m_current_frame_is_last = false;
            QuicOffset m_read_pos_in_frame = 0;
            std::weak_ptr<StreamSender> m_sender;

            bool m_shutdown = false;
            bool m_fin_read = false;
            bool m_canceld_read = false;
            bool m_reset_by_remote = false;

            FiberSemaphore::ptr m_wait_read_sem = nullptr;
            uint64_t m_deadline = 0;

            FrameSorter m_received_frame_queue;
            StreamFlowController::ptr m_flow_controller;
            QuicVersion m_version;
        };

        class QuicSndStream : public std::enable_shared_from_this<QuicSndStream> {
        public:
            typedef std::shared_ptr<QuicSndStream> ptr;
            typedef Mutex MutexType;

            QuicSndStream(QuicStreamId stream_id, std::weak_ptr<StreamSender> sender,
                    const StreamFlowController::ptr &fc)
                    : m_stream_id(stream_id), m_sender(sender),
                      m_flow_controller(fc) {}
            virtual ~QuicSndStream() {}

            void waitWrite() { m_wait_write_sem.wait(); }
            void signalWrite() { m_wait_write_sem.notify(); }

            bool canBufferStreamFrame();
            const QuicStreamResult::ptr write(const MBuffer::ptr &buffer_block);

            // called by lower
            void get_data_for_writing(QuicStreamFrame::ptr stream_frame, size_t max_bytes);
            bool popNewStreamFrameWithoutBuffer(QuicStreamFrame::ptr frame, size_t max_bytes, size_t send_win);
            std::tuple<QuicStreamFrame::ptr, bool> popNewStreamFrame(size_t max_bytes, size_t send_win);
            std::tuple<QuicStreamFrame::ptr, bool> maybeGetRetransmission(size_t max_bytes);
            std::tuple<QuicStreamFrame::ptr, bool> popNewOrRetransmissitedStreamFrame(size_t max_bytes);
            std::tuple<QuicStreamFrame::ptr, bool> popStreamFrame(size_t max_bytes);

            void queueRetransmission(const QuicFrame::ptr &frame);
            void frameAcked(const QuicFrame::ptr &frame);

            const QuicStreamResult::ptr close();
            bool isNewlyCompleted();
            void cancelWrite();
            void closeForShutdown();

            QuicStreamId stream_id() const { return m_stream_id; }
            void set_stream_id(QuicStreamId id) { m_stream_id = id; }
            const StreamFlowController::ptr &getFlowController() const { return m_flow_controller; }

            void updateSendWin(uint64_t limit);
            void handleStopSendingFrame(QuicStopSendingFrame::ptr frame);
            const QuicStreamFrame::ptr &nextFrame() const { return m_next_frame; }
            QuicOffset writeOffset() const { return m_write_offset; }
            std::string toStatisticsString() const;

        private:
            MutexType m_mutex;
            QuicStreamId m_stream_id = 0;
            int64_t m_num_outstanding_frames = 0;
            std::list<QuicStreamFrame::ptr> m_retransmission_queue;
            QuicStreamFrame::ptr m_next_frame = nullptr;
            QuicOffset m_write_offset = 0;
            MBuffer::ptr m_data_for_writing = nullptr;
            std::weak_ptr<StreamSender> m_sender;

            bool m_shutdown = false;
            bool m_finished_writing = false; // set once close() is called
            bool m_canceled_write = false;
            bool m_reset_by_remote = false;
            bool m_fin_sent = false;
            bool m_complete = false;

            FiberSemaphore m_wait_write_sem;
            uint64_t m_deadline = 0;

            StreamFlowController::ptr m_flow_controller;
            QuicVersion m_version;

            uint64_t m_sum_sent_packet = 0;
            uint64_t m_sum_retrans_packet = 0;
            uint64_t m_sum_bytes_sent_packet = 0;
            uint64_t m_sum_bytes_retrans_packet = 0;
        };

        class QuicStream : public std::enable_shared_from_this<QuicStream> {
        public:
            friend QuicSession;
            typedef std::shared_ptr<QuicStream> ptr;
            QuicStream(QuicStreamId stream_id, std::weak_ptr<StreamSender> sender,
                    const StreamFlowController::ptr &fc)
                : m_sender(sender) {
                m_send_stream = std::make_shared<QuicSndStream>(stream_id, m_sender, fc);
                m_receive_stream = std::make_shared<QuicRcvStream>(stream_id, m_sender, fc);
            }
            virtual ~QuicStream() {
                std::cout << "~QuicStream" << std::endl;
            }

            const std::shared_ptr<StreamSender> getSender() const { return m_sender.lock(); } // can not return const &
            const QuicStreamResult::ptr read(MBuffer::ptr buffer_block, size_t length) {
                return m_receive_stream->read(buffer_block, length);
            }
            const QuicStreamResult::ptr write(MBuffer::ptr buffer_block) {
                return m_send_stream->write(buffer_block);
            }
            const QuicStreamResult::ptr close() {
                return m_send_stream->close();
            }
            void closeForShutdown() {
                m_send_stream->closeForShutdown();
                m_receive_stream->closeForShutdown();
            }
            void updateSendWin(uint64_t limit) { return m_send_stream->updateSendWin(limit); }
            const QuicRcvStream::ptr &readStream() const { return m_receive_stream; }
            const QuicSndStream::ptr &writeStream() const { return m_send_stream; }
            QuicStreamId stream_id() const { return m_receive_stream->stream_id(); }

            uint64_t getWinUpdate();
            std::string toSndStatisticsString() const { return m_send_stream->toStatisticsString(); }
        private:
            std::weak_ptr<StreamSender> m_sender;
            QuicRcvStream::ptr          m_receive_stream = nullptr;
            QuicSndStream::ptr          m_send_stream = nullptr;
        };

        class QuicBuffer {
        public:
            typedef std::shared_ptr<QuicBuffer> ptr;
            QuicBuffer();
            ~QuicBuffer();

            int bufferRead(void *data, size_t length); // copyOut
            int bufferWrite(void *data, size_t length);

            const MBuffer::ptr &readBuffer() const { return m_read_buffer; }
            const MBuffer::ptr &writeBuffer() const { return m_write_buffer; }
            const Address::ptr &getAddr() const { return m_remote_addr; }

        private:
            Address::ptr m_remote_addr;
            MBuffer::ptr m_read_buffer;
            MBuffer::ptr m_write_buffer;
        };

        struct QuicStreamEntry {
            QuicStream::ptr stream = nullptr;
            bool shouldDelete = false;
        };

        class QuicIncomingBidiStreamsMap {
        public:
            typedef std::shared_ptr<QuicIncomingBidiStreamsMap> ptr;
            typedef RWMutex RWMutexType;
            QuicIncomingBidiStreamsMap(const std::function<QuicStream::ptr(QuicStreamNum)> &new_stream_cb,
                                       const std::function<void(QuicFrame::ptr)> &queue_control_frame_cb, uint64_t max_streams = 1024)
                    : m_new_stream_cb(new_stream_cb),
                      m_queue_max_stream_id_cb(queue_control_frame_cb) {}

            QuicStream::ptr acceptStream();
            QuicStream::ptr getOrOpenStream(QuicStreamNum num);
            bool deleteStream(QuicStreamNum num);
            bool deleteStreamImp(QuicStreamNum num);
            void closeWithErr();

            void waitAccept() { m_wait_accept_sem.wait(); }
            void signalAccept() { m_wait_accept_sem.notify(); }
            const std::unordered_map<QuicStreamNum, QuicStreamEntry>& streams() const { return m_streams; }
        //private:
        public:
            RWMutexType             m_mutex;
            sylar::FiberSemaphore   m_wait_accept_sem;
            std::unordered_map<QuicStreamNum, QuicStreamEntry> m_streams;
            QuicStreamNum m_next_stream_to_accept = 1;
            QuicStreamNum m_next_stream_to_open = 1;
            QuicStreamNum m_max_stream = ~0ull;
            uint64_t m_max_num_streams = ~0ull;
            std::function<QuicStream::ptr(QuicStreamNum)> m_new_stream_cb;
            std::function<void(QuicMaxStreamsFrame::ptr)> m_queue_max_stream_id_cb;
            bool m_closed = false;
        };

        class QuicOutgoingBidiStreamsMap {
        public:
            typedef std::shared_ptr<QuicOutgoingBidiStreamsMap> ptr;
            typedef RWMutex RWMutexType;
            QuicOutgoingBidiStreamsMap(const std::function<QuicStream::ptr(QuicStreamNum)> &new_stream_cb,
                    const std::function<void(QuicFrame::ptr)> &queue_control_frame_cb)
                    : m_new_stream_cb(new_stream_cb),
                      m_queue_streamid_blocked_cb(queue_control_frame_cb) {}

            QuicStream::ptr openStreamImp();
            void maybeSendBlockedFrame();
            QuicStream::ptr openStream();
            QuicStream::ptr openStreamSync();
            QuicStream::ptr getStream(QuicStreamNum num);
            int deleteStream(QuicStreamNum num);
            void unblockOpenSync();
            void setMaxStream(QuicStreamNum num);
            void updateSendWin(uint64_t limit);
            void closeWithErr();
            const std::unordered_map<QuicStreamNum, QuicStream::ptr> &streams() const { return m_streams; };
        private:
            RWMutexType             m_mutex;
            std::unordered_map<QuicStreamNum, QuicStream::ptr> m_streams;
            std::unordered_map<uint64_t, QuicStream::ptr> m_open_streams;
            uint64_t m_lowest_in_queue = 0;
            uint64_t m_highest_in_queue = ~0ull;
            QuicStreamNum m_next_stream = 1;
            QuicStreamNum m_max_stream = ~0ull;
            bool m_blocked_sent = false;
            std::function<QuicStream::ptr(QuicStreamNum)> m_new_stream_cb;
            std::function<void(QuicStreamsBlockedFrame::ptr)> m_queue_streamid_blocked_cb;
            bool m_closed = false;
        };

        class QuicStreamManager {
        public:
            typedef std::shared_ptr<QuicStreamManager> ptr;
            typedef RWMutex RWMutexType;

            QuicStreamManager(QuicRole role,
                    const std::function<StreamFlowController::ptr(QuicStreamId)> &new_fc);
            ~QuicStreamManager() {}
            void initMaps();
            void setSessoin(const std::shared_ptr<QuicSession> &session);
            std::shared_ptr<StreamSender> getSession() const;

            int streamInitiatedBy(QuicStreamId id);
            QuicStream::ptr openStream();
            QuicStream::ptr acceptStream();
            void deleteStream(QuicStreamId id);
            QuicRcvStream::ptr getOrOpenReceiveStream(QuicStreamId id);
            QuicSndStream::ptr getOrOpenSendStream(QuicStreamId id);
            void closeWithErr();

            bool hasData(); // TODO
            int popStreamFrames(std::list<QuicFrame::ptr> &frames, uint64_t max_packet_size);

        private:
            RWMutexType             m_mutex;
            sylar::FiberSemaphore   m_wait_accept_sem;
            QuicRole                m_role;
            std::weak_ptr<StreamSender> m_sender;
            uint64_t m_num_incoming_streams = 0;
            QuicStreamId m_max_incoming_streams = 1024;
            QuicStreamId m_next_stream = 0;
            QuicStreamId m_next_stream_to_accept = 0;

            QuicStreamId m_highest_opened_by_peer = 0;
            std::queue<QuicStream::ptr> m_open_streams;
            std::function<StreamFlowController::ptr(QuicStreamId)> m_new_flow_control_cb;

            QuicOutgoingBidiStreamsMap::ptr m_outgoing_bidi_streams_map;
            QuicIncomingBidiStreamsMap::ptr m_incoming_bidi_streams_map;
        };
    }
}
#endif

