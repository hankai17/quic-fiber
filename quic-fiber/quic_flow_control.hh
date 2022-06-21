#ifndef __QUIC_FLOW_CONTROL_HH__
#define __QUIC_FLOW_CONTROL_HH__

#include <stdlib.h>
#include <float.h>
#include <cmath>
#include <map>
#include <deque>
#include <list>
#include <memory>
#include <functional>

#include "my_sylar/util.hh"
#include "my_sylar/thread.hh"
#include "quic-fiber/quic_utils.hh"
#include "quic-fiber/quic_type.hh"

namespace sylar {
    namespace quic {
        class FlowController {
        public:
            typedef std::shared_ptr<FlowController> ptr;
            // for sending
            virtual uint64_t sendWinSize() = 0;
            virtual void updateSendWin(uint64_t n) = 0;
            virtual void addBytesSent(uint64_t n) = 0;
            // for receiving
            virtual void addBytesRead(uint64_t n) = 0;
            virtual uint64_t getWinUpdate() = 0;
            virtual uint64_t isNewlyBlocked() = 0;
        };
        
        class BaseFlowController : public FlowController {
        public:
            typedef std::shared_ptr<BaseFlowController> ptr;
            typedef Mutex MutexType;
            // for connection
            BaseFlowController(uint64_t recv_win, uint64_t max_recv_win, 
                    const RTTStats::ptr &stat, const std::string &tag = "connection") :
                    m_receive_win(recv_win), 
                    m_receive_win_size(recv_win),
                    m_max_recv_win_size(max_recv_win),
                    m_rtt_stats(stat) {
                debug_tag = tag;
            }
            // for stream
            BaseFlowController(uint64_t recv_win, uint64_t max_recv_win, 
                    uint64_t initial_win_size, const RTTStats::ptr &stat, const std::string &tag = "stream") :
                    m_receive_win(recv_win), 
                    m_receive_win_size(recv_win),
                    m_max_recv_win_size(max_recv_win),
                    m_send_win(initial_win_size),
                    m_rtt_stats(stat) {
                debug_tag = tag;
            }

            // for sending
            virtual uint64_t sendWinSize() override;
            virtual void updateSendWin(uint64_t offset) override;
            virtual void addBytesSent(uint64_t n) override;

            // for receiving
            void startNewAutoTuningEpoch(uint64_t time);
            bool hasWinUpdate();
            void maybeAdjustWinSize();
            virtual void addBytesRead(uint64_t n) override;
            virtual uint64_t getWinUpdate() override;
            virtual uint64_t isNewlyBlocked() override;
            bool checkFlowControlViolation();

        //protected:
        public:
            // for receiving data
            MutexType m_mutex;
            uint64_t m_bytes_read = 0;
            uint64_t m_highest_received = 0;
            uint64_t m_receive_win;
            uint64_t m_receive_win_size;
            uint64_t m_max_recv_win_size;

            // for sending data
            uint64_t m_bytes_sent = 0;
            uint64_t m_send_win = (1 << 10) * 512 * 1.5; // TODO replace by nego
            uint64_t m_last_blocked_at = 0;

            uint64_t m_epoch_start_time = 0;
            uint64_t m_epoch_start_offset = 0;
            RTTStats::ptr m_rtt_stats = nullptr;
            std::string debug_tag;
        };

        class ConnectionFlowControllerI {
        public:
            typedef std::shared_ptr<ConnectionFlowControllerI> ptr;
            // for sending
            virtual void ensureMinWinSize(uint64_t n) = 0;
            // for receiving
            virtual bool incrementHighestReceived(uint64_t increment) = 0;
        };

        class ConnectionFlowController : public BaseFlowController,
                public ConnectionFlowControllerI {
        public:
            typedef std::shared_ptr<ConnectionFlowController> ptr;
            ConnectionFlowController(uint64_t recv_win, uint64_t max_recv_win, 
                    const RTTStats::ptr &stat, const std::function<void()> &queue_win_update)
                    : BaseFlowController(recv_win, max_recv_win, stat),
                      m_queue_win_update(queue_win_update) {}          

            // for sending just use parent BaseFlowController
            // for receiving
            virtual void addBytesRead(uint64_t n) override;
            virtual uint64_t getWinUpdate() override;

            virtual void ensureMinWinSize(uint64_t n) override;
            virtual bool incrementHighestReceived(uint64_t increment) override;

            void reset();
        private:            
            std::function<void()> m_queue_win_update;
        };

        class StreamFlowController : public BaseFlowController {
        public:
            typedef std::shared_ptr<StreamFlowController> ptr;
            typedef Mutex MutexType;
            StreamFlowController(QuicStreamId stream_id, ConnectionFlowController::ptr conn,
                    const std::function<void(QuicStreamId)> &queue_win_update,
                    uint64_t recv_win, uint64_t max_recv_win, 
                    uint64_t initial_send_win, const RTTStats::ptr &stat)
                    : BaseFlowController(recv_win, max_recv_win, initial_send_win, stat),
                      m_stream_id(stream_id),
                      m_connection(conn),
                      m_queue_win_update(queue_win_update) {}

            // for sending
            virtual uint64_t sendWinSize() override;
            virtual void addBytesSent(uint64_t n) override;

            // for receiving
            virtual void addBytesRead(uint64_t n) override;
            virtual uint64_t getWinUpdate() override;

            bool updateHighestReceived(uint64_t offset, bool final);
            void abandon();
            bool shouldQueueWinUpdate();
        private:
            QuicStreamId m_stream_id;
            ConnectionFlowController::ptr m_connection = nullptr;
            std::function<void(QuicStreamId)> m_queue_win_update;
            bool m_received_final_offset = false;
        };
    }
}

#endif

