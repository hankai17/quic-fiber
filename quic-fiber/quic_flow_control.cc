#include "quic_flow_control.hh"
#include "my_sylar/log.hh"

#include <math.h>

namespace sylar {
    namespace quic {
        static sylar::Logger::ptr g_logger = SYLAR_LOG_NAME("system");

        /// BaseFlowController
        uint64_t BaseFlowController::sendWinSize() {
            if (m_bytes_sent > m_send_win) {
                return 0;
            }
            return m_send_win - m_bytes_sent;
        }

        void BaseFlowController::updateSendWin(uint64_t offset) { 
            if (offset > m_send_win) {
                m_send_win = offset; 
            }
        }

        void BaseFlowController::addBytesSent(uint64_t n) { 
            m_bytes_sent += n;
        }

        void BaseFlowController::startNewAutoTuningEpoch(uint64_t now) {
            m_epoch_start_time = now;
            m_epoch_start_offset = m_bytes_read;
        }

        bool BaseFlowController::hasWinUpdate() {
            uint64_t bytes_remaining = m_receive_win - m_bytes_read;
            if (bytes_remaining <= (uint64_t)(float(m_receive_win_size * (1 - 0.25)))) {
                SYLAR_LOG_DEBUG(g_logger) << "consume more 1/4 * " << m_receive_win_size;
                return true;
            }
            return false;
        }

        void BaseFlowController::maybeAdjustWinSize() {
            uint64_t bytes_read_in_epoch = m_bytes_read - m_epoch_start_offset;
            if (bytes_read_in_epoch <= m_receive_win_size / 2) {
                return;
            }
            uint64_t rtt = m_rtt_stats->smoothedRTT();
            if (rtt == 0) {
                return;
            }
            float fraction = (float)bytes_read_in_epoch / (float)m_receive_win_size;
            uint64_t now = sylar::GetCurrentUs();
            uint64_t diff = now - m_epoch_start_time;
            uint64_t base_diff = 4 * fraction * (float)rtt;

            if (diff < base_diff) {
                SYLAR_LOG_WARN(g_logger) << "aggresive set recv_win_size";
                m_receive_win_size = std::min(
                    2 * m_receive_win_size, m_max_recv_win_size
                );
            }
            if (debug_tag == "stream") {
                SYLAR_LOG_WARN(g_logger) << "real_diff: " << diff << ", base_diff: " << base_diff
                                         << ", fraction: " << fraction << ", rtt: " << rtt
                                         << ", m_bytes_read: " << m_bytes_read
                                         << ", m_epoch_start_offset: " << m_epoch_start_offset
                                         << ", m_receive_win_size: " << m_receive_win_size;
            }
            startNewAutoTuningEpoch(now);
        }

        void BaseFlowController::addBytesRead(uint64_t n) {
            if (m_bytes_read == 0) {
                startNewAutoTuningEpoch(sylar::GetCurrentUs());
            }
            m_bytes_read += n;
        }

        uint64_t BaseFlowController::getWinUpdate() {
            if (!hasWinUpdate()) {
                return 0;
            }
            maybeAdjustWinSize();
            m_receive_win = m_bytes_read + m_receive_win_size;
            if (debug_tag == "stream") {
                SYLAR_LOG_WARN(g_logger) << "trace now: " << GetCurrentUs()
                                         << " getWinUpdate receive_win " << m_receive_win
                                         << " receive_win_size " << m_receive_win_size
                                         << " bytes_read " << m_bytes_read;
            }
            return m_receive_win;
        }

        uint64_t BaseFlowController::isNewlyBlocked() {
            if (sendWinSize() != 0 ||
                    m_send_win == m_last_blocked_at) {
                return 0;
            }
            m_last_blocked_at = m_send_win;
            return m_send_win;
        }

        bool BaseFlowController::checkFlowControlViolation() {
            return m_highest_received > m_receive_win;
        }

        /// ConnectionFlowController
        void  ConnectionFlowController::addBytesRead(uint64_t n) {
            MutexType::Lock lock(m_mutex);
            BaseFlowController::addBytesRead(n);
            bool should_queue_win_update = hasWinUpdate();
            lock.unlock();
            if (should_queue_win_update) {
                m_queue_win_update();
            }
        }

        uint64_t ConnectionFlowController::getWinUpdate() {
            MutexType::Lock lock(m_mutex);
            uint64_t old_win_size = m_receive_win_size;
            uint64_t offset = BaseFlowController::getWinUpdate();
            if (old_win_size < m_receive_win_size) {
                // TODO
            }
            lock.unlock();
            return offset;
        }

        void ConnectionFlowController::ensureMinWinSize(uint64_t n) {
            MutexType::Lock lock(m_mutex);
            if (n > m_receive_win_size) {
                m_receive_win_size = std::min(n, m_max_recv_win_size);
                startNewAutoTuningEpoch(GetCurrentUs());
            }
        }

        bool ConnectionFlowController::incrementHighestReceived(uint64_t increment) {
            MutexType::Lock lock(m_mutex);
            m_highest_received += increment;
            if (checkFlowControlViolation()) {
                return false;
            }
            return true;
        }

        void ConnectionFlowController::reset() {
            MutexType::Lock lock(m_mutex);
            if (m_bytes_read > 0 || 
                    m_highest_received > 0 ||
                    !m_epoch_start_time) {
                return;
            }
            m_bytes_sent = 0;
            m_last_blocked_at = 0;
            return;
        }

        /// StreamFlowController
        uint64_t StreamFlowController::sendWinSize() {
            uint64_t base_send_win_size = BaseFlowController::sendWinSize();
            uint64_t conn_send_win_size = m_connection->sendWinSize();
            return std::min(base_send_win_size, conn_send_win_size);
        }

        void StreamFlowController::addBytesSent(uint64_t n) {
            uint64_t old_m_send_win = 0;
            old_m_send_win = m_send_win;
            BaseFlowController::addBytesSent(n);
            m_connection->addBytesSent(n);
            if (m_send_win > old_m_send_win) {
                SYLAR_LOG_WARN(g_logger) << "after stream::addBytesSent: " << m_bytes_sent << " m_send_win: " << m_send_win
                                         << ", conn m_bytes_sent: " << m_connection->m_bytes_sent << " m_send_win: " << m_connection->m_send_win;
            }
        }

        void StreamFlowController::addBytesRead(uint64_t n) {
            MutexType::Lock lock(m_mutex);
            bool should_queue_win_update = false;
            BaseFlowController::addBytesRead(n);
            should_queue_win_update = shouldQueueWinUpdate();
            m_mutex.unlock();
            if (should_queue_win_update) {
                m_queue_win_update(m_stream_id);
            }
            m_connection->addBytesRead(n);
        }

        uint64_t StreamFlowController::getWinUpdate() {
            if (m_received_final_offset) {
                return 0;
            }
            MutexType::Lock lock(m_mutex);
            uint64_t old_win_size = m_receive_win_size;
            uint64_t offset = BaseFlowController::getWinUpdate();
            if (m_receive_win_size > old_win_size) {
                SYLAR_LOG_DEBUG(g_logger) << "Increasing receive flow control window to %d kB";
                m_connection->ensureMinWinSize(
                    (uint64_t)(m_receive_win_size * 1.5) // TODO
                );
            }
            lock.unlock();
            return offset;
        }

        bool StreamFlowController::updateHighestReceived(uint64_t offset, bool final) {
            if (m_received_final_offset) {
                if (final && (offset != m_highest_received)) {
                    return false;
                }
                if (offset > m_highest_received) {
                    return false;
                }
            }
    
            if (final) {
                m_received_final_offset = true;
            }
            if (offset == m_highest_received) {
                return true;
            }
            if (offset <= m_highest_received) {
                if (final) {
                    return false;
                }
                return true;
            }
            uint64_t increment = offset - m_highest_received;
            m_highest_received = offset;
            if (checkFlowControlViolation()) {
                return false;
            }
            return m_connection->incrementHighestReceived(increment);
        }

        void StreamFlowController::abandon() {
            MutexType::Lock lock(m_mutex);
            uint64_t unread = m_highest_received - m_bytes_read;
            lock.unlock();
            if (unread > 0) {
                m_connection->addBytesRead(unread);
            }
        }

        bool StreamFlowController::shouldQueueWinUpdate() {
            return !m_received_final_offset && hasWinUpdate();
        }
    }
}
