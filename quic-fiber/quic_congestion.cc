#include "quic_congestion.hh"
#include <cmath>
#include <my_sylar/macro.hh>

namespace sylar {
    namespace quic {
        static sylar::Logger::ptr g_logger = SYLAR_LOG_NAME("system");

        void SlowStart::startReceiveRound(QuicPacketNumber last_sent) {
            m_end_pn = last_sent;
            m_cur_min_rtt = 0;
            m_rtt_sample_count = 0;
            m_started = true;
        }

        bool SlowStart::isEndOfRound(QuicPacketNumber ack) {
            return m_end_pn < ack;
        }

        bool SlowStart::shouldExitSlowStart(uint64_t latest_rtt, 
                uint64_t min_rtt, uint64_t cong_win) {
            if (!m_started) {
                startReceiveRound(m_last_sent_pn);
            }
            if (m_start_found) {
                SYLAR_LOG_WARN(g_logger) << "trace now: " << GetCurrentUs()
                                                 << " shouldExitSlowStart true";
                return true;
            }
            m_rtt_sample_count++;
            if (m_rtt_sample_count <= START_MIN_SAMPLES) {
                if (m_cur_min_rtt == 0 
                        || m_cur_min_rtt > latest_rtt) {
                    m_cur_min_rtt = latest_rtt;
                }
            }
            SYLAR_LOG_WARN(g_logger) << "trace now: " << GetCurrentUs()
                                     << " shouldExitSlowStart m_cur_min_rtt: " << m_cur_min_rtt
                                     << " min_rtt " << min_rtt;
            if (m_rtt_sample_count == START_MIN_SAMPLES) {
                uint64_t min_rtt_inc_threshold = (uint64_t)(min_rtt >> START_DELAY_FACTOR_EXP);
                min_rtt_inc_threshold = std::min(min_rtt_inc_threshold, START_DELAY_MAX_THRESHOULD);
                min_rtt_inc_threshold = std::max(min_rtt_inc_threshold, START_DELAY_MIN_THRESHOULD);
                if (m_cur_min_rtt > (min_rtt + min_rtt_inc_threshold)) {
                    m_start_found = true;
                }
            	SYLAR_LOG_WARN(g_logger) << "trace now: " << GetCurrentUs()
                                             << " shouldExitSlowStart sample is 8, m_cur_min_rtt: " << m_cur_min_rtt
					     << " min_rtt: " << min_rtt << " min_rtt_inc_threshold: " << min_rtt_inc_threshold
					     << " start_found: " << m_start_found << " cong_win: " << cong_win;
            }
            return (cong_win >= START_LOW_WIN) && 
                    m_start_found;
        }

        void SlowStart::onPacketAcked(QuicPacketNumber ack_pn) {
            if (isEndOfRound(ack_pn)) {
                m_started = false;
            }
        }

        void SlowStart::restart() {
            m_started = false;
            m_start_found = false;
        }

        /// Cubic
        void Cubic::reset() {
            m_epoch = GetCurrentUs();
            m_last_max_cong_win = 0;
            m_acked_bytes_count = 0;
            m_estimated_tcp_cong_win = 0;
            m_ori_point_cong_win = 0;
            m_time_to_ori_point = 0;
            m_last_target_cong_win = 0;
        }

        float Cubic::beta() {
            return (float(m_num_connections - 1) + Beta) / float(m_num_connections);
        }

        float Cubic::alpha() {
            float b = beta();
            return 3 * float(m_num_connections) * float(m_num_connections) * (1 - b) / (1 + b);
        }

        float Cubic::betaLastMax() {
            return (float(m_num_connections - 1) + BetaLastMax) / float(m_num_connections);
        }

        void Cubic::onApplicationLimited() {
            m_epoch = GetCurrentUs();
        }

        uint64_t Cubic::congestionWinAfterPacketLoss(uint64_t cur_cong_win) {
            if (cur_cong_win + MaxDatagramSize < m_last_max_cong_win) {
                m_last_max_cong_win = uint64_t(betaLastMax() * float(cur_cong_win));
            } else {
                m_last_max_cong_win = cur_cong_win;
            }
            m_epoch = GetCurrentUs();
            return uint64_t(float(cur_cong_win) * beta());
        }

        uint64_t Cubic::congestionWinAfterAck(uint64_t acked_bytes, uint64_t cur_cong_win,
                                       uint64_t delay_min, uint64_t event_time) {
            m_acked_bytes_count += acked_bytes;
            if (m_epoch == 0) {
                m_epoch = event_time;
                m_acked_bytes_count = acked_bytes;
                m_estimated_tcp_cong_win = cur_cong_win;
                if (m_last_max_cong_win <= cur_cong_win) {
                    m_time_to_ori_point = 0;
                    m_ori_point_cong_win = cur_cong_win;
                } else {
                    m_time_to_ori_point = (uint64_t)cbrt(float(
                            CubeFactor * (m_last_max_cong_win - cur_cong_win)
                            ));
                    m_ori_point_cong_win = m_last_max_cong_win;
                }
            }
            int64_t elapsed_time = (int64_t)(
                    (event_time + delay_min - m_epoch) << 10 / (1000 * 1000)
            );
            int64_t offset = (int64_t)(m_time_to_ori_point) - elapsed_time;
            if (offset < 0) {
                offset = -offset;
            }
            uint64_t delta_cong_win = CubeCongestionWindowScale * offset * offset * offset * MaxDatagramSize
                    >> CubeScale;
            uint64_t target_cong_win = 0;
            if (elapsed_time > (int64_t)m_time_to_ori_point) {
                target_cong_win = m_ori_point_cong_win + delta_cong_win;
            } else {
                target_cong_win = m_ori_point_cong_win - delta_cong_win;
            }
            target_cong_win = std::min( target_cong_win, cur_cong_win + m_acked_bytes_count/2);
            m_estimated_tcp_cong_win += uint64_t(float(m_acked_bytes_count) * alpha() * float(MaxDatagramSize) /
                    float(m_estimated_tcp_cong_win));
            m_acked_bytes_count = 0;
            m_last_target_cong_win = target_cong_win;
            if (target_cong_win < m_estimated_tcp_cong_win) {
                target_cong_win = m_estimated_tcp_cong_win;
            }
            return target_cong_win;
        }

        /// CubicSender
        void CubicSender::maybeExitSlowStart() {
            if (inSlowStart() && 
                    m_slow_start.shouldExitSlowStart(m_rtt->latestRTT(),
                            m_rtt->minRTT(), getCongestionWindow() / m_max_datagram_size)) {
                SYLAR_LOG_WARN(g_logger) << "trace now: " << GetCurrentUs()
                                                 << " maybeExitSlowStart m_slow_start_threshold " << m_cong_win;
                m_slow_start_threshold = m_cong_win;
            }
        }

        CubicSender::CubicSender(uint64_t clock, RTTStats::ptr stats, bool reno,
                uint64_t initial_max_datagram_size, uint64_t initial_cong_win, uint64_t initial_max_cong_win)
                : m_clock(clock),
                m_rtt(stats),
                m_reno(reno),
                m_max_datagram_size(initial_max_datagram_size),
                m_initial_cong_win(initial_cong_win),
                m_initial_max_cong_win(initial_max_cong_win) {
                    m_cubic = std::make_shared<Cubic>();
                    m_pacer = std::make_shared<Pacer>(
                            [this]()->uint64_t {
                        uint64_t srtt = m_rtt->smoothedRTT();
                        if (srtt == 0) {
                            return ~0ull;
                        }
                        uint64_t cong_size = this->getCongestionWindow();
                        SYLAR_LOG_WARN(g_logger) << "trace now: " << GetCurrentUs()
                                                         << " congestion_win " << cong_size;
                        return cong_size * 1000 * 1000 / srtt;
                        }
                    );
        }

        void CubicSender::init() {
            m_pacer = std::make_shared<Pacer>(
                    std::bind(&CubicSender::bwEstimate, shared_from_this())
                    );
        }

        uint64_t CubicSender::bwEstimate() {
            uint64_t srtt = m_rtt->smoothedRTT();
            if (srtt == 0) {
                return ~0ull;
            }
            srtt = srtt / 1000 / 1000;
            return getCongestionWindow() / srtt * 8;
        }

        bool CubicSender::isCwndLimited(uint64_t bytes_inflight) {
            uint64_t cong_win = getCongestionWindow();
            if (bytes_inflight >= cong_win) {
                return true;
            }
            uint64_t available_bytes = cong_win - bytes_inflight;
            uint64_t slow_start_limited = inSlowStart() && bytes_inflight > cong_win / 2;
            return slow_start_limited ||
                    available_bytes <= MaxBurstPackets * m_max_datagram_size;
        }

        bool CubicSender::inSlowStart() {
            return getCongestionWindow() < m_slow_start_threshold;
        }

        void CubicSender::maybeIncreaseCwnd(QuicPacketNumber pn, uint64_t acked_bytes,
                uint64_t prior_inflight, uint64_t event_time) {
            if (!isCwndLimited(prior_inflight)) {
                m_cubic->onApplicationLimited();
                return;
            }
            if (m_cong_win >= maxCongestionWindow()) {
                return;
            }
            if (inSlowStart()) {
                m_cong_win += m_max_datagram_size;
                return;
            }
            // congestion avoidance
            if (m_reno) { // classic reno congestion avoidance
                m_num_acked_packets++;
                if (m_num_acked_packets >= (uint64_t)(m_cong_win / m_max_datagram_size)) {
                    m_cong_win += m_max_datagram_size;
                    m_num_acked_packets = 0;
                }
            } else {
                m_cong_win = std::min(
                        maxCongestionWindow(),
                        m_cubic->congestionWinAfterAck(acked_bytes, m_cong_win, m_rtt->minRTT(), event_time)
                        );
            }
        }

        bool CubicSender::inRecovery() {
            return (m_largest_acked_pn != ~0ull) &&
                    m_largest_acked_pn <= m_largest_sent_at_last_cutback;
        }

        void CubicSender::onPacketAcked(QuicPacketNumber acked_pn, uint64_t acked_bytes,
                uint64_t prior_inflight, uint64_t event_time) {
            m_largest_acked_pn = std::max(acked_pn, m_largest_acked_pn);
            if (inRecovery()) {
                return;
            }
            maybeIncreaseCwnd(acked_pn, acked_bytes, prior_inflight, event_time);
            SYLAR_LOG_WARN(g_logger) << "trace now: " << GetCurrentUs()
                                     << "  onPacketAcked " << m_cong_win;
            if (inSlowStart()) {
                m_slow_start.onPacketAcked(acked_pn);
            }
        }

        void CubicSender::onPacketSent(uint64_t sent_time, uint64_t bytes_inflight,
                QuicPacketNumber pn, uint64_t bytes, bool is_retransmittable) {
            m_pacer->sentPacket(sent_time, bytes_inflight);
            if (!is_retransmittable) {
                return;
            }
            m_largest_sent_pn = pn;
            m_slow_start.onPacketSent(pn);
        }

         void CubicSender::onPacketLost(QuicPacketNumber pn, uint64_t lost_bytes,
                 uint64_t prior_infligth) {
             if (m_largest_sent_at_last_cutback != ~0ull && 
                     pn <= m_largest_sent_at_last_cutback) {
                 return;
             }
             m_last_cutback_exited_slow_start = inSlowStart();
             if (m_reno) {
                 m_cong_win = (uint64_t)(float(m_cong_win) * RenoBeta);
             } else {
                 m_cong_win = m_cubic->congestionWinAfterPacketLoss(m_cong_win);
             }

             uint64_t min_cwnd = minCongestionWindow();
             if (m_cong_win < min_cwnd) {
                 m_cong_win = min_cwnd;
             }
             m_slow_start_threshold = m_cong_win;
             SYLAR_LOG_WARN(g_logger) << "trace now: " << GetCurrentUs()
                                      << "  onPacketLost " << m_cong_win;
             m_largest_sent_at_last_cutback = m_largest_sent_pn;
             m_num_acked_packets = 0;
         }

        void CubicSender::onRetransmissionTimeout(bool packet_retransmitted) {
            m_largest_sent_at_last_cutback = ~0ull;
            if (!packet_retransmitted) {
                return;
            }
            m_slow_start.restart();
            m_cubic->reset();
            m_slow_start_threshold = m_cong_win / 2;
            SYLAR_LOG_WARN(g_logger) << "trace now: " << GetCurrentUs()
                                     << "  slow_start_threshold2 " << m_slow_start_threshold;
            m_cong_win = minCongestionWindow();
        }

        void CubicSender::setMaxDatagramSize(uint64_t s) {
            if (s < m_max_datagram_size) {
                SYLAR_ASSERT(0);
            }
            bool cwnd_is_min_cwnd = m_cong_win == minCongestionWindow();
            m_max_datagram_size = s;
            if (cwnd_is_min_cwnd) {
                m_cong_win = minCongestionWindow();
            }
            m_pacer->setMaxDatagramSize(s);
        }
    }
}
