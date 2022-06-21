#include "quic_utils.hh"

#include "my_sylar/log.hh"
#include <math.h>
#include <iostream>

namespace sylar {
    namespace quic {

        static sylar::Logger::ptr g_logger = SYLAR_LOG_NAME("system");
        /// RTTStats
        uint64_t RTTStats::PTO(bool include_max_ack_delay) {
            if (smoothedRTT() == 0) {
                return 2 * DEFAULT_INITIAL_RTT;
            }
            uint64_t pto = smoothedRTT() + std::max(4 * meanDeviation(), 1000UL);
            if (include_max_ack_delay) {
                pto += maxAckDelay();
            }
            return pto;
        }

        static uint64_t abs_diff(uint64_t a, uint64_t b) {
            if (a > b) {
                return a - b;
            }
            return b - a;
        }

        void RTTStats::updateRTT(uint64_t send_delta, uint64_t ack_delay, uint64_t now) {
            if (send_delta == std::numeric_limits<uint64_t>::max() || send_delta <= 0) {
                return;
            }
            if (m_min_rtt == 0 || m_min_rtt > send_delta) {
                m_min_rtt = send_delta;
            }
            uint64_t sample = send_delta;
            if (sample - m_min_rtt >= ack_delay) {
                sample -= ack_delay;
            }
            m_latest_rtt = sample;
            SYLAR_LOG_DEBUG(g_logger) << "receivedAck updateRTT real_rtt: " << send_delta << ", ack_delay: " << ack_delay
                      << ", min_rtt: " << m_min_rtt << ", sample: " << sample;
            if (!m_has_measurement) {
                m_has_measurement = true;
                m_smoothed_rtt = sample;
                m_mean_deviation = sample / 2;
            } else {
                m_mean_deviation = ONE_MINUS_BETA * m_mean_deviation + RTT_BETA * abs_diff(m_smoothed_rtt, sample);
                m_smoothed_rtt = ONE_MINUS_ALPHA * m_smoothed_rtt + RTT_ALPHA * sample;
            }
            SYLAR_LOG_WARN(g_logger)<< "trace now: " << GetCurrentUs()
                                    << " real_rtt: " << send_delta << " ack_delay: " << ack_delay
                                    << " min_rtt: " << m_min_rtt << " sample: " << sample
                                    << " m_smoothed_rtt: " << m_smoothed_rtt
                                    << " m_mean_deviation: " << m_mean_deviation;
        }

        void RTTStats::setInitialRTT(uint64_t t) {
            if (m_has_measurement) {
	            printf("initial RTT set after first measurement");
            }
            m_smoothed_rtt = t;
            m_latest_rtt = t;
        }

        void RTTStats::onConnectionMigration() {
            m_min_rtt = 0;
            m_latest_rtt = 0;
            m_smoothed_rtt = 0;
            m_mean_deviation = 0;
        }

        void RTTStats::expireSmoothedMetrics() {
            m_mean_deviation = std::max(m_mean_deviation, abs_diff(m_smoothed_rtt, m_latest_rtt));
            m_smoothed_rtt = std::max(m_smoothed_rtt, m_latest_rtt);
        }
        
        /// Pacer
        Pacer::Pacer(std::function<uint64_t()> get_bw) {
            m_max_datagram_size = InitialMaxDatagramSize;
            m_get_adjust_bw_cb = get_bw;
            m_budget_at_last_sent = maxBurstSize();
        }

        uint64_t Pacer::maxBurstSize() {
            uint64_t bw_size = m_get_adjust_bw_cb();
            uint64_t ideal_size = (MinPacingDelay + 1000) * bw_size / 1000 / 1000;
            return 10 * 1024;
            return std::max(
                //(MinPacingDelay + 1000) * m_get_adjust_bw_cb() / 1000 / 1000,
                ideal_size,
                MaxBurstSizePackets * m_max_datagram_size
            );
        }

        uint64_t Pacer::budget(uint64_t now) {
            if (!m_last_sent_time) {
                return maxBurstSize();
            }
            uint64_t budget = m_budget_at_last_sent +
                    (m_get_adjust_bw_cb() * (now - m_last_sent_time) / 1000 / 1000);
            return budget;
            return std::min(budget, maxBurstSize());
        }

        void Pacer::sentPacket(uint64_t sent_time, uint64_t size) {
            uint64_t budget_bytes = budget(sent_time);
            if (size > budget_bytes) {
                m_budget_at_last_sent = 0;
            } else {
                m_budget_at_last_sent = budget_bytes - size;
            }
            m_last_sent_time = sent_time;
        }

        uint64_t Pacer::timeUntilSend() {
            if (m_budget_at_last_sent >= m_max_datagram_size) {
                return 0;
            }
            uint64_t min_pacing_delay = MinPacingDelay;
            uint64_t ideal_delay = (uint64_t)ceil((m_max_datagram_size - m_budget_at_last_sent) * 1000 * 1000 / (m_get_adjust_bw_cb()));
            SYLAR_LOG_WARN(g_logger) << "m_last_sent_time: " << m_last_sent_time << ", ideal_delay: " << ideal_delay << " budget_at_last_sent: " << m_budget_at_last_sent;
            return m_last_sent_time + ideal_delay;
            return m_last_sent_time +
                    std::max(min_pacing_delay, ideal_delay);
        }
    }
}
