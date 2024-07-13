#include "bbr_sender.hh"

#include "my_sylar/log.hh"
#include <math.h>
#include <iostream>
#include <random>

namespace sylar {
    namespace quic {
        static sylar::Logger::ptr g_logger = SYLAR_LOG_NAME("system");
        static float PacingGain[] = {1.25, 0.75, 1, 1, 1, 1, 1, 1};

        static uint64_t BandwidthFromDelta(uint64_t bytes, uint64_t delta) {
            return bytes * 1 / delta * 8;
        }

        uint64_t BbrSender::getMinRtt() {
            if (m_min_rtt) {
                return m_min_rtt;
            }
            //return m_rtt->minRTT();
            return 100 * 1000;
        }

        uint64_t BbrSender::getCongestionWin() {
            if (m_mode == Mode::ProbeRTT) {
                SYLAR_LOG_WARN(g_logger) << "trace now: " << GetCurrentUs()
                                         << " BbrSender getCongestionWin1 " << (uint64_t)MinimumCongWin;
                return (uint64_t)MinimumCongWin;
            }
            if (inRecovery()) {
                uint64_t res = std::min(m_cong_win, m_recovery_win);
                SYLAR_LOG_WARN(g_logger) << "trace now: " << GetCurrentUs()
                                         << " BbrSender getCongestionWin2 " << (uint64_t)MinimumCongWin;
                return res;
            }
            SYLAR_LOG_WARN(g_logger) << "trace now: " << GetCurrentUs()
                                     << " BbrSender getCongestionWin3 " << m_cong_win;
            return m_cong_win;
        }

        uint64_t BbrSender::timeUntilSend(uint64_t now, uint64_t bytes_inflight) {
            if (bytes_inflight < getCongestionWin()) {
                return 1;
            }
            return ~0ull;
        }

        uint64_t BbrSender::pacingRate(uint64_t bytes_inflight) {
            if (m_pacing_rate_value == 0) {
                return HighGain * BandwidthFromDelta(m_initial_cong_win, getMinRtt());
            }
            return m_pacing_rate_value;
        }

        void BbrSender::onPacketSent(uint64_t sent_time, uint64_t bytes_inflight, uint64_t pn,
                uint64_t bytes, bool is_retransmittable) {
            m_last_sent_packet = pn;                        // 1
            if (bytes_inflight == 0 &&
                    m_sampler.m_is_app_limited) {
                m_exiting_quiescense = true;
            }
            m_sampler.onPacketSent(sent_time, pn, bytes, bytes_inflight, is_retransmittable);
            //return is_retransmittable;
        }

        void BbrSender::discardLostPackets(const std::vector<QuicPacket::ptr> &lost_packets) {
            for (const auto &packet : lost_packets) {
                m_sampler.onPacketLost(packet->packetNumber());
            }
        }

        bool BbrSender::updateRoundTripCounter(uint64_t last_acked_pn) {
            if (last_acked_pn > m_current_round_trip_end) {
                m_round_trip_count++;
                m_current_round_trip_end = m_last_sent_packet;
                return true;
            }
            return false;
        }

        bool BbrSender::updateBwAndMinRtt(uint64_t now, const std::vector<QuicPacket::ptr> &acked_packets) {
            uint64_t sample_min_rtt = ~0ull;
            for (const auto& packet : acked_packets) {
                auto bw_sample = m_sampler.onPacketAcked(now, packet->packetNumber());
                m_last_sample_is_app_limited = bw_sample.isApplimited;
                if (bw_sample.rtt) {
                    sample_min_rtt = std::min(sample_min_rtt, bw_sample.rtt);
                }
                if (!bw_sample.isApplimited ||
                        bw_sample.bandwith > bwEstimate()) {
                    m_max_bw.update(bw_sample.bandwith, m_round_trip_count);
                }
            }
            if (sample_min_rtt == ~0ull) {
                return false;
            }
            bool min_rtt_expired = m_min_rtt != 0 && now > (m_min_rtt_ts + MinRttExpiry);
            if (min_rtt_expired ||
                    sample_min_rtt < m_min_rtt ||
                    m_min_rtt == 0) {
                m_min_rtt = sample_min_rtt;
                m_min_rtt_ts = now;
            }
            return min_rtt_expired;
        }

        void BbrSender::updateRecoveryState(uint64_t last_acked_pn, bool has_losses, 
                bool is_round_start) {
            if (has_losses) {
                m_end_recovery_at = m_last_sent_packet;
            }
            switch (m_recovery_state) {
                case RecoveryState::NotInRecovery : {
                    if (has_losses) {
                        m_recovery_state = RecoveryState::Conservation;
                        m_current_round_trip_end = m_last_sent_packet;
                    }
                    break;
                }
                case RecoveryState::Conservation : {
                    if (is_round_start) {
                        m_recovery_state = RecoveryState::Growth;
                    }
                    break;
                }
                case RecoveryState::Growth : {
                    if (!has_losses &&
                            last_acked_pn > m_end_recovery_at) {
                        m_recovery_state = RecoveryState::NotInRecovery;
                    }
                    break;
                }
                default: {
                    break;
                }
            }
            return;
        }

        uint64_t BbrSender::getTargetCongWin(float gain) {
            float bdp = getMinRtt() / 1000 / 1000 * float(bwEstimate() / 1);
            uint64_t cwnd = (uint64_t)(gain * float(bdp));
            if (cwnd == 0) {
                cwnd = (uint64_t)(gain * float(m_initial_cong_win));
            }
            return std::max(cwnd, (uint64_t)MinimumCongWin);
        }

        void BbrSender::updateGainCyclePhase(uint64_t now, uint64_t prior_inflight, bool has_losses) {
            bool should_adv_gain_cycling = now - m_last_cycle_start > getMinRtt();
            if (m_pacing_gain > 1 && !has_losses &&
                    prior_inflight < getTargetCongWin(m_pacing_gain)) {
                should_adv_gain_cycling = false;
            }
            if (m_pacing_gain < 1 && prior_inflight < getTargetCongWin(1)) {
                should_adv_gain_cycling = true;
            }
            if (should_adv_gain_cycling) {
                m_cycle_cur_offset = (m_cycle_cur_offset + 1) % GainCycleLength;
                m_last_cycle_start = now;
                m_pacing_gain = PacingGain[m_cycle_cur_offset];
            }
        }

        void BbrSender::checkIfFullBwReached() {
            if (m_last_sample_is_app_limited) {
                return;
            }
            uint64_t target = (uint64_t)(float(m_bw_at_last_round) * StartupGrowthTarget);
            if (bwEstimate() >= target) {
                m_bw_at_last_round = bwEstimate();
                m_rounds_without_bw_gain = 0;
                return;
            }
            m_rounds_without_bw_gain++;
            if (m_rounds_without_bw_gain >= RoundTripWithoutGrowthBeforeExitingStartup) {
                m_is_at_full_bw = true;
            }
        }

        void BbrSender::enterStartupMode() {
            m_mode = Mode::Startup;
            m_pacing_gain = HighGain;
            m_cong_win_gain = HighGain;
        }

        void BbrSender::enterProbeBwMode(uint64_t now) {
            m_mode = Mode::ProbeBW;
            m_cong_win_gain = CongWinGain;

            m_cycle_cur_offset = random() % (GainCycleLength - 1);
            if (m_cycle_cur_offset >= 1) {
                m_cycle_cur_offset++;
            }
            m_last_cycle_start = now;
            m_pacing_gain = PacingGain[m_cycle_cur_offset];
        }

        void BbrSender::maybeExitStartupOrDrain(uint64_t now, uint64_t bytes_inflight) {
            if (m_mode == Mode::Startup &&
                    m_is_at_full_bw) {
                m_mode = Mode::Drain;
                m_pacing_gain = DrainGain;
                m_cong_win = HighGain;
            }
            if (m_mode == Mode::Drain &&
                    bytes_inflight <= getTargetCongWin(1)) {
                enterProbeBwMode(now);
            }
        }

        void BbrSender::maybeEnterOrExitProbeRtt(uint64_t now, bool is_round_start, bool min_rtt_expired, uint64_t bytes_inflight) {
            if (min_rtt_expired &&
                    !m_exiting_quiescense &&
                    m_mode != Mode::ProbeRTT) {
                m_mode = Mode::ProbeRTT;
                m_pacing_gain = 1;
                m_exit_probe_rtt_at = 0;
            }
            if (m_mode == Mode::ProbeRTT) {
                m_sampler.onApplimited();
                if (m_exit_probe_rtt_at == 0) {
                    if (bytes_inflight < (uint64_t)MinimumCongWin + 1252) {
                        m_exit_probe_rtt_at = now + ProbeRttTime;
                        m_probe_rtt_round_passed = false;
                    }
                } else {
                    if (is_round_start) {
                        m_probe_rtt_round_passed = true;
                    }
                    if (now >= m_exit_probe_rtt_at &&
                            m_probe_rtt_round_passed) {
                        m_min_rtt_ts = now;
                        if (!m_is_at_full_bw) {
                            enterStartupMode();
                        } else {
                            enterProbeBwMode(now);
                        }
                    }
                }
            }
            return;
        }

        void BbrSender::calcPacingRate() {
            if (bwEstimate() == 0) {
                return;
            }
            m_pacing_rate_value = (uint64_t)(m_pacing_gain * float(bwEstimate()));
        }

        void BbrSender::calcRecoveryWin(uint64_t bytes_acked, uint64_t bytes_inflight) {
            switch (m_recovery_state) {
                case RecoveryState::Conservation : {
                    m_recovery_win = bytes_inflight + bytes_acked;
                    break;
                }
                case RecoveryState::Growth : {
                    m_recovery_win = bytes_inflight + 2 * bytes_acked;
                    break;
                }
                default: {
                    break;
                }
            }
            m_recovery_win = std::max(m_recovery_win, (uint64_t)MinimumCongWin);
        }

        void BbrSender::calcCongWin(uint64_t bytes_acked) {
            if (m_mode == Mode::ProbeRTT) {
                return;
            }
            uint64_t target_win = getTargetCongWin(m_cong_win_gain);
            if (m_is_at_full_bw) {
                m_cong_win = std::min(target_win, m_cong_win + bytes_acked);
            } else if (m_cong_win < target_win ||
                    m_sampler.m_total_bytes_acked < m_initial_cong_win) {
                m_cong_win += bytes_acked;
            }
            m_cong_win = std::max(m_cong_win, (uint64_t)MinimumCongWin);
            m_cong_win = std::min(m_cong_win, m_max_cong_win);
        }

        void BbrSender::onCongEvent(bool rtt_updated, uint64_t prior_inflight, uint64_t bytes_inflight, uint64_t event_time,
                         std::vector<QuicPacket::ptr> acked_packets, std::vector<QuicPacket::ptr> lost_packets, uint64_t least_unacked) {
            uint64_t total_bytes_acked_before = m_sampler.m_total_bytes_acked;
            bool is_round_start = false;
            bool min_rtt_expired = false;

            discardLostPackets(lost_packets);
            bool has_lost_packets = lost_packets.size() > 0;
            if (acked_packets.size() > 0) {
                uint64_t last_acked_pn = acked_packets[0]->packetNumber();
                is_round_start = updateRoundTripCounter(m_last_sent_packet);
                min_rtt_expired = updateBwAndMinRtt(event_time, acked_packets);
                updateRecoveryState(last_acked_pn, has_lost_packets, is_round_start);
            }
            if (m_mode == Mode::ProbeBW) {
                updateGainCyclePhase(event_time, prior_inflight, has_lost_packets);
            }
            if (is_round_start && !m_is_at_full_bw) {
                checkIfFullBwReached();
            }
            maybeExitStartupOrDrain(event_time, bytes_inflight);
            maybeEnterOrExitProbeRtt(event_time, is_round_start, min_rtt_expired, bytes_inflight);
            uint64_t bytes_acked = m_sampler.m_total_bytes_acked - total_bytes_acked_before;
            calcPacingRate();
            calcCongWin(bytes_acked);
            calcRecoveryWin(bytes_acked, bytes_inflight);
            m_sampler.removeObsoletePackets(least_unacked);
        }

        void BbrSender::onApplicationLimited(uint64_t bytes_inflight) {
            if (bytes_inflight >= getCongestionWin()) {
                return;
            }
            m_sampler.onApplimited();
        }

    }
}

