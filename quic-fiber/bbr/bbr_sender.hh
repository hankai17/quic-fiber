#ifndef __BBR_SENDER_HH__
#define __BBR_SENDER_HH__

#include "my_sylar/quic/quic_utils.hh"
#include "my_sylar/quic/quic_congestion.hh"
#include "my_sylar/quic/quic_packet.hh"
#include "my_sylar/quic/bbr/bbr_utils.hh"

namespace sylar {
    namespace quic {

        enum class Mode : u_int8_t {
            Startup = 1,
            Drain,
            ProbeBW,
            ProbeRTT
        };

        enum class RecoveryState : u_int8_t {
            NotInRecovery = 1,
            Conservation,
            Growth,
        };

        class BbrSender : public std::enable_shared_from_this<BbrSender>,
                            public SendAlgorithm {
        public:
            typedef std::shared_ptr<BbrSender> ptr;
            static constexpr uint64_t MaxSegmentSize = 1400;
            static constexpr uint64_t MinimumCongWin = 4 * MaxSegmentSize;
            static constexpr float HighGain = 2.885;
            static constexpr float DrainGain = 1 / HighGain;
            static constexpr float CongWinGain = 2.0;
            static constexpr uint64_t GainCycleLength = 8;
            static constexpr uint64_t RoundTripCount = GainCycleLength + 2;
            static constexpr uint64_t MinRttExpiry = 10 * 1000 * 1000; // 10s
            static constexpr uint64_t ProbeRttTime = 200 * 1000;
            static constexpr float StartupGrowthTarget = 1.25;
            static constexpr uint64_t RoundTripWithoutGrowthBeforeExitingStartup = 3;

            BbrSender(RTTStats::ptr rtt, uint64_t initial_max_datagram_size,
                    uint64_t initial_cong_win = InitialCongestionWindow * InitialMaxDatagramSize,
                    uint64_t initial_max_cong_win = MaxCongestionWindowPackets * InitialMaxDatagramSize)
                    : m_rtt(rtt),
                      m_max_bw(RoundTripCount),
                      m_initial_cong_win(initial_cong_win),
                      m_max_cong_win(initial_max_cong_win) {
            }
            void setNumEmulatedConnections(uint64_t n) {}
            void onConnectionMigration() {}
            // uint64_t RetransmissionDelay() { return 1000 * 1000; }
            void setSlowStartLargestReduction(bool enabled) {}
            bool inSlowStart() { return m_mode == Mode::Startup; }
            bool inRecovery() { return m_recovery_state != RecoveryState::NotInRecovery; }
            uint64_t bwEstimate() { return m_max_bw.getBest(); }

            uint64_t timeUntilSend() override { return 0; }
            bool hasPacingBudget() override { return true; } // TODO
            void onPacketAcked(QuicPacketNumber pn, uint64_t acked_bytes, uint64_t prior_inflight, uint64_t event_time) override {}
            void onPacketSent(uint64_t sent_time, uint64_t bytes_inflight, QuicPacketNumber pn, uint64_t bytes, bool is_retransmittable) override;
            void onPacketLost(QuicPacketNumber pn, uint64_t lost_bytes, uint64_t prior_infligth) override {}
            void onRetransmissionTimeout(bool packet_retransmitted) override {}
            bool canSend(uint64_t bytes_inflight) override { return bytes_inflight < getCongestionWin(); }
            void maybeExitSlowStart() override {}
            void setMaxDatagramSize(uint64_t s) override {}

            uint64_t getMinRtt();
            uint64_t getCongestionWin();
            uint64_t timeUntilSend(uint64_t now, uint64_t bytes_inflight);
            uint64_t pacingRate(uint64_t bytes_inflight);
            void discardLostPackets(const std::vector<QuicPacket::ptr> &lost_packets);
            bool updateRoundTripCounter(uint64_t last_acked_pn);
            bool updateBwAndMinRtt(uint64_t now, const std::vector<QuicPacket::ptr> &acked_packets);
            void updateRecoveryState(uint64_t last_acked_pn, bool has_losses, bool is_round_start);
            uint64_t getTargetCongWin(float gain);
            void checkIfFullBwReached();
            void maybeExitStartupOrDrain(uint64_t now, uint64_t bytes_inflight);
            void enterStartupMode();
            void enterProbeBwMode(uint64_t now);
            void maybeEnterOrExitProbeRtt(uint64_t now, bool is_round_start, bool min_rtt_expired, uint64_t bytes_inflight);
            void updateGainCyclePhase(uint64_t now, uint64_t prior_inflight, bool has_losses);
            void calcPacingRate();
            void calcRecoveryWin(uint64_t bytes_acked, uint64_t bytes_inflight);
            void calcCongWin(uint64_t bytes_acked);
            void onCongEvent(bool rtt_updated, uint64_t prior_inflight, uint64_t bytes_inflight, uint64_t event_time,
                    std::vector<QuicPacket::ptr> acked_packets, std::vector<QuicPacket::ptr> lost_packets, uint64_t least_unacked);
            void onApplicationLimited(uint64_t bytes_inflight);
        private:
            RTTStats::ptr m_rtt = nullptr;
            Mode m_mode = Mode::Startup;
            BandwidthSampler m_sampler;
            uint64_t m_round_trip_count = 0;
            uint64_t m_last_sent_packet = 0;
            uint64_t m_current_round_trip_end = 0;
            WindowedFilter m_max_bw;
            uint64_t m_min_rtt = 0;
            uint64_t m_min_rtt_ts = 0;
            uint64_t m_cong_win = InitialCongestionWindow * InitialMaxDatagramSize;
            uint64_t m_initial_cong_win;
            uint64_t m_max_cong_win;
            uint64_t m_pacing_rate_value = 0;

            float m_pacing_gain = 1.0;
            float m_cong_win_gain = 1.0;
            uint64_t m_cycle_cur_offset = 0;
            uint64_t m_last_cycle_start = 0;
            bool m_is_at_full_bw = false;
            uint64_t m_rounds_without_bw_gain = 0;
            uint64_t m_bw_at_last_round = 0;
            bool m_exiting_quiescense = false;
            uint64_t m_exit_probe_rtt_at = 0;
            bool m_probe_rtt_round_passed = false;
            bool m_last_sample_is_app_limited = false;
            RecoveryState m_recovery_state = RecoveryState::NotInRecovery;
            uint64_t m_end_recovery_at = 0;
            uint64_t m_recovery_win = 0;
        };

    }
}

#endif
