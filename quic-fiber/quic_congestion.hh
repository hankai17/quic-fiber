#ifndef __QUIC_CONGESTION_HH__
#define __QUIC_CONGESTION_HH__

#include <stdlib.h>
#include <float.h>
#include <cmath>
#include <map>
#include <deque>
#include <list>
#include <memory>
#include <functional>

#include "my_sylar/util.hh"
#include "quic-fiber/quic_type.hh"
#include "quic-fiber/quic_utils.hh"

namespace sylar {
    namespace quic {
        static constexpr uint64_t START_LOW_WIN = 16;
        static constexpr uint64_t START_MIN_SAMPLES = 8;
        static constexpr uint64_t START_DELAY_FACTOR_EXP = 3;
        static constexpr uint64_t START_DELAY_MIN_THRESHOULD = 4000;
        static constexpr uint64_t START_DELAY_MAX_THRESHOULD = 16000;

        class SlowStart {
        public:
            typedef std::shared_ptr<SlowStart> ptr;

            void startReceiveRound(QuicPacketNumber last_sent);
            bool isEndOfRound(QuicPacketNumber ack);
            bool shouldExitSlowStart(uint64_t latest_rtt, uint64_t min_rtt, uint64_t cong_win);
            void onPacketAcked(QuicPacketNumber pn);
            void restart();
            
            void onPacketSent(QuicPacketNumber pn) { m_last_sent_pn = pn; }
            bool isStarted() const { return m_started; }

        private:
            QuicPacketNumber m_end_pn = 0;
            QuicPacketNumber m_last_sent_pn = 0;
            bool m_started = false;
            uint64_t m_cur_min_rtt = 0;
            uint64_t m_rtt_sample_count = 0;
            bool m_start_found = false;
        };

        class Cubic {
        public:
            typedef std::shared_ptr<Cubic> ptr;
            static constexpr uint64_t CubeScale = 40;
            static constexpr uint64_t CubeCongestionWindowScale = 410;
            static constexpr uint64_t MaxDatagramSize = 1252;
            static constexpr uint64_t CubeFactor = 1 << CubeScale / CubeCongestionWindowScale / MaxDatagramSize;
            static constexpr uint64_t DefaultNumConnections = 1;
            static constexpr float Beta = 0.7;
            static constexpr float BetaLastMax = 0.85;

            Cubic() { m_clock = GetCurrentUs(); reset(); }
            void reset();
            float beta();
            float alpha();
            float betaLastMax();
            void onApplicationLimited();

            uint64_t congestionWinAfterPacketLoss(uint64_t cur_cong_win);
            uint64_t congestionWinAfterAck(uint64_t acked_bytes, uint64_t cur_cong_win,
                    uint64_t delay_min, uint64_t event_time);
            void setNumConnections(int n) { m_num_connections = n; }
        private:
            uint64_t m_clock;
            uint64_t m_num_connections = DefaultNumConnections;
            uint64_t m_epoch = 0;

            uint64_t m_last_max_cong_win = 0;
            uint64_t m_acked_bytes_count = 0;
            uint64_t m_estimated_tcp_cong_win = 0;
            uint64_t m_ori_point_cong_win = 0;
            uint64_t m_time_to_ori_point = 0;
            uint64_t m_last_target_cong_win = 0;
        };

        class SendAlgorithm {
        public:
            typedef std::shared_ptr<SendAlgorithm> ptr;
            virtual uint64_t timeUntilSend() = 0;
            virtual bool hasPacingBudget() = 0;
            virtual void onPacketAcked(QuicPacketNumber pn, uint64_t acked_bytes, uint64_t prior_inflight, uint64_t event_time) = 0;
            virtual void onPacketSent(uint64_t sent_time, uint64_t bytes_inflight, QuicPacketNumber pn, uint64_t bytes, bool is_retransmittable) = 0;
            virtual void onPacketLost(QuicPacketNumber pn, uint64_t lost_bytes, uint64_t prior_infligth) = 0;
            virtual void onRetransmissionTimeout(bool packet_retransmitted) = 0;
            virtual bool canSend(uint64_t bytes_inflight) = 0;
            virtual void maybeExitSlowStart() = 0;
            virtual void setMaxDatagramSize(uint64_t s) = 0;
        };

        class CubicSender : public std::enable_shared_from_this<CubicSender>,
                public SendAlgorithm {
        public:
            typedef std::shared_ptr<CubicSender> ptr;
            static constexpr uint64_t InitialMaxDatagramSize = 1252;
            static constexpr uint64_t MaxBurstPackets = 3;
            static constexpr float RenoBeta = 0.7;
            static constexpr uint64_t MaxCongestionWindowPackets = 10000;
            static constexpr uint64_t MinCongestionWindownPackets = 2;
            static constexpr uint64_t InitialCongestionWindow = 32;

            CubicSender(uint64_t clock, RTTStats::ptr stats, bool reno,
                    uint64_t initial_max_datagram_size,
                    uint64_t initial_cong_win = InitialCongestionWindow * InitialMaxDatagramSize,
                    uint64_t initial_max_cong_win = MaxCongestionWindowPackets * InitialMaxDatagramSize);

            void init();
            uint64_t getNow() { m_clock = GetCurrentUs(); return m_clock; }
            uint64_t bwEstimate();
            uint64_t timeUntilSend() { return m_pacer->timeUntilSend(); }
            bool hasPacingBudget() { return m_pacer->budget(getNow()) > m_max_datagram_size; }
            uint64_t maxCongestionWindow() { return m_max_datagram_size * MaxCongestionWindowPackets; }
            uint64_t minCongestionWindow() { return m_max_datagram_size * MinCongestionWindownPackets; }
            uint64_t getCongestionWindow() { return m_cong_win; }
            bool canSend(uint64_t bytes_inflight) { return bytes_inflight < getCongestionWindow(); }
            bool inRecovery();
            bool inSlowStart();

            bool isCwndLimited(uint64_t bytes_inflight);
            void maybeIncreaseCwnd(QuicPacketNumber pn, uint64_t acked_bytes, uint64_t prior_inflight, uint64_t event_time);

            void maybeExitSlowStart();
            void onPacketAcked(QuicPacketNumber pn, uint64_t acked_bytes, uint64_t prior_inflight, uint64_t event_time);
            void onPacketSent(uint64_t sent_time, uint64_t bytes_inflight, QuicPacketNumber pn, uint64_t bytes, bool is_retransmittable);
            void onPacketLost(QuicPacketNumber pn, uint64_t lost_bytes, uint64_t prior_inflight);
            void onRetransmissionTimeout(bool packet_retransmitted);
            void setMaxDatagramSize(uint64_t s);

        private:
            uint64_t m_clock;
            RTTStats::ptr m_rtt = nullptr;
            bool m_reno = false;

            SlowStart m_slow_start;
            Cubic::ptr m_cubic = nullptr;
            Pacer::ptr m_pacer = nullptr;

            uint64_t m_largest_sent_pn = ~0ull;
            uint64_t m_largest_acked_pn = ~0ull;
            uint64_t m_largest_sent_at_last_cutback = ~0ull;
            bool m_last_cutback_exited_slow_start = false;
            uint64_t m_cong_win = InitialCongestionWindow * InitialMaxDatagramSize;
            uint64_t m_slow_start_threshold = ~0ull;
            uint64_t m_num_acked_packets = 0;
            uint64_t m_max_datagram_size;
            uint64_t m_initial_cong_win;
            uint64_t m_initial_max_cong_win;
        };
    }
}

#endif

