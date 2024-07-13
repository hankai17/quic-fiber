#ifndef __QUIC_UTILS_HH__
#define __QUIC_UTILS_HH__

#include <stdlib.h>
#include <float.h>
#include <cmath>
#include <map>
#include <deque>
#include <list>
#include <memory>
#include <functional>

#include "my_sylar/util.hh"

namespace sylar {
    namespace quic {
        static constexpr float RTT_ALPHA = 0.125;
        static constexpr float ONE_MINUS_ALPHA = 1 - RTT_ALPHA;
        static constexpr float RTT_BETA = 0.25;
        static constexpr float ONE_MINUS_BETA = 1 - RTT_BETA;
        static constexpr uint64_t DEFAULT_INITIAL_RTT = 100 * 1000; // 100ms

        struct RTTStats {
            typedef std::shared_ptr<RTTStats> ptr;

            uint64_t minRTT() const { return m_min_rtt; }
            uint64_t latestRTT() const { return m_latest_rtt; }
            uint64_t smoothedRTT() const { return m_smoothed_rtt; }
            uint64_t meanDeviation() const { return m_mean_deviation; }
            uint64_t maxAckDelay() const { return m_max_ack_delay; }

            uint64_t PTO(bool include_max_ack_delay);
            void updateRTT(uint64_t send_delta, uint64_t ack_delay, uint64_t now);
            void setMaxAckDelay(uint64_t mad) { m_max_ack_delay = mad; }
            void setInitialRTT(uint64_t t);
            void onConnectionMigration();
            void expireSmoothedMetrics();
            
            bool m_has_measurement = false;
            uint64_t m_min_rtt = 0;
            uint64_t m_latest_rtt = 0;
            uint64_t m_smoothed_rtt = 0;
            uint64_t m_mean_deviation = 0;
            uint64_t m_max_ack_delay = 25 * 1000;
        };

        static constexpr uint64_t MinPacingDelay = 1000;
        static constexpr uint64_t MaxBurstSizePackets = 10;
        static constexpr uint64_t InitialMaxDatagramSize = 1252;
        static constexpr uint64_t InitialCongestionWindow = 32;
        static constexpr uint64_t MaxCongestionWindowPackets = 10000;

        class Pacer {
        public:
            typedef std::shared_ptr<Pacer> ptr;
            Pacer(std::function<uint64_t()> get_bw);
            uint64_t maxBurstSize();
            uint64_t budget(uint64_t time);
            void sentPacket(uint64_t sent_time, uint64_t size);

            uint64_t timeUntilSend();
            void setMaxDatagramSize(uint64_t val) { m_max_datagram_size = val; }
        private:
            uint64_t m_budget_at_last_sent = 0;
            uint64_t m_max_datagram_size = 1252;
            uint64_t m_last_sent_time = 0;
            std::function<uint64_t()> m_get_adjust_bw_cb;
        };
    }
}

#endif

