#ifndef __BBR_UTILS_HH__
#define __BBR_UTILS_HH__

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
        struct sample {
            sample(uint64_t bw = 0, uint64_t time = 0)
                : bandwidth(bw), time(time) {}
            uint64_t bandwidth = 0;
            uint64_t time = 0;
        };

        class WindowedFilter {
        public:
            typedef std::shared_ptr<WindowedFilter> ptr;
            WindowedFilter(uint64_t win_len);
            void update(uint64_t new_bw, uint64_t new_time);
            void reset(uint64_t new_bw, uint64_t new_time);
            uint64_t getBest() { return m_estimates[0].bandwidth; }
            uint64_t getSecondBest() { return m_estimates[1].bandwidth; }
            uint64_t getThirdBest() { return m_estimates[2].bandwidth; }
        public:
            uint64_t m_win_length = 0;
            sample m_estimates[3];
            std::function<bool(uint64_t, uint64_t)> m_compare_cb = nullptr;
        };

        struct BandwidthSample {
            BandwidthSample() {}
            BandwidthSample(uint64_t bandwith, uint64_t rtt, bool is_limited)
                : bandwith(bandwith), rtt(rtt), isApplimited(is_limited) {}
            // The bandwidth at that particular sample. Zero if no valid bandwidth sample
            // is available.
            uint64_t bandwith = 0;
            // The RTT measurement at this particular sample.  Zero if no RTT sample is
            // available.  Does not correct for delayed ack time.
            uint64_t rtt = 0;
            // Indicates whether the sample might be artificially low because the sender
            // did not have enough data to send in order to saturate the link.
            bool isApplimited = false;
        };

        // connectionStateOnSentPacket represents the information about a sent packet
        // and the state of the connection at the moment the packet was sent,
        // specifically the information about the most recently acknowledged packet at
        // that moment.
        class BandwidthSampler;
        struct ConnectionStateOnSentPacket {
            typedef std::shared_ptr<ConnectionStateOnSentPacket> ptr;
            // Snapshot constructor. Records the current state of the bandwidth sampler.
            ConnectionStateOnSentPacket(uint64_t sent_time, uint64_t bytes, BandwidthSampler *b);
            // Time at which the packet is sent.
            uint64_t sentTime = 0;
            // Size of the packet
            uint64_t size = 0;
            // The value of |total_bytes_sent_| at the time the packet was sent.
            // Includes the packet itself.
            uint64_t totalBytesSent = 0;
            // The value of |total_bytes_sent_at_last_acked_packet_| at the time the
            // packet was sent.
            uint64_t totalBytesSentAtLastAckedPacket = 0;
            // The value of |last_acked_packet_sent_time_| at the time the packet was sent
            uint64_t lastAckedPacketSentTime = 0;
            // The value of |last_acked_packet_ack_time_| at the time the packet was sent
            uint64_t lastAckedPacketAckTime = 0;
            // The value of |total_bytes_acked_| at the time the packet was sent.
            uint64_t totalBytesAckedAtTheLastAckedPacket = 0;
            // The value of |is_app_limited_| at the time the packet was sent.
            bool isAppLimited = false;
        };

        class BandwidthSampler {
        public:
            typedef std::shared_ptr<BandwidthSampler> ptr;
            BandwidthSampler() {}

            void onPacketSent(uint64_t sent_time, uint64_t pn, uint64_t bytes, uint64_t bytes_inflight, bool has_retransmittable_data);
            BandwidthSample onPacketAcked(uint64_t ack_time, uint64_t pn);
            void onPacketLost(uint64_t pn);
            void onApplimited();
            void removeObsoletePackets(uint64_t least_unacked);

        //private:
        public:
            // The total number of congestion controlled bytes sent during the connection.
            uint64_t m_total_bytes_sent = 0;
            // The total number of congestion controlled bytes which were acknowledged.
            uint64_t m_total_bytes_acked = 0;

            // The value of |total_bytes_sent_| at the time the last acknowledged packet
            // was sent. Valid only when |last_acked_packet_sent_time_| is valid.
            uint64_t m_total_bytes_sent_at_last_acked_packet = 0;

            // The time at which the last acknowledged packet was sent. Set to
            // QuicTime::Zero() if no valid timestamp is available.
            uint64_t m_last_acked_packet_sent_time = 0;

            // The time at which the most recent packet was acknowledged.
            uint64_t m_last_acked_packet_ack_time = 0;
            // The most recently sent packet.
            uint64_t m_last_sent_packet = 0;
            // Indicates whether the bandwidth sampler is currently in an app-limited phase.
            bool m_is_app_limited = false;

            // The packet that will be acknowledged after this one will cause the sampler
            // to exit the app-limited phase.
            uint64_t m_end_of_app_limited_phase = 0;
            std::map<uint64_t, ConnectionStateOnSentPacket::ptr> m_connection_state_map;
        };

    }
}

#endif

