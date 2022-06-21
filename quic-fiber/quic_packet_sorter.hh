#ifndef __QUIC_PACKET_SORTER_HH__
#define __QUIC_PACKET_SORTER_HH__

#include <map>
#include <unordered_map>
#include <vector>
#include <memory>
#include <functional>

#include "quic-fiber/quic_frame.hh"
#include "quic-fiber/quic_packet.hh"
#include "quic-fiber/quic_utils.hh"
#include "quic-fiber/quic_congestion.hh"

namespace sylar {
    namespace quic {
        static constexpr uint32_t MAX_PACKET_NUMBER = 0X7FFFFFFF;
        static constexpr uint32_t MAX_NUMBER_ACK_RANGES = 64;

        class QuicPacket;
        struct PacketInterval {
        public:
            typedef std::shared_ptr<PacketInterval> ptr;
            PacketInterval(QuicPacketNumber start, QuicPacketNumber end) : m_start(start), m_end(end) {}
            void set_start(QuicPacketNumber start) { m_start = start; }
            void set_end(QuicPacketNumber end) { m_end = end; }
            QuicPacketNumber start() const { return m_start; }
            QuicPacketNumber end() const { return m_end; }

            QuicPacketNumber m_start = 0;
            QuicPacketNumber m_end = MAX_PACKET_NUMBER;
        };

        class ReceivedPacketHistory {
        public:
            typedef std::shared_ptr<ReceivedPacketHistory> ptr;
            bool receivedPacket(QuicPacketNumber pn);
            bool addToRanges(QuicPacketNumber pn);
            void maybeDeleteOldRanges();
            void deleteBelow(QuicPacketNumber pn);
            std::vector<AckRange::ptr> getAckRanges();
            AckRange::ptr getHighestAckRange();
            bool isPotentiallyDuplicate(QuicPacketNumber pn);
            std::string toString();
        private:
            std::list<PacketInterval::ptr> m_ranges;
            uint64_t m_deleted_below;
        };
        
        class ReceivedPacketTracker {
        public:
            typedef std::shared_ptr<ReceivedPacketTracker> ptr;
            typedef Mutex MutexType;
            static constexpr uint64_t MAX_ACK_DELAY = 25 * 1000;

            ReceivedPacketTracker();
            uint64_t largestObservedReceivedTime() const { return m_largest_observed_received_time;}
            int ackElicitingPacketsReceivedSinceLastAck() const { return m_ack_eliciting_packets_received_since_last_ack; }
            uint64_t ackAlarm() const { return m_ack_alarm; }
    
            void ignoreBelow(QuicPacketNumber pn);
            bool isMissing(QuicPacketNumber pn);
            bool hasNewMissingPackets();
            void maybeQueueAck(QuicPacketNumber pn, uint64_t recv_time, bool was_missing);
            void receivedPacket(QuicPacketNumber pn, uint64_t recv_time, bool should_instigate_ack);
            QuicAckFrame::ptr getAckFrame(bool only_if_queued);

        //private:
            MutexType m_mutex;
            ReceivedPacketHistory::ptr m_packet_history;
            QuicPacketNumber m_largest_observed = 0;
            QuicPacketNumber m_ignore_below = 0;
            uint64_t m_largest_observed_received_time = 0;
            bool m_has_new_ack = false;
            bool m_ack_queued = false;
            int m_ack_eliciting_packets_received_since_last_ack = 0;
            uint64_t m_ack_alarm = 0;
            QuicAckFrame::ptr m_last_ack = nullptr;
            QuicVersion m_version;
        };

        class SentPacketHistory {
        public:
            typedef std::shared_ptr<SentPacketHistory> ptr;
            typedef Mutex MutexType;

            SentPacketHistory(RTTStats::ptr rtt_stats);
            size_t len() const { return m_packet_map.size(); }
            bool hasOutstandingPackets() { return (firstOutstanding() != nullptr); }
            bool hasPacket(QuicPacketNumber pn) { return m_packet_map.count(pn) > 0; }
            QuicPacket::ptr getPacket(QuicPacketNumber pn) { if (!hasPacket(pn)) return nullptr; return *(m_packet_map[pn]); }
            void sentPacket(QuicPacket::ptr packet, bool is_ack_eliciting, uint64_t now);
            void Iterate(std::function<bool(QuicPacket::ptr)> cb);
            QuicPacket::ptr firstOutstanding();
            bool remove(QuicPacketNumber pn);
            void deleteOldPackets(uint64_t now);
        private:
            MutexType m_mutex;
            RTTStats::ptr m_rtt_stats = nullptr;
            std::list<QuicPacket::ptr> m_packet_list = {};
            std::unordered_map<QuicPacketNumber, std::list<QuicPacket::ptr>::iterator> m_packet_map;
            QuicPacketNumber m_highest_sent = 0;
        };

        class SentPacketHandler {
        public:
            typedef std::shared_ptr<SentPacketHandler> ptr;
            static constexpr int amplicationFactor = 3;
            static constexpr float timeThreshold = 9.0 / 8;
            static constexpr int packetThreshold = 3;
            struct PacketNumberSpace {
                SentPacketHistory::ptr m_history = nullptr;
                uint64_t m_loss_time = 0;
                uint64_t m_last_ack_eliciting_packet_time = 0;
                QuicPacketNumber m_largest_acked = 0;
                QuicPacketNumber m_largest_sent = ~0ull;
            };

            SentPacketHandler(const RTTStats::ptr &rtt);
            const PacketNumberSpace &dataPackets() const { return m_data_packets; }
            uint64_t bytesReceived() const { return m_bytes_received; }
            uint64_t bytesSent() const { return m_bytes_sent; }
            uint64_t bytesInflight() const { return m_bytes_inflight; }
            const RTTStats::ptr getRTTStats() const { return m_rtt_stats; }

            void removeFromBytesInflight(QuicPacket::ptr packet);
            void dropPackets();
            void receivedBytes(uint64_t n) { m_bytes_received += n; }
            int packetsInflight() { return m_data_packets.m_history->len(); }
            uint64_t getLossTimeAndSpace();
            QuicPacketNumber getLowestPacketNotConfirmedAcked() const { return m_lowest_not_confirmed_acked; }

            bool hasOutstandingPackets();
            bool isAmplificationLimited();
            void setLossDetectionTimer(int phase);
            bool sentPacketImpl(QuicPacket::ptr packet);
            void sentPacket(QuicPacket::ptr packet, uint64_t now);

            bool queueProbePacket();
            void queueFramesForRetransmission(QuicPacket::ptr packet);
            bool detectLostPackets(uint64_t now);
            std::vector<QuicPacket::ptr> detectAndRemoveAckedPackets(QuicAckFrame::ptr frame);
            bool receivedAck(QuicAckFrame::ptr frame, uint64_t recv_time);

            bool onLossDetectionTimeout();
            uint64_t getLossDetectionTimeout() const { return m_alarm; }
            PacketSendMode sendMode();
            bool hasPacingBudget() { return m_congestion->hasPacingBudget(); }
            uint64_t timeUntilSend() const { return m_congestion->timeUntilSend(); }
            void setMaxDatagramSize(uint64_t s) { m_congestion->setMaxDatagramSize(s); }

        private:
            uint64_t m_send_interval = 0;
            PacketNumberSpace m_data_packets;
            uint64_t m_bytes_received = 0;
            uint64_t m_bytes_sent = 0;
            QuicPacketNumber m_lowest_not_confirmed_acked = 0;
            std::vector<QuicPacket::ptr> m_acked_packets = {};
            uint64_t m_bytes_inflight = 0;
            SendAlgorithm::ptr m_congestion = nullptr;
            RTTStats::ptr m_rtt_stats;
            uint32_t m_PTO_count = 0;
            // pto mode
            int m_num_probes_to_send = 0;
            uint64_t m_alarm = 0;
            QuicRole m_role;
        };

    }
}

#endif

