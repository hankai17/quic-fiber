#include "bbr_utils.hh"

#include "my_sylar/log.hh"
#include <math.h>
#include <iostream>

namespace sylar {
    namespace quic {
        static sylar::Logger::ptr g_logger = SYLAR_LOG_NAME("system");

        WindowedFilter::WindowedFilter(uint64_t win_len)
            : m_win_length(win_len) {
            m_estimates[0] = sample();
            m_estimates[1] = sample();
            m_estimates[2] = sample();
            m_compare_cb = [](uint64_t a, uint64_t b)-> bool {
                return a >= b;
            };
        }

        // Update updates best estimates with |sample|, and expires and updates best
        // estimates as necessary.
        void WindowedFilter::update(uint64_t new_bw, uint64_t new_time) {
            // Reset all estimates if they have not yet been initialized, if new sample
            // is a new best, or if the newest recorded estimate is too old.
            if (m_estimates[0].bandwidth == 0 ||
                    m_compare_cb(new_bw, m_estimates[0].bandwidth) ||
                    new_time - m_estimates[2].time > m_win_length) {
                reset(new_bw, new_time);
                return;
            }
            sample new_sample(new_bw, new_time);
            if (m_compare_cb(new_bw, m_estimates[1].bandwidth)) {
                m_estimates[1] = new_sample;
                m_estimates[2] = m_estimates[1];
            } else if (m_compare_cb(new_bw, m_estimates[2].bandwidth)) {
                m_estimates[2] = new_sample;
            }

            // Expire and update estimates as necessary.
            if (new_time - m_estimates[0].time > m_win_length) {
                // The best estimate hasn't been updated for an entire window, so promote
                // second and third best estimates.
                m_estimates[0] = m_estimates[1];
                m_estimates[1] = m_estimates[2];
                m_estimates[2] = new_sample;
                // Need to iterate one more time. Check if the new best estimate is
                // outside the window as well, since it may also have been recorded a
                // long time ago. Don't need to iterate once more since we cover that
                // case at the beginning of the method.
                if (new_time - m_estimates[0].time > m_win_length) {
                    m_estimates[0] = m_estimates[1];
                    m_estimates[1] = m_estimates[2];
                }
                return;
            }
            if (m_estimates[1].bandwidth == m_estimates[0].bandwidth &&
                    new_time - m_estimates[1].time > (m_win_length >> 2)) {
                // A quarter of the window has passed without a better sample, so the
                // second-best estimate is taken from the second quarter of the window.
                m_estimates[2] = new_sample;
                m_estimates[1] = new_sample;
                return;
            }
            if (m_estimates[2].bandwidth == m_estimates[1].bandwidth &&
                    new_time - m_estimates[2].time > (m_win_length >> 1)) {
                // We've passed a half of the window without a better estimate, so take
                // a third-best estimate from the second half of the window.
                m_estimates[2] = new_sample;
            }
            return;
        }

        void WindowedFilter::reset(uint64_t new_bw, uint64_t new_time) {
            sample s = {new_bw, new_time};
            m_estimates[0] = s;
            m_estimates[1] = s;
            m_estimates[2] = s;
        }

        ConnectionStateOnSentPacket::ConnectionStateOnSentPacket(uint64_t sent_time, uint64_t bytes,
                BandwidthSampler *b) :
        sentTime(sent_time),
        size(bytes),
        totalBytesSent(b->m_total_bytes_sent),
        lastAckedPacketSentTime(b->m_last_acked_packet_sent_time),
        lastAckedPacketAckTime(b->m_last_acked_packet_ack_time),
        totalBytesAckedAtTheLastAckedPacket(b->m_total_bytes_acked),
        isAppLimited(b->m_is_app_limited) {}

        // OnPacketSent inputs the sent packet information into the sampler. Assumes that all
        // packets are sent in order. The information about the packet will not be
        // released from the sampler until it the packet is either acknowledged or
        // declared lost.
        void BandwidthSampler::onPacketSent(uint64_t sent_time, uint64_t pn, uint64_t bytes, 
                uint64_t bytes_inflight, bool has_retransmittable_data) {
            m_last_sent_packet = pn;
            if (!has_retransmittable_data) {
                return;
            }
            m_total_bytes_sent += bytes;

	        // If there are no packets in flight, the time at which the new transmission
	        // opens can be treated as the A_0 point for the purpose of bandwidth
	        // sampling. This underestimates bandwidth to some extent, and produces some
	        // artificially low samples for most packets in flight, but it provides with
	        // samples at important points where we would not have them otherwise, most
	        // importantly at the beginning of the connection.
            if (bytes_inflight == 0) {
                m_last_acked_packet_ack_time = sent_time;
                m_total_bytes_sent_at_last_acked_packet = m_total_bytes_sent;

                // In this situation ack compression is not a concern, set send rate to effectively infinite.
                m_last_acked_packet_sent_time = sent_time;
            }
            m_connection_state_map[pn] = std::make_shared<ConnectionStateOnSentPacket>(sent_time, bytes, this);
        }

        static uint64_t BandwidthFromDelta(uint64_t bytes, uint64_t delta) {
            return bytes * 1 / delta * 8;
        }

        BandwidthSample BandwidthSampler::onPacketAcked(uint64_t ack_time, uint64_t pn) {
            auto it = m_connection_state_map.find(pn);
            if (it == m_connection_state_map.end()) {
                // TODO(vasilvv): currently, this can happen because the congestion
                // controller can be created while some of the handshake packets are still
                // in flight.  Once the sampler is fully integrated with unacked packet map,
                // this should be a QUIC_BUG equivalent.
                return BandwidthSample();
            }
            auto sent_packet = it->second;
            m_total_bytes_acked += sent_packet->size;

            m_total_bytes_sent_at_last_acked_packet = sent_packet->totalBytesSent;
            m_last_acked_packet_sent_time = sent_packet->sentTime;
            m_last_acked_packet_ack_time = ack_time;
            m_connection_state_map.erase(pn);

            // Exit app-limited phase once a packet that was sent while the connection is
            // not app-limited is acknowledged.
            if (m_is_app_limited && pn > m_end_of_app_limited_phase) {
                m_is_app_limited = false;
            }

            // There might have been no packets acknowledged at the moment when the
            // current packet was sent. In that case, there is no bandwidth sample to
            // make.
            if (sent_packet->lastAckedPacketSentTime == 0) {
                return BandwidthSample();
            }

            // Infinite rate indicates that the sampler is supposed to discard the
            // current send rate sample and use only the ack rate.
            uint64_t sent_rate = ~0ull;
            if (sent_packet->sentTime < sent_packet->lastAckedPacketSentTime) {
                sent_rate = BandwidthFromDelta(sent_packet->totalBytesSent - sent_packet->totalBytesSentAtLastAckedPacket,
                        sent_packet->sentTime - sent_packet->lastAckedPacketSentTime);
            }

            // During the slope calculation, ensure that ack time of the current packet is
            // always larger than the time of the previous packet, otherwise division by
            // zero or integer underflow can occur.
            if (ack_time <= sent_packet->lastAckedPacketAckTime) {
                return BandwidthSample();
            }

            uint64_t ack_rate = BandwidthFromDelta(m_total_bytes_acked - sent_packet->totalBytesAckedAtTheLastAckedPacket,
                    ack_time - sent_packet->lastAckedPacketAckTime);

            return BandwidthSample {
                std::min(sent_rate, ack_rate),
    	        // Note: this sample does not account for delayed acknowledgement time.  This
    	        // means that the RTT measurements here can be artificially high, especially
    	        // on low bandwidth connections.
    	        ack_time - sent_packet->sentTime,
    	        // A sample is app-limited if the packet was sent during the app-limited
    	        // phase.
    	        sent_packet->isAppLimited
            };
        }

        void BandwidthSampler::onPacketLost(uint64_t pn) {
            auto it = m_connection_state_map.find(pn);
            if (it == m_connection_state_map.end()) {
                return;
            }
            m_connection_state_map.erase(pn);
        }

        void BandwidthSampler::onApplimited() {
            m_is_app_limited = true;
            m_end_of_app_limited_phase = m_last_sent_packet;
        }

        void BandwidthSampler::removeObsoletePackets(uint64_t least_unacked) {
            for (auto it = m_connection_state_map.begin();
                    it != m_connection_state_map.end();) {
                if (it->first < least_unacked) {
                    m_connection_state_map.erase(it++);
                } else {
                    it++;
                }
            }
            return;
        }

    }
}
