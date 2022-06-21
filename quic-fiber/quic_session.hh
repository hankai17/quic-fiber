#ifndef __QUIC_SESSION_HH__
#define __QUIC_SESSION_HH__

#include "my_sylar/stream.hh"
#include "my_sylar/hash.hh"
#include "my_sylar/scheduler.hh"
#include "quic-fiber/quic_type.hh"
#include "quic-fiber/quic_frame.hh"
#include "quic-fiber/quic_packet.hh"
#include "quic-fiber/quic_stream.hh"
#include "quic-fiber/quic_packet_sorter.hh"
#include "quic-fiber/quic_flow_control.hh"

#include <map>
#include <functional>

namespace sylar {
    namespace quic {

   	    class SessionSemaphore : public Nocopyable {
   	    public:
            typedef std::shared_ptr<SessionSemaphore> ptr;
            typedef SpinLock MutexType;

            SessionSemaphore();
            ~SessionSemaphore();
            QuicSessionEvent wait();
            void notify(QuicSessionEvent event);
            size_t concurrencySize() const { return m_events.size(); }
            std::string toString();
        private:
            MutexType       m_mutex;
            std::list<QuicSessionEvent> m_events;
            std::list<std::pair<Scheduler*, Fiber::ptr> >  m_waiters;
        };

        class WinUpdateQueue {
        public:
            typedef std::shared_ptr<WinUpdateQueue> ptr;
            typedef Mutex MutexType;

            WinUpdateQueue(const QuicStreamManager::ptr &streams,
                    const ConnectionFlowController::ptr &conn_flow_controller,
                    const std::function<void(QuicFrame::ptr)> &cb)
                    : m_streams(streams),
                      m_conn_flow_controller(conn_flow_controller),
                      m_cb(cb) {};
            void addStream(QuicStreamId id);
            void addConnection();
            void queueAll();
        private:
            MutexType       m_mutex;
            std::set<QuicStreamId> m_queue;
            bool            m_queued_conn = false;
            QuicStreamManager::ptr m_streams;
            ConnectionFlowController::ptr m_conn_flow_controller;
            std::function<void(QuicFrame::ptr)> m_cb;
        };


        class QuicServer;
        class QuicSession : public std::enable_shared_from_this<QuicSession>,
                public StreamSender {
        public:
            friend QuicServer;
            typedef std::shared_ptr<QuicSession> ptr;
            typedef sylar::RWMutex RWMutexType;
            typedef Mutex MutexType;

            virtual void onHasStreamData(QuicStreamId stream_id) override;
            virtual void onStreamCompleted(QuicStreamId stream_id) override;

            struct RetransmissionQueue {
                typedef std::shared_ptr<RetransmissionQueue> ptr;
                bool hasAppData() { return m_app_data.size() > 0; }
                void addAppData(QuicFrame::ptr frame);
                QuicFrame::ptr getAppDataFrame(uint64_t max_len);
                std::list<QuicFrame::ptr> m_app_data;
            };

            QuicSession(std::shared_ptr<QuicServer> server, QuicRole role, 
                    QuicConnectionId::ptr cid, Address::ptr peer_addr = nullptr);
            ~QuicSession();

            int handleFrame(const QuicFrame::ptr &frame, uint64_t now);
            int handleUnpackedPacket(const QuicEPacketHeader::ptr &header, const MBuffer::ptr &buffer_block);
            int handlePacket(const MBuffer::ptr &buffer_block);
            int signalRead(MBuffer::ptr buffer_block);

            void sendPacketBuffer(MBuffer::ptr buffer_block);

            bool maybePackProbePacket(uint64_t now);
            void sendProbePacket();

            uint64_t appendControlFrames(std::list<QuicFrame::ptr> &frames, uint64_t max_packet_size);
            const QuicPacketPayload::ptr composeNextPacket(uint64_t max_payload_size, bool ack_allow = true);
            int popStreamFrames(std::list<QuicFrame::ptr> &frames, uint64_t max_packet_size);
            bool sendPacket(uint64_t now);
            void sendPackets();
            void signalWrite();

            uint64_t nextKeepAliveTime();

            uint64_t maybeResetTimer();
            void run_impl();
            void run();
            void closeSession() { m_is_alive = false; signalWrite(); signalRead(nullptr); }
            void closeLocal() { return closeSession(); }
            void closeRemote() { return closeSession(); }
            bool isAlive() const { return m_is_alive; }

            const std::shared_ptr<QuicServer> getServer() const { return m_server.lock(); }
            const QuicStreamManager::ptr &getStreamMgr() const { return m_streams; }
            const QuicStream::ptr openStream();
            const QuicStream::ptr acceptStream();

            const QuicEPacketHeader::ptr getShortHeader(QuicConnectionId::ptr cid, QuicPacketType type);
            const QuicEPacketHeader::ptr getLongHeader(QuicConnectionId::ptr sid, QuicConnectionId::ptr did,
                    QuicPacketType type);
            QuicConnectionId::ptr getCid() const { return m_cid; }

            void onHasConnectionWinUpdate() { m_win_update_queue->addConnection(); signalWrite(); }
            void onHasStreamWinUpdate(QuicStreamId stream_id) { m_win_update_queue->addStream(stream_id); signalWrite(); }
            StreamFlowController::ptr newFlowController(QuicStreamId stream_id);
            void queueControlFrame(QuicFrame::ptr frame) override { m_control_frames.push_back(frame); signalWrite(); }
            void addActiveStream(QuicStreamId id);

        private:
            std::weak_ptr<QuicServer> m_server;
            QuicRole m_role;
            QuicConnectionId::ptr m_cid;
            bool m_ssl;

            Address::ptr m_peer_addr;
            RWMutexType             m_mutex;
            sylar::FiberSemaphore   m_received_sem;
            std::list<MBuffer::ptr> m_received_queue;
            sylar::FiberSemaphore   m_send_sem;
            std::list<MBuffer::ptr> m_send_queue;
            sylar::FiberSemaphore   m_timer_sem;
            SessionSemaphore  m_session_sem;
            uint64_t m_pacing_deadline = 0;

            QuicStreamManager::ptr m_streams;
            PacketNumberManager::ptr m_pn_mgr;
            RTTStats::ptr m_rtt_stats;
            SentPacketHandler::ptr m_sent_packet_handler;
            ReceivedPacketTracker::ptr m_received_packet_handler;
            RetransmissionQueue::ptr m_retrans_queue;

            ConnectionFlowController::ptr m_conn_flow_controler;
            WinUpdateQueue::ptr m_win_update_queue;
            std::list<QuicFrame::ptr> m_control_frames;

            MutexType m_active_stream_mutex;
            std::list<QuicStreamId> m_stream_queue;
            std::map<QuicStreamId, bool> m_active_streams;

            MutexType m_timer_snd_mutex;
            bool m_is_alive;
        };

        class QuicSessionManager {
        public:
            typedef std::shared_ptr<QuicSessionManager> ptr;
            typedef RWMutex RWMutexType;

            const QuicSession::ptr get(QuicConnectionId::ptr cid);
            void add(QuicSession::ptr session);
            void del(const std::string &cid);
            void clear();
            void foreach(std::function<void(QuicSession::ptr)> cb);

        private:
            RWMutexType m_mutex;
            std::unordered_map<std::string, QuicSession::ptr> m_sessions;
        };

        class QuicClosedLocalSession {
        public:
            typedef std::shared_ptr<QuicClosedLocalSession> ptr;
            void run() {
                for (;;) {

                }
            }
            void handlePacket(const MBuffer::ptr &buffer_block);
            void handlePacketImpl(const MBuffer::ptr &buffer_block);
            void destroy() {} // TODO
            void shutdown() { return destroy(); }

        private:
            QuicRole m_role;
            uint64_t m_counter = 0;
        };
    }
}

#endif

