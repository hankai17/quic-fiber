#ifndef __QUIC_SERVER_HH__
#define __QUIC_SERVER_HH__

#include "my_sylar/stream.hh"
#include "quic-fiber/quic_type.hh"
#include "quic-fiber/quic_packet.hh"
#include "quic-fiber/quic_stream.hh"
#include "quic-fiber/quic_packet_sorter.hh"
#include "quic-fiber/quic_session.hh"

#include <map>

namespace sylar {
    namespace quic {

        class QuicServer : public AsyncSocketStream {
        public:
            typedef std::shared_ptr<QuicServer> ptr;
            QuicServer(Socket::ptr sock, QuicRole role = QuicRole::QUIC_ROLE_SERVER);
            ~QuicServer() {};

            QuicConnectionId::ptr generateConnectionId();

            QuicSession::ptr accept();
            bool signalAccept(QuicSession::ptr session);

            int sendPacket(MBuffer::ptr buffer_block, Address::ptr addr);

            void run();

            QuicSession::ptr newClientSession(Address::ptr peer_addr = nullptr);
        protected:
            struct PacketSendCtx : public Ctx {
                typedef std::shared_ptr<PacketSendCtx> ptr;
                MBuffer::ptr packet_buffer;
                Address::ptr peer_addr;
                virtual bool doSend(AsyncSocketStream::ptr stream) override;
            };

            int handleInitialPacket(QuicEPacketHeader::ptr header, MBuffer::ptr alt_packet);
            QuicConnectionId::ptr parseConnectionId(MBuffer::ptr buffer_block);
            int handlePacket(uint64_t now);
            Ctx::ptr doRecv();

        private:
            QuicRole m_role;
            QuicSessionManager m_sessions_mgr;
            QuicBuffer::ptr m_buffer;

            RWMutexType             m_mutex;
            sylar::FiberSemaphore   m_accept_sem;
            std::list<QuicSession::ptr> m_accept_queue;
        };
    }
}

#endif

