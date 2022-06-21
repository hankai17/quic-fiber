#include <my_sylar/macro.hh>
#include "quic-fiber/quic_server.hh"
#include "my_sylar/log.hh"
#include "my_sylar/util.hh"
#include "my_sylar/hash.hh"
#include "my_sylar/scheduler.hh"
#include "my_sylar/iomanager.hh"
#include "my_sylar/mbuffer.hh"
#include "my_sylar/address.hh"

namespace sylar {
    namespace quic {
        static sylar::Logger::ptr g_logger = SYLAR_LOG_NAME("system");

        QuicServer::QuicServer(Socket::ptr sock, QuicRole role) :
                AsyncSocketStream(sock, true),
                m_role(role) {
            m_buffer = std::make_shared<QuicBuffer>();
        }

        QuicConnectionId::ptr QuicServer::generateConnectionId() {
            QuicConnectionId::ptr cid = nullptr;
            while (1) {
                std::string cid_str = random_string(4);
                cid = std::make_shared<QuicConnectionId>((const uint8_t*)&cid_str.c_str()[0], 4);
                auto session = m_sessions_mgr.get(cid);
                if (session == nullptr) {
                    break;
                }
            }
            return cid; 
        }

        int QuicServer::handleInitialPacket(QuicEPacketHeader::ptr header, MBuffer::ptr alternate_packet) {
            auto ori_dcid = header->m_dst_cid;
            auto new_cid = generateConnectionId();
            auto session = m_sessions_mgr.get(ori_dcid);
            if (session) {
                SYLAR_LOG_INFO(g_logger) << "Not adding connection ID " << header->m_dst_cid->toHexString()
                                         << " for a new session, as it already exists";
                return -1;
            }
            session = std::make_shared<QuicSession>(std::dynamic_pointer_cast<QuicServer>(shared_from_this()),
                    QuicRole::QUIC_ROLE_SERVER, ori_dcid, m_buffer->getAddr());
            m_sessions_mgr.add(session);
            session->getStreamMgr()->setSessoin(session);
            session->getStreamMgr()->initMaps();
            SYLAR_LOG_WARN(g_logger) << "Adding cid " << ori_dcid->toHexString() << " and "
                                     << new_cid->toHexString() << "for a new session";
            signalAccept(session);
            session->signalRead(alternate_packet);
            session->run();
            return 0;
        }

        int QuicServer::handlePacket(uint64_t now) {
            auto packet = m_buffer->readBuffer();
            auto alternate_packet = std::make_shared<MBuffer_t>(*packet.get(), now);
            auto dst_cid = QuicConnectionId::parseConnectionId(packet);
            if (dst_cid == nullptr) {
                SYLAR_LOG_INFO(g_logger) << "handlePacket parseConnectionId failed";
                return -1;
            }
            auto session = m_sessions_mgr.get(dst_cid);
            if (session) {
                return session->signalRead(alternate_packet);
            }
            // accept new session
            auto header = readPacketHeaderFrom(packet);
            if (header == nullptr) {
                SYLAR_LOG_INFO(g_logger) << "handlePacket readPacketHeaderFrom failed";
                return -1;
            }
            SYLAR_LOG_INFO(g_logger) << "<- Reveived Initial packet";
            header->readPacketNumberFrom(packet);
            handleInitialPacket(header, alternate_packet);
            return 0;
        }

        QuicSession::ptr QuicServer::accept() {
            m_accept_sem.wait();
            QuicSession::ptr session = nullptr;
            {
                RWMutexType::WriteLock lock(m_mutex);
                session = m_accept_queue.front();
                m_accept_queue.pop_front();
            }
            return session;
        }
        
        bool QuicServer::signalAccept(QuicSession::ptr session) {
            RWMutexType::WriteLock lock(m_mutex);
            bool empty = m_accept_queue.empty();
            m_accept_queue.push_back(session);
            lock.unlock();
            //if (empty) {
                m_accept_sem.notify();
            //}
            return empty;
        }

        int QuicServer::sendPacket(MBuffer::ptr buffer_block, Address::ptr addr) {
            PacketSendCtx::ptr ctx = std::make_shared<PacketSendCtx>();
            ctx->packet_buffer = buffer_block;
            ctx->peer_addr = addr;
            //enqueue(ctx);
            ctx->doSend(shared_from_this());
            return 1;
        }

        void QuicServer::run() {
            start();
        }

        QuicSession::ptr QuicServer::newClientSession(Address::ptr peer_addr) {
            auto cid = generateConnectionId();
            auto session = std::make_shared<QuicSession>(
                    std::dynamic_pointer_cast<QuicServer>(shared_from_this()),
                    QuicRole::QUIC_ROLE_CLIENT, cid, peer_addr);
            m_sessions_mgr.add(session);
            session->getStreamMgr()->setSessoin(session);
            session->getStreamMgr()->initMaps();
            session->run();
            return session;
        }

        bool QuicServer::PacketSendCtx::doSend(AsyncSocketStream::ptr stream) {
            stream->sendTo(packet_buffer,
                    packet_buffer->readAvailable(), peer_addr);
            return true;
        }

        QuicServer::Ctx::ptr QuicServer::doRecv() {
            int ret = recvFrom(m_buffer->readBuffer(), 1500, m_buffer->getAddr());
            if (ret < 0) {
                return nullptr;
            }
            handlePacket(GetCurrentUs());
            m_buffer->readBuffer()->clear();
            return nullptr;
        }
        
    }
}

