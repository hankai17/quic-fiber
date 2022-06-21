#include "my_sylar/log.hh"
#include "my_sylar/address.hh"
#include "my_sylar/iomanager.hh"
#include "my_sylar/stream.hh"
#include "my_sylar/fiber.hh"
#include "my_sylar/macro.hh"

#include "quic-fiber/quic_type.hh"
#include "quic-fiber/quic_frame.hh"
#include "quic-fiber/quic_session.hh"
#include "quic-fiber/quic_frame_sorter.hh"
#include "quic-fiber/quic_server.hh"

#include <signal.h>

using namespace sylar;
using namespace quic;

Logger::ptr g_logger = SYLAR_LOG_ROOT();
std::vector<QuicStream::ptr> g_streams;

std::string to_hex(const std::string& str) {
    std::stringstream ss;
    for(size_t i = 0; i < str.size(); ++i) {
        ss << std::setw(2) << std::setfill('0') << std::hex
           << (int)(uint8_t)str[i];
    }
    return ss.str();
}

static void handle_session_stream(QuicStream::ptr stream) {
    int sum_size = 0;
    SYLAR_LOG_ERROR(g_logger) << ", accept stream_id: " << stream->stream_id();
    while (1) {
        auto buffer_block = std::make_shared<sylar::MBuffer>();
        auto ret = stream->read(buffer_block, 1500);
        sum_size += ret->bytes_rw();
        //SYLAR_LOG_ERROR(g_logger) << "upper stream read ret: " << ret->bytes_rw()
        //            << ", sum_size: " << sum_size << ", err: " << ret->err_no();
        if (ret->isCompleted()) {
            break;
        }
    }
    stream->readStream()->cancelRead();
    SYLAR_LOG_ERROR(g_logger) << "stream read completed: " << sum_size;
    stream->close();
}

static void handle_session(QuicSession::ptr session) {
    while (1) {
        auto stream = session->acceptStream();
        if (stream) {
            SYLAR_LOG_ERROR(g_logger)  << "session accept stream ok ";
            IOManager::GetThis()->schedule(std::bind(&handle_session_stream, stream));
        }
    }
}

void quic_server() {
    IPAddress::ptr server_addr = IPv4Address::Create("0.0.0.0", 4242);
    auto sock = Socket::CreateUDP(server_addr);
    sock->bind(server_addr);
    QuicServer::ptr server = nullptr;
    server = std::make_shared<QuicServer>(sock);
    server->run();
    while (1) {
        auto session = server->accept();
        if (session) {
            SYLAR_LOG_ERROR(g_logger)  << "server accept session ok ";
            IOManager::GetThis()->schedule(std::bind(&handle_session, session));
        }
    }
    return;
}

int main() {
    signal(SIGPIPE, SIG_IGN);
    sylar::IOManager iom(2, false, "io");
    srand(time(0));
    iom.schedule(quic_server);
    iom.stop();
    return 0;
}

