#include "my_sylar/log.hh"
#include "my_sylar/address.hh"
#include "my_sylar/iomanager.hh"
#include "my_sylar/stream.hh"
#include "my_sylar/fiber.hh"
#include "my_sylar/hash.hh"

#include "my_sylar/quic/quic_type.hh"
#include "my_sylar/quic/quic_frame.hh"
#include "my_sylar/quic/quic_session.hh"
#include "my_sylar/quic/quic_frame_sorter.hh"
#include "my_sylar/quic/quic_server.hh"

#include <signal.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

using namespace sylar;
using namespace quic;
#define TMP_FILE "/tmp/1.log"

Logger::ptr g_logger = SYLAR_LOG_ROOT();

std::string to_hex(const std::string& str) {
    std::stringstream ss;
    for(size_t i = 0; i < str.size(); ++i) {
        ss << std::setw(2) << std::setfill('0') << std::hex
           << (int)(uint8_t)str[i];
    }
    return ss.str();
}

int file_size(const char* filePath) {
    if(filePath == NULL) return 0;
    struct stat sb;
    if(stat(filePath, &sb) < 0)
    return 0;
    return sb.st_size;
}

int generate_file()
{
    int size = 0;
    FILE *f = fopen(TMP_FILE, "w+");
    if (f == nullptr) {
        SYLAR_LOG_ERROR(g_logger) << "generate file failed";
        return -1;
    }
    std::string str = "1234567890abcdefghigklmnopqrstuvwxyz";
    for (int i = 0; i < 1000 * 100; i++) {
        int ret = fwrite(str.c_str(), 1, str.size(), f);
        if (ret != (int)str.size()) {
            SYLAR_LOG_ERROR(g_logger) << "generate file fwrite failed";
            fclose(f);
            return -1;
        }
        size += ret;
    }
    fclose(f);
    return size;
}

void client_send_file(QuicServer::ptr server)
{
    int size = 0;
    auto server_addr = sylar::IPv4Address::Create("0.0.0.0", 4242);
    auto client_session = server->newClientSession(server_addr);
    SYLAR_LOG_ERROR(g_logger) << "session id: " << client_session->getCid()->toHexString();
    auto stream = client_session->openStream();
    SYLAR_LOG_ERROR(g_logger) << "streamid: " << stream->stream_id();

    size = file_size(TMP_FILE);
    if (size <= 0) {
        size = generate_file();
        if (size < 0) {
            return;
        }
    }
    FILE *f = fopen(TMP_FILE, "r");
    if (f == nullptr) {
        SYLAR_LOG_ERROR(g_logger) << "open file faild";
        return;
    }
    uint64_t sum = 0;
    while (size) {
        std::string buffer("", 1024);
        int ret = fread(&buffer[0], 1, buffer.size(), f);
        size -= ret;
        auto buffer_block = std::make_shared<sylar::MBuffer>();
        buffer_block->write(buffer.c_str(), ret);
        auto res = stream->write(buffer_block);
        if (res->bytes_rw() != ret || res->err_no() != 0) {
            SYLAR_LOG_ERROR(g_logger) << "ret: " << ret << ", write ret: " << res->bytes_rw() << ", error: " << res->err_no() << ", strerr: " << res->strerr();
        }
        sum += res->bytes_rw();
    }
    SYLAR_LOG_ERROR(g_logger) << "sum: " << sum << ", remain size: " << size;
    fclose(f);
    SYLAR_LOG_ERROR(g_logger) << stream->toSndStatisticsString();
    stream->close();
}

void quic_server(int idx) {
    auto client_addr = sylar::IPv4Address::Create("0.0.0.0", 1234 + idx);
    auto sock = sylar::Socket::CreateUDP(client_addr);
    sock->bind(client_addr);
    auto server = std::make_shared<QuicServer>(sock);
    server->run();
    IOManager::GetThis()->addTimer(100, std::bind(&client_send_file, server), false);
    return;
}

int main() {
    signal(SIGPIPE, SIG_IGN);
    sylar::IOManager iom(2, false, "io");
    srand(time(0));
    generate_file();
    for (int i = 0; i < 1; i++) {
        iom.schedule(std::bind(quic_server, i));
    }
    iom.addTimer(1000, [](){}, true);
    iom.stop();
    return 0;
}

