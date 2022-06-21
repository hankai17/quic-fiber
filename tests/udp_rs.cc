#include <signal.h>

#include "my_sylar/log.hh"
#include "my_sylar/util.hh"
#include "my_sylar/scheduler.hh"
#include "my_sylar/iomanager.hh"
#include "my_sylar/mbuffer.hh"
#include "my_sylar/address.hh"
#include "my_sylar/stream.hh"

using namespace sylar;
static uint64_t g_count = 0;
static uint64_t g_interval = 0;

sylar::Logger::ptr g_logger = SYLAR_LOG_ROOT();

class UdpSession : public AsyncSocketStream {
public:
    typedef std::shared_ptr<UdpSession> ptr;
    
    UdpSession(Socket::ptr sock, Address::ptr peer_addr = nullptr) 
        : AsyncSocketStream(sock),
          m_peer_addr(peer_addr) {}

    void run() {
        start();
    }
protected:
    struct PacketSendCtx : public Ctx {
        typedef std::shared_ptr<PacketSendCtx> ptr;
        uint64_t recv_time;
        MBuffer::ptr buffer;
        Address::ptr peer_addr;
        virtual bool doSend(AsyncSocketStream::ptr stream) override {
            g_count++;
            stream->sendTo(buffer, buffer->readAvailable(), peer_addr);
            SYLAR_LOG_ERROR(g_logger) << "interval: " << GetCurrentUs() - recv_time;
            //g_interval += GetCurrentUs() - recv_time;
            return true;
        }
    };
    virtual Ctx::ptr doRecv() override {
        Address::ptr peer_addr = std::make_shared<IPv4Address>();
        MBuffer::ptr buffer = std::make_shared<MBuffer>(); 
        int ret = recvFrom(buffer, 1500, peer_addr);
        if (ret < 0) {
            return nullptr;
        }
        m_peer_addr = peer_addr;
        sendPacketBuffer(buffer);
        return nullptr;
    }
    void sendPacketBuffer(MBuffer::ptr buffer) {
        PacketSendCtx::ptr ctx = std::make_shared<PacketSendCtx>();
        ctx->buffer = buffer;
        ctx->peer_addr = m_peer_addr;
        ctx->recv_time = GetCurrentUs();
#if 0
        enqueue(ctx);
#else
        ctx->doSend(shared_from_this());
#endif
    }

private:
    bool m_ssl;
    uint64_t m_interval = 0;
    Address::ptr m_peer_addr;
};

int main()
{
    signal(SIGPIPE, SIG_IGN);
    sylar::IOManager iom(4, false, "io");

    auto server_addr = sylar::IPv4Address::Create("0.0.0.0", 4242);
    auto sock = sylar::Socket::CreateUDP(server_addr);
    sock->bind(server_addr);
    auto session = std::make_shared<UdpSession>(sock);
    iom.schedule([session](){
        session->run();
    }); 
    iom.addTimer(2000, [](){
        if (g_count == 0) {
            return;
        }
        SYLAR_LOG_ERROR(g_logger) << "mean interval: " << g_interval/g_count;
    }, true);
    iom.stop();
    return 0;
}

// nc -u 0.0.0.0 4242

/*

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <ctype.h>

#define SERV_PORT 4242

int main(int argc, char *argv[])
{
    struct sockaddr_in servaddr;
    int sockfd, n;
    char buf[BUFSIZ];

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    inet_pton(AF_INET, "127.0.0.1", &servaddr.sin_addr);
    servaddr.sin_port = htons(SERV_PORT);

    strcpy(buf, "hello world\n");
    int count = 0;

    while (1) {
        count++;
        n = sendto(sockfd, buf, strlen(buf), 0, (struct sockaddr *)&servaddr, sizeof(servaddr));
        if (n == -1)
            perror("sendto error");

        n = recvfrom(sockfd, buf, BUFSIZ, 0, NULL, 0);         //NULL:不关心对端信息
        if (n == -1)
            perror("recvfrom error");

        //write(STDOUT_FILENO, buf, n);
        usleep(1000);
        if (count == 100000) {
            break;
        }
    }

    close(sockfd);

    return 0;
}

*/
