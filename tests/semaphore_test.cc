#include "my_sylar/log.hh"
#include "my_sylar/iomanager.hh"
#include "my_sylar/thread.hh"
#include "my_sylar/util.hh"
#include "quic-fiber/quic_session.hh"

#define PRODUCER_ENTRY 100

using namespace sylar;
using namespace quic;

sylar::Logger::ptr g_logger = SYLAR_LOG_ROOT();

void producer(sylar::FiberSemaphore::ptr sem) {
    sleep(1);
    for (int i = 0; i < PRODUCER_ENTRY; i++) {
        usleep(5 * 1000);
        sem->notifyMore(5);
    }
    return;
}

void consumer(sylar::FiberSemaphore::ptr sem) {
    while (1) {
        uint64_t before = GetCurrentUs();
#if 1
        sem->wait();
#else
        if (!sem->tryWait()) {
            continue;
        }
#endif
        uint64_t interval = GetCurrentUs() - before;
        SYLAR_LOG_INFO(g_logger) << interval;
    }
}

void session_producer(SessionSemaphore::ptr sem) {
    for (int i = 0; i < 10; i++) {
        if (i % 2) {
            sem->notify(QuicSessionEvent::READ);
        } else {
            sem->notify(QuicSessionEvent::WRITE);
        }
    }
    return;
}

void session_consumer(SessionSemaphore::ptr sem) {
    while (1) {
        uint64_t before = GetCurrentUs();
        QuicSessionEvent ev = sem->wait();
        uint64_t interval = GetCurrentUs() - before;
        SYLAR_LOG_ERROR(g_logger) << interval << ", session consumer wait end, get ev: " << (int)ev;
    }
}

int main1() {
    sylar::IOManager iom(4, false, "io");

    sylar::FiberSemaphore::ptr sem(new sylar::FiberSemaphore(0));
    for (int j = 0; j < 2; j++) {
        iom.schedule(std::bind(&producer, sem));
    }
    iom.schedule(std::bind(&consumer, sem));
    iom.stop();
    return 0;
}

int main() {
    sylar::IOManager iom(4, false, "io");
    auto sem = std::make_shared<SessionSemaphore>();
    for (int i = 0; i < 2; i++) {
        iom.schedule(std::bind(&session_producer, sem));
    }
    iom.schedule(std::bind(&session_consumer, sem));
    iom.stop();
    return 0;
}

