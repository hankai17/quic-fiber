#ifndef __QUIC_FRAME_SORTER_HH__
#define __QUIC_FRAME_SORTER_HH__

#include <map>
#include <list>
#include <memory>
#include <functional>
#include <unordered_map>

#include "my_sylar/mbuffer.hh"
#include "quic-fiber/quic_type.hh"

namespace sylar {
    namespace quic {

        static constexpr uint32_t MAX_BYTE_OFFSET = 0XFFFFFFFF;
        class FrameSorterEntry {
        public:
            typedef std::shared_ptr<FrameSorterEntry> ptr;
            FrameSorterEntry(const MBuffer::ptr &data, const std::function<void()> &cb) : m_data(data), m_cb(cb) {}
            size_t size() const { return m_data->readAvailable(); }
            void cb() { if (m_cb) return m_cb(); }
            const MBuffer::ptr &data() const { return m_data; }
        private:
            MBuffer::ptr m_data = nullptr;
            std::function<void()> m_cb = nullptr;
        };

        struct ByteInterval {
        public:
            typedef std::shared_ptr<ByteInterval> ptr;
            ByteInterval(QuicOffset start, QuicOffset end) : m_start(start), m_end(end) {}
            void set_start(QuicOffset start) { m_start = start; }
            void set_end(QuicOffset end) { m_end = end; }
            QuicOffset start() const { return m_start; }
            QuicOffset end() const { return m_end; }
        private:        
            QuicOffset m_start = 0;
            QuicOffset m_end = MAX_BYTE_OFFSET;
        };

        class FrameSorterResult {
        public:
            typedef std::shared_ptr<FrameSorterResult> ptr;
            enum class Error {
                OK = 0,
                DUP_DATA = 1,
                TOO_MANY_GAPS = 2,
                UNKNOW
            };
            std::string toString() const;
            FrameSorterResult(int result, const std::string &err = "")
                    : m_result(result), m_error(err) {};
            int err_no() const { return m_result; }
        private:
            int m_result = 0;
            std::string m_error = "";
        };

        class FrameSorter {
        public:
            typedef std::shared_ptr<FrameSorter> ptr;
            typedef std::list<ByteInterval::ptr>::iterator GapIt;

            GapIt findStartGap(QuicOffset offset, int &result);
            GapIt findEndGap(QuicOffset offset, int &result);
            void delete_consecutive(QuicOffset pos);
            FrameSorterResult::ptr push(const MBuffer::ptr &data, QuicOffset offset, const std::function<void()> &cb);
            FrameSorterEntry::ptr pop();
            QuicOffset read_pos() const { return m_read_pos; }
            std::string toString() const;
            size_t size() const { return m_queue.size(); }
            int gaps() const { return m_gaps.size(); }
            
        private:
            QuicOffset m_read_pos = 0;
            std::unordered_map<QuicOffset, FrameSorterEntry::ptr> m_queue;
            std::list<ByteInterval::ptr> m_gaps = {std::make_shared<ByteInterval>(0, MAX_BYTE_OFFSET)};
        };
    }
}

#endif

