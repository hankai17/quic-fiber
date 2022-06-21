#include "quic_frame_sorter.hh"
#include <sstream>

namespace sylar {
    namespace quic {
        FrameSorter::GapIt FrameSorter::findStartGap(QuicOffset offset, int &result) {
            result = false;
            for (auto it = m_gaps.begin(); it != m_gaps.end(); it++) {
                if (offset >= (*it)->start()
                        && offset <= (*it)->end()) {
                    result = true;
                    return it;
                }
                if (offset < (*it)->start()) {
                    return it;
                }
            }
            return m_gaps.end();
        }
        
        FrameSorter::GapIt FrameSorter::findEndGap(QuicOffset offset, int &result) {
            result = false;
            for (auto it = m_gaps.begin(); it != m_gaps.end(); it++) {
                if (offset >= (*it)->start()
                        && offset < (*it)->end()) {
                    result = true;
                    return it;
                }
                if (offset < (*it)->start()) {
                    return (it == m_gaps.begin()) ? m_gaps.end() : --it;
                }
            }
            return m_gaps.end();
        }
        
        void FrameSorter::delete_consecutive(QuicOffset pos) {
            for (;;) {
                auto it = m_queue.find(pos);
                if (it == m_queue.end()) {
                   break;
                }
                size_t old_entry_len = it->second->size();
                m_queue.erase(it->first);
                it->second->cb();
                pos += old_entry_len;
            }
        }

        FrameSorterResult::ptr FrameSorter::push(const MBuffer::ptr &data, QuicOffset offset, 
                const std::function<void()> &cb) {
            int start_in_gap = 0;
            int end_in_gap = 0;

            if (data->readAvailable() == 0) {
                return std::make_shared<FrameSorterResult>(1, "data null");
            }
            QuicOffset start = offset;
            QuicOffset end = offset + data->readAvailable();
            if (end <= m_gaps.front()->start()) {
                return std::make_shared<FrameSorterResult>(1, "data end pos < gaps's front start");
            }
            FrameSorter::GapIt start_gap_it = findStartGap(start, start_in_gap);
            FrameSorter::GapIt end_gap_it = findEndGap(end, end_in_gap);
            ByteInterval::ptr start_gap = *start_gap_it;
            ByteInterval::ptr end_gap = *end_gap_it;
            bool start_equal_end_gap = start_gap == end_gap;
        
            if ((start_equal_end_gap && end <= start_gap->start()) ||
                    (!start_equal_end_gap && 
                    start_gap->end() >= end_gap->start() &&
                    end <= start_gap->start())) {
                return std::make_shared<FrameSorterResult>(1, "todo");
            }
        
            FrameSorter::GapIt start_gap_next = ++start_gap_it;
            --start_gap_it;
            QuicOffset start_gap_end = start_gap->end();
            QuicOffset end_gap_start = end_gap->start();
            QuicOffset end_gap_end = end_gap->end();
            bool adjusted_start_gap_end = false; 
            bool was_cut = false;
            
            QuicOffset pos = start;
            bool has_replaced = false;
        
            for (;;) {
                auto it = m_queue.find(pos);
                if (it == m_queue.end()) {
                   break;
                }
                QuicOffset old_entry_len = it->second->size();
                if (end - pos > old_entry_len || 
                        (has_replaced && end - pos == old_entry_len)) {
                    m_queue.erase(it->first);
                    pos += old_entry_len;
                    has_replaced = true;
                    it->second->cb();
                } else {
                    if (!has_replaced) {
                        return std::make_shared<FrameSorterResult>(1, "todo1");
                    }
                    data->truncate_r(pos - start);
                    end = pos;
                    was_cut = true;
                    break;
                }
            }
        
            if (!start_in_gap && !has_replaced) {
                data->truncate_r(start_gap->start() - start);
                start = start_gap->start();
                was_cut = true;
            }
        
            if (start <= start_gap->start()) {
                if (end >= start_gap->end()) {
                    m_gaps.erase(start_gap_it);
                } else {
                    start_gap->set_start(end);
                }
            } else {
                start_gap->set_end(start);
                adjusted_start_gap_end = true;
            }
        
            if (!start_equal_end_gap) {
                delete_consecutive(start_gap_end);
                FrameSorter::GapIt next;
                for (auto it = start_gap_next; (*it)->end() < end_gap_start; it = next) {
                    auto tmp_it = it;
                    next = ++tmp_it;

                    delete_consecutive((*it)->end());
                    m_gaps.erase(it);
                }
            }
        
            if (end_in_gap && start != end_gap_end && end > end_gap_end) {
                data->truncate(end_gap_end - start);
                end = end_gap_end;
                was_cut = true;
            }
        
            if (end == end_gap_end) {
                if (!start_equal_end_gap) {
                    m_gaps.erase(end_gap_it);
                }
            } else {
                if (start_equal_end_gap && adjusted_start_gap_end) {
                    m_gaps.insert(++start_gap_it, std::make_shared<ByteInterval>(end, start_gap_end));
                } else if (!start_equal_end_gap) {
                    end_gap->set_start(end);
                }
            }
        
            if (was_cut && data->readAvailable() < 0) {
                cb(); 
            }
        
            if (m_gaps.size() > 1024) {
                return std::make_shared<FrameSorterResult>(2);
            }
            m_queue.insert(std::make_pair(start, std::make_shared<FrameSorterEntry>(data, cb)));
            return std::make_shared<FrameSorterResult>(0);
        }

        FrameSorterEntry::ptr FrameSorter::pop() {
            auto it = m_queue.find(m_read_pos);
            if (it == m_queue.end()) {
                return nullptr;
            }
            FrameSorterEntry::ptr entry = it->second;
            m_read_pos += it->second->size();
            m_queue.erase(it->first);
            if (m_gaps.front()->end() <= m_read_pos) {
                // TODO
            }
            return entry;
        }

        std::string FrameSorter::toString() const {
            std::stringstream ss;
            ss << "FrameSorter queue size: " << m_queue.size()
                << ", gaps size: " << m_gaps.size()
                << ", read pos: " << m_read_pos << "\n";

            for (auto it = m_queue.begin(); it != m_queue.end(); it++) {
                ss << "[offset: " << it->first << " entry_size: "
                    << it->second->size() << "], ";
            }
            ss << "\n";
            for (auto it = m_gaps.begin(); it != m_gaps.end(); it++) {
                ss << "{start: " << (*it)->start() << " end: "
                    << (*it)->end() << "}, ";
            }
            return ss.str();
        }
    }
}

