#pragma once

#include <condition_variable>
#include <cstddef>
#include <deque>
#include <mutex>
#include <optional>
#include <stop_token>

namespace mh {

template <typename T>
class BoundedQueue {
public:
    explicit BoundedQueue(std::size_t capacity) : capacity_(capacity) {}

    // Blocks while the queue is full. Returns false if the queue was closed or a stop was requested.
    bool push(T value, std::stop_token stop) {
        std::unique_lock lock(mutex_);
        if (!not_full_.wait(lock, stop, [&] { return items_.size() < capacity_ || closed_; }) || closed_) {
            return false;
        }
        items_.push_back(std::move(value));
        lock.unlock();
        not_empty_.notify_one();
        return true;
    }

    // Blocks while the queue is empty. Returns nullopt once the queue is closed and drained, or on stop.
    std::optional<T> pop(std::stop_token stop) {
        std::unique_lock lock(mutex_);
        if (!not_empty_.wait(lock, stop, [&] { return !items_.empty() || closed_; }) || items_.empty()) {
            return std::nullopt;
        }
        T value = std::move(items_.front());
        items_.pop_front();
        lock.unlock();
        not_full_.notify_one();
        return value;
    }

    void close() {
        {
            std::lock_guard lock(mutex_);
            closed_ = true;
        }
        not_empty_.notify_all();
        not_full_.notify_all();
    }

private:
    std::mutex mutex_;
    std::condition_variable_any not_empty_;
    std::condition_variable_any not_full_;
    std::deque<T> items_;
    std::size_t capacity_;
    bool closed_ = false;
};

}  // namespace mh
