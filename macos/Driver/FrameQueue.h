#ifndef ALFA_FRAME_QUEUE_H
#define ALFA_FRAME_QUEUE_H

#include "AlfaProtocol.h"
#include <stddef.h>
#include <string.h>

inline bool AlfaValidMAC(const uint8_t mac[6]) {
    uint8_t nonzero = 0;
    for (size_t i = 0; i < 6; ++i) nonzero |= mac[i];
    return nonzero && !(mac[0] & 1u);
}

inline bool AlfaValidFrame(const void *bytes, size_t length) {
    if (!bytes || length < ALFA_MIN_FRAME_SIZE || length > ALFA_MAX_FRAME_SIZE) return false;
    const auto *frame = static_cast<const uint8_t *>(bytes);
    const uint16_t type = static_cast<uint16_t>(frame[12] << 8) | frame[13];
    return type == 0x0800 || type == 0x0806 || type == 0x86dd;
}

struct AlfaFrame {
    uint16_t length;
    uint8_t bytes[ALFA_MAX_FRAME_SIZE];
};

struct AlfaFrameQueue {
    AlfaFrame frames[ALFA_FRAME_QUEUE_CAPACITY];
    uint32_t head;
    uint32_t count;

    bool push(const void *bytes, size_t length) {
        if (!AlfaValidFrame(bytes, length) || count == ALFA_FRAME_QUEUE_CAPACITY) return false;
        AlfaFrame &frame = frames[(head + count) % ALFA_FRAME_QUEUE_CAPACITY];
        memcpy(frame.bytes, bytes, length);
        frame.length = static_cast<uint16_t>(length);
        ++count;
        return true;
    }

    const AlfaFrame *peek() const { return count ? &frames[head] : nullptr; }

    uint32_t freeSlots() const { return ALFA_FRAME_QUEUE_CAPACITY - count; }

    void pop() {
        if (!count) return;
        memset(&frames[head], 0, sizeof(AlfaFrame));
        head = (head + 1) % ALFA_FRAME_QUEUE_CAPACITY;
        --count;
    }

    void clear() {
        memset(frames, 0, sizeof(frames));
        head = count = 0;
    }
};

template <typename Packet, typename Dequeue, typename Complete>
inline void AlfaDrainFrames(const AlfaFrameQueue &frames, bool ready,
                            Dequeue dequeue, Complete complete) {
    const uint32_t limit = ready ? frames.freeSlots() : ALFA_FRAME_QUEUE_CAPACITY;
    if (!limit) return;
    Packet *packets[ALFA_FRAME_QUEUE_CAPACITY];
    const uint32_t count = dequeue(packets, limit);
    for (uint32_t i = 0; i < count; ++i) complete(packets[i]);
}

#endif
