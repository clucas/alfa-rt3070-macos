#include "FrameQueue.h"
#include "Authorization.h"
#include <assert.h>
#include <deque>
#include <random>
#include <vector>

static std::vector<uint8_t> frame(size_t size, uint8_t marker) {
    std::vector<uint8_t> bytes(size, marker);
    if (size >= 14) { bytes[12] = 0x08; bytes[13] = 0x00; }
    return bytes;
}

struct SubmittedPacket {
    std::vector<uint8_t> bytes;
    uint32_t completions = 0;
};

struct TransmitQueues {
    AlfaFrameQueue frames = {};
    std::deque<SubmittedPacket> owned;
    std::deque<SubmittedPacket *> submission;
    uint32_t drops = 0;
    uint32_t dequeueCalls = 0;

    void submit(uint8_t marker, bool valid = true) {
        owned.push_back({frame(valid ? 64 : 10, marker)});
        submission.push_back(&owned.back());
    }

    void drain(bool ready = true) {
        AlfaDrainFrames<SubmittedPacket>(frames, ready,
          [&](SubmittedPacket **packets, uint32_t limit) {
            ++dequeueCalls;
            assert(limit > 0 && limit <= ALFA_FRAME_QUEUE_CAPACITY);
            uint32_t count = 0;
            while (count < limit && !submission.empty()) {
                packets[count++] = submission.front();
                submission.pop_front();
            }
            return count;
          },
          [&](SubmittedPacket *packet) {
            assert(packet->completions++ == 0);
            if (!ready || !frames.push(packet->bytes.data(), packet->bytes.size())) ++drops;
          });
    }
};

static void testTransmitBackpressure() {
    TransmitQueues queues;
    for (uint32_t i = 0; i < 2 * ALFA_FRAME_QUEUE_CAPACITY; ++i) queues.submit(i);
    queues.drain();
    assert(queues.frames.freeSlots() == 0);
    assert(queues.submission.size() == ALFA_FRAME_QUEUE_CAPACITY);
    const uint32_t calls = queues.dequeueCalls;
    queues.drain();
    assert(queues.dequeueCalls == calls);
    assert(queues.drops == 0);

    for (uint32_t i = 0; i < 2 * ALFA_FRAME_QUEUE_CAPACITY; ++i) {
        const auto *packet = queues.frames.peek();
        assert(packet && packet->bytes[0] == i);
        queues.frames.pop();
        queues.drain();
    }
    assert(queues.frames.count == 0 && queues.submission.empty());
    assert(queues.drops == 0);
    for (const auto &packet : queues.owned) assert(packet.completions == 1);
}

static void testInvalidFramesDoNotStrandValidTraffic() {
    TransmitQueues queues;
    for (uint32_t i = 0; i < ALFA_FRAME_QUEUE_CAPACITY - 1; ++i) {
        auto packet = frame(64, i);
        assert(queues.frames.push(packet.data(), packet.size()));
    }
    queues.submit(0, false);
    queues.submit(99);
    queues.drain();
    assert(queues.frames.count == ALFA_FRAME_QUEUE_CAPACITY - 1);
    assert(queues.submission.size() == 1 && queues.drops == 1);
    queues.drain();
    assert(queues.frames.freeSlots() == 0 && queues.submission.empty());
    for (uint32_t i = 0; i < ALFA_FRAME_QUEUE_CAPACITY - 1; ++i) queues.frames.pop();
    assert(queues.frames.peek()->bytes[0] == 99);
    queues.frames.pop();

    for (uint32_t i = 0; i < ALFA_FRAME_QUEUE_CAPACITY; ++i) queues.submit(0, false);
    queues.submit(100);
    queues.drain();
    assert(queues.frames.peek() == nullptr && queues.submission.size() == 1);
    queues.drain();
    assert(queues.frames.peek()->bytes[0] == 100 && queues.submission.empty());
    assert(queues.drops == ALFA_FRAME_QUEUE_CAPACITY + 1);
}

static void testDisconnectCompletesPendingPacketsAndReleasesCapacity() {
    TransmitQueues queues;
    for (uint32_t i = 0; i < 2 * ALFA_FRAME_QUEUE_CAPACITY; ++i) queues.submit(i);
    queues.drain();
    queues.frames.clear();
    queues.drain(false);
    assert(queues.submission.empty() && queues.frames.count == 0);
    assert(queues.drops == ALFA_FRAME_QUEUE_CAPACITY);
    for (const auto &packet : queues.owned) assert(packet.completions == 1);
    queues.submit(200);
    queues.drain();
    assert(queues.frames.peek()->bytes[0] == 200);
}

int main() {
    testTransmitBackpressure();
    testInvalidFramesDoNotStrandValidTraffic();
    testDisconnectCompletesPendingPacketsAndReleasesCapacity();
    const char *expectedApplication = "TESTTEAM01.com.example.AlfaWiFi";
    const char *expectedTeam = "TESTTEAM01";
    auto authorized = [&](const char *application, const char *team) {
        return AlfaAuthorizedIdentity(application, application ? strlen(application) : 0,
            team, team ? strlen(team) : 0, expectedApplication, expectedTeam);
    };
    assert(authorized(expectedApplication, expectedTeam));
    assert(!authorized(nullptr, expectedTeam));
    assert(!authorized(expectedApplication, nullptr));
    assert(!authorized(expectedApplication, "OTHERTEAM1"));
    assert(!authorized("OTHERTEAM1.com.example.AlfaWiFi", expectedTeam));
    assert(!authorized("TESTTEAM01.com.example.AlfaWiFi.malicious", expectedTeam));
    assert(!authorized("TESTTEAM01.other.application", expectedTeam));
    assert(!authorized("", ""));
    const char embeddedNull[] = "TESTTEAM01.com.example.AlfaWiFi\0suffix";
    assert(!AlfaAuthorizedIdentity(embeddedNull, sizeof(embeddedNull) - 1,
        expectedTeam, strlen(expectedTeam), expectedApplication, expectedTeam));
    static_assert(offsetof(AlfaStatus, txDrops) == 24, "Status alignment");
    static_assert(offsetof(AlfaStatus, rxDrops) == 32, "Status alignment");
    const uint8_t goodMAC[] = {2, 1, 2, 3, 4, 5};
    const uint8_t zeroMAC[] = {0, 0, 0, 0, 0, 0};
    const uint8_t groupMAC[] = {1, 1, 2, 3, 4, 5};
    assert(AlfaValidMAC(goodMAC));
    assert(!AlfaValidMAC(zeroMAC));
    assert(!AlfaValidMAC(groupMAC));
    assert(!AlfaValidFrame(nullptr, 14));
    for (size_t size = 0; size <= ALFA_MAX_FRAME_SIZE + 1; ++size) {
        auto bytes = frame(size, 0);
        assert(AlfaValidFrame(bytes.data(), size) == (size >= 14 && size <= 1514));
    }
    auto bytes = frame(64, 0);
    bytes[12] = 0x88; bytes[13] = 0x8e;
    assert(!AlfaValidFrame(bytes.data(), bytes.size()));
    bytes[12] = 0x81; bytes[13] = 0x00;
    assert(!AlfaValidFrame(bytes.data(), bytes.size()));
    bytes[12] = 0x08; bytes[13] = 0x06;
    assert(AlfaValidFrame(bytes.data(), bytes.size()));
    bytes[12] = 0x86; bytes[13] = 0xdd;
    assert(AlfaValidFrame(bytes.data(), bytes.size()));

    AlfaFrameQueue queue = {};
    assert(queue.peek() == nullptr);
    queue.pop();
    for (size_t i = 0; i < 64; ++i) {
        auto packet = frame(14 + i, static_cast<uint8_t>(i));
        assert(queue.push(packet.data(), packet.size()));
    }
    assert(!queue.push(bytes.data(), bytes.size()));
    for (size_t i = 0; i < 64; ++i) {
        assert(queue.peek()->length == 14 + i);
        assert(queue.peek()->bytes[0] == i);
        queue.pop();
    }
    assert(queue.peek() == nullptr);

    std::mt19937 random(3070);
    std::deque<std::vector<uint8_t>> reference;
    for (size_t step = 0; step < 50000; ++step) {
        switch (random() % 4) {
        case 0:
        case 1: {
            auto packet = frame(14 + random() % 1501, static_cast<uint8_t>(random()));
            const bool accepted = reference.size() < 64;
            assert(queue.push(packet.data(), packet.size()) == accepted);
            if (accepted) reference.push_back(packet);
            break;
        }
        case 2:
            if (reference.empty()) assert(queue.peek() == nullptr);
            else {
                assert(queue.peek()->length == reference.front().size());
                assert(memcmp(queue.peek()->bytes, reference.front().data(), reference.front().size()) == 0);
                reference.pop_front();
            }
            queue.pop();
            break;
        case 3:
            if (random() % 20 == 0) {
                queue.clear();
                reference.clear();
                for (const auto &slot : queue.frames) {
                    assert(slot.length == 0);
                    for (uint8_t byte : slot.bytes) assert(byte == 0);
                }
            }
            break;
        }
        assert(queue.count == reference.size());
    }
}
