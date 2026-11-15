#include "virtual_controller/LaserCubeVirtualControllerHost.hpp"
#include "virtual_controller/VirtualControllerHostRegistry.hpp"

#include "libera/core/ByteRead.hpp"
#include "libera/lasercubenet/LaserCubeNetConfig.hpp"
#include "libera/lasercubenet/LaserCubeNetController.hpp"
#include "libera/lasercubenet/LaserCubeNetControllerInfo.hpp"
#include "libera/lasercubenet/LaserCubeNetStatus.hpp"
#include "libera/net/NetConfig.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

using namespace std::chrono_literals;
namespace vc = libera_link::virtual_controller;
using libera::net::udp;

namespace {

int g_failures = 0;

#define ASSERT_TRUE(cond, msg) \
    do { if (!(cond)) { std::fprintf(stderr, "ASSERT TRUE FAILED: %s @ %s:%d\n", (msg), __FILE__, __LINE__); ++g_failures; } } while (0)

#define ASSERT_EQ(a, b, msg) \
    do { auto _va = (a); auto _vb = (b); if (!((_va) == (_vb))) { \
        std::fprintf(stderr, "ASSERT EQ FAILED: %s lhs=%lld rhs=%lld @ %s:%d\n", \
                     (msg), static_cast<long long>(_va), static_cast<long long>(_vb), __FILE__, __LINE__); \
        ++g_failures; \
    } } while (0)

#define ASSERT_NEAR(a, b, eps, msg) \
    do { const double _va = (a); const double _vb = (b); if (std::fabs(_va - _vb) > (eps)) { \
        std::fprintf(stderr, "ASSERT NEAR FAILED: %s lhs=%f rhs=%f @ %s:%d\n", \
                     (msg), _va, _vb, __FILE__, __LINE__); \
        ++g_failures; \
    } } while (0)

class RecordingSink final : public vc::TargetSink {
public:
    explicit RecordingSink(std::string id, std::uint32_t maxPointRate = 100000) {
        info_.id = std::move(id);
        info_.label = "Recording target";
        info_.type = "test";
        info_.maxPointRate = maxPointRate;
    }

    const vc::TargetInfo& targetInfo() const override { return info_; }

    vc::SubmissionResult submitContinuous(vc::SliceSubmission submission) override {
        std::lock_guard<std::mutex> lock(mutex_);
        received_.insert(received_.end(), submission.points.begin(), submission.points.end());
        observedRate_ = submission.effectivePointRate.value_or(0);
        cv_.notify_all();
        vc::SubmissionResult result;
        result.accepted = true;
        result.submittedPoints = submission.points.size();
        result.acceptedPoints = submission.points.size();
        return result;
    }

    vc::SubmissionResult replaceFrame(vc::FrameSubmission) override { return {}; }
    vc::SubmissionResult submitFrame(vc::FrameSubmission) override { return {}; }
    void setScannerSync(std::int64_t, bool) override {}
    vc::TargetStatus status() const override { return {}; }
    void reset() override {}

    bool waitFor(std::chrono::milliseconds timeout,
                 const std::function<bool(const std::vector<libera::core::LaserPoint>&)>& predicate) {
        std::unique_lock<std::mutex> lock(mutex_);
        return cv_.wait_for(lock, timeout, [&] { return predicate(received_); });
    }

    std::vector<libera::core::LaserPoint> points() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return received_;
    }

    std::uint32_t observedRate() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return observedRate_;
    }

private:
    vc::TargetInfo info_;
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::vector<libera::core::LaserPoint> received_;
    std::uint32_t observedRate_ = 0;
};

std::unique_ptr<vc::VirtualControllerHost> createHost(
    std::unordered_map<std::string, std::string> options,
    const std::shared_ptr<RecordingSink>& sink,
    std::string& error) {
    vc::ensureBuiltInLaserCubeVirtualControllerHostLinked();
    vc::VirtualControllerHostConfig config;
    config.sliceDurationUs = 1000;
    config.options = std::move(options);
    auto host = vc::createVirtualControllerHost("lasercube", config, error);
    if (!host) {
        return nullptr;
    }
    vc::VirtualControllerHostContext context;
    context.targets.push_back(vc::Target{sink});
    if (!host->start(context, error)) {
        return nullptr;
    }
    return host;
}

/// Minimal blocking UDP client for driving the virtual device.
class Client {
public:
    Client() : socket_(io_) {
        socket_.open(udp::v4());
        socket_.bind(udp::endpoint(asio::ip::make_address_v4("127.0.0.1"), 0));
    }

    void send(const std::string& address, std::uint16_t port, const std::vector<std::uint8_t>& bytes) {
        socket_.send_to(asio::buffer(bytes), udp::endpoint(asio::ip::make_address_v4(address), port));
    }

    std::optional<std::vector<std::uint8_t>> receive(std::chrono::milliseconds timeout, udp::endpoint* from = nullptr) {
        std::vector<std::uint8_t> buffer(2048);
        udp::endpoint sender;
        std::optional<std::size_t> received;
        socket_.async_receive_from(asio::buffer(buffer), sender,
                                   [&](const std::error_code& ec, std::size_t size) {
                                       if (!ec) {
                                           received = size;
                                       }
                                   });
        io_.restart();
        io_.run_for(timeout);
        if (!received) {
            socket_.cancel();
            io_.restart();
            io_.run();
            return std::nullopt;
        }
        if (from != nullptr) {
            *from = sender;
        }
        buffer.resize(*received);
        return buffer;
    }

private:
    asio::io_context io_;
    udp::socket socket_;
};

std::vector<std::uint8_t> le32(std::uint8_t command, std::uint32_t value) {
    return {command,
            static_cast<std::uint8_t>(value & 0xffu),
            static_cast<std::uint8_t>((value >> 8) & 0xffu),
            static_cast<std::uint8_t>((value >> 16) & 0xffu),
            static_cast<std::uint8_t>((value >> 24) & 0xffu)};
}

void appendU16(std::vector<std::uint8_t>& out, std::uint16_t value) {
    out.push_back(static_cast<std::uint8_t>(value & 0xffu));
    out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xffu));
}

void testProtocol() {
    constexpr std::uint16_t alivePort = 46456;
    constexpr std::uint16_t commandPort = 46457;
    constexpr std::uint16_t dataPort = 46458;
    auto sink = std::make_shared<RecordingSink>("helios:test-1");
    std::string error;
    auto host = createHost({
        {"addresses", "127.0.0.1"},
        {"alive_port", std::to_string(alivePort)},
        {"command_port", std::to_string(commandPort)},
        {"data_port", std::to_string(dataPort)},
        // Probes sent to 127.0.0.2 reach the wildcard discovery socket rather
        // than the device socket bound to 127.0.0.1.
        {"discovery_bind_addresses", "0.0.0.0"},
        {"model_name", "Virtual Cube"},
        {"buffer_capacity", "1000"},
        {"max_point_rate", "50000"},
    }, sink, error);
    ASSERT_TRUE(host != nullptr, error.c_str());
    if (!host) {
        return;
    }

    const auto endpoints = host->endpoints();
    ASSERT_EQ(endpoints.size(), std::size_t{1}, "one endpoint per target");
    ASSERT_TRUE(endpoints[0].protocol == "LaserCube", "endpoint protocol");
    ASSERT_TRUE(endpoints[0].value == "127.0.0.1:46458", "endpoint value is the data socket");
    ASSERT_TRUE(vc::isVirtualLaserCubeSerial(endpoints[0].attributes.at("serial")),
                "endpoint serial uses the virtual prefix");

    Client client;

    // Discovery through the shared listener: the reply must come from the
    // device's own address and parse as a LaserCube status packet.
    client.send("127.0.0.2", commandPort, {0x77});
    udp::endpoint from;
    auto reply = client.receive(1000ms, &from);
    ASSERT_TRUE(reply.has_value(), "full info reply via discovery listener");
    if (reply) {
        ASSERT_EQ(reply->size(), std::size_t{64}, "full info is 64 bytes");
        ASSERT_TRUE(from.address().to_string() == "127.0.0.1", "reply source is the device address");
        ASSERT_EQ(from.port(), commandPort, "reply source port is the command port");
        const auto status = libera::lasercubenet::LaserCubeNetStatus::parse(reply->data(), reply->size());
        ASSERT_TRUE(status.has_value(), "Libera parses the status packet");
        if (status) {
            ASSERT_TRUE(status->modelName == "Virtual Cube", "model name");
            ASSERT_TRUE(status->serialNumber == endpoints[0].attributes.at("serial"), "serial matches endpoint");
            ASSERT_TRUE(status->ipAddress == "127.0.0.1", "status packet IP");
            ASSERT_EQ(status->bufferMax, 1000, "buffer capacity");
            ASSERT_EQ(status->bufferFree, 1000, "empty buffer");
            ASSERT_EQ(status->pointRateMax, 50000u, "max point rate");
            ASSERT_TRUE(status->outputEnabled, "output enabled at start");
            ASSERT_EQ(status->modelNumber, 6, "model number of a Cube2 Ultra");
            ASSERT_TRUE(status->firmwareVersion == "0.23", "firmware version of a real cube");
        }
    }

    // LaserOS discovery: ALIVE (0x27) on the alive port, answered with
    // [0x27, 0x00] from the device's alive port. Both unicast and through the
    // shared broadcast listener.
    for (const char* destination : {"127.0.0.1", "127.0.0.2"}) {
        client.send(destination, alivePort, {0x27});
        from = {};
        auto alive = client.receive(1000ms, &from);
        ASSERT_TRUE(alive.has_value(), "alive reply");
        if (alive) {
            ASSERT_EQ(alive->size(), std::size_t{2}, "alive reply is two bytes");
            ASSERT_EQ((*alive)[0], 0x27, "alive reply command");
            ASSERT_EQ((*alive)[1], 0x00, "alive reply status");
            ASSERT_TRUE(from.address().to_string() == "127.0.0.1", "alive reply from the device address");
            ASSERT_EQ(from.port(), alivePort, "alive reply from the alive port");
        }
    }
    // An alive reply from another cube must not be answered.
    client.send("127.0.0.1", alivePort, {0x27, 0x00});
    ASSERT_TRUE(!client.receive(200ms).has_value(), "alive replies are not answered");

    // A 64-byte status packet (another cube's reply) must not be answered.
    {
        std::vector<std::uint8_t> foreignStatus(64, 0);
        foreignStatus[0] = 0x77;
        client.send("127.0.0.1", commandPort, foreignStatus);
        ASSERT_TRUE(!client.receive(200ms).has_value(), "status packets are not answered");
    }

    // Commands are idempotent and acknowledged.
    for (int i = 0; i < 2; ++i) {
        client.send("127.0.0.1", commandPort, le32(0x82, 20000));
        auto ack = client.receive(500ms);
        ASSERT_TRUE(ack && ack->size() == 2 && (*ack)[0] == 0x82, "set rate ack");
    }
    client.send("127.0.0.1", commandPort, {0x83});
    if (auto rate = client.receive(500ms); rate && rate->size() == 6) {
        ASSERT_EQ(libera::core::bytes::readLe32(rate->data() + 2), 20000u, "rate was applied");
    } else {
        ASSERT_TRUE(false, "get rate reply");
    }

    // Sample data: acked on the data socket with the message number and free space.
    std::vector<std::uint8_t> packet{0xa9, 0x00, 0x2a, 0x01};
    constexpr int pointCount = 100;
    for (int i = 0; i < pointCount; ++i) {
        appendU16(packet, 4095);  // x: right edge on the wire (mirrored by default)
        appendU16(packet, 0);     // y: bottom
        appendU16(packet, 4095);  // r
        appendU16(packet, 0);     // g
        appendU16(packet, 2048);  // b
    }
    client.send("127.0.0.1", dataPort, packet);
    from = {};
    auto ack = client.receive(500ms, &from);
    ASSERT_TRUE(ack.has_value(), "sample data ack");
    if (ack) {
        ASSERT_EQ(ack->size(), std::size_t{4}, "ack size");
        ASSERT_EQ((*ack)[0], 0x8a, "ack command");
        ASSERT_EQ((*ack)[1], 0x2a, "ack echoes message number");
        ASSERT_TRUE(libera::core::bytes::readLe16(ack->data() + 2) <= 1000 - pointCount + 20,
                    "ack reports reduced free space");
        ASSERT_EQ(from.port(), dataPort, "ack source port is the data port");
    }

    const bool played = sink->waitFor(2000ms, [&](const auto& points) {
        return points.size() >= static_cast<std::size_t>(pointCount);
    });
    ASSERT_TRUE(played, "buffered points are played out to the target");
    const auto points = sink->points();
    if (!points.empty()) {
        ASSERT_NEAR(points[0].x, -1.0, 1e-3, "x mirrored like a LaserCube");
        ASSERT_NEAR(points[0].y, -1.0, 1e-3, "y decoded");
        ASSERT_NEAR(points[0].r, 1.0, 1e-3, "red");
        ASSERT_NEAR(points[0].g, 0.0, 1e-3, "green");
        ASSERT_NEAR(points[0].b, 2048.0 / 4095.0, 1e-3, "blue");
        ASSERT_NEAR(points[0].i, 1.0, 1e-3, "intensity for lit points");
    }
    ASSERT_EQ(sink->observedRate(), 20000u, "playback uses the client's point rate");

    // Output off blanks colours but keeps the timeline.
    client.send("127.0.0.1", commandPort, {0x80, 0x00});
    ASSERT_TRUE(client.receive(500ms).has_value(), "set output ack");
    packet[2] = 0x2b;
    client.send("127.0.0.1", dataPort, packet);
    (void)client.receive(500ms);
    const bool blanked = sink->waitFor(2000ms, [&](const auto& all) {
        return all.size() >= static_cast<std::size_t>(2 * pointCount);
    });
    ASSERT_TRUE(blanked, "points still play with output disabled");
    const auto after = sink->points();
    if (after.size() >= static_cast<std::size_t>(2 * pointCount)) {
        ASSERT_NEAR(after.back().r, 0.0, 1e-6, "blanked while output disabled");
        ASSERT_NEAR(after.back().b, 0.0, 1e-6, "blanked while output disabled");
    }

    // Disabling buffer responses suppresses acks.
    client.send("127.0.0.1", commandPort, {0x78, 0x00});
    (void)client.receive(500ms);
    client.send("127.0.0.1", dataPort, packet);
    ASSERT_TRUE(!client.receive(300ms).has_value(), "no ack when buffer response disabled");

    host->stop();
    ASSERT_TRUE(!host->running(), "host stopped");

    // Restart on the same ports works (sockets were released).
    auto restarted = createHost({
        {"addresses", "127.0.0.1"},
        {"alive_port", std::to_string(alivePort)},
        {"command_port", std::to_string(commandPort)},
        {"data_port", std::to_string(dataPort)},
        {"discovery", "false"},
    }, sink, error);
    ASSERT_TRUE(restarted != nullptr, error.c_str());
}

/// Drive the virtual device with Libera's own LaserCube Net client, which
/// mirrors what LaserCube software does on the wire.
void testWithLiberaLaserCubeClient() {
    using libera::lasercubenet::LaserCubeNetConfig;
    if (!asio::ip::make_address_v4("127.0.0.1").is_loopback()) {
        return;
    }

    auto sink = std::make_shared<RecordingSink>("helios:test-2");
    std::string error;
    auto host = createHost({
        {"addresses", "127.0.0.1"},
        {"discovery", "false"},
    }, sink, error);
    if (!host) {
        std::fprintf(stderr, "Skipping LaserCube client test: %s\n", error.c_str());
        return;
    }

    Client probe;
    probe.send("127.0.0.1", LaserCubeNetConfig::COMMAND_PORT, {LaserCubeNetConfig::CMD_GET_FULL_INFO});
    auto reply = probe.receive(1000ms);
    ASSERT_TRUE(reply.has_value(), "full info on standard port");
    if (!reply) {
        return;
    }
    auto status = libera::lasercubenet::LaserCubeNetStatus::parse(reply->data(), reply->size());
    ASSERT_TRUE(status.has_value(), "status parses");
    if (!status) {
        return;
    }
    status->ipAddress = "127.0.0.1";

    libera::lasercubenet::LaserCubeNetControllerInfo info(*status);
    libera::lasercubenet::LaserCubeNetController controller(info);
    controller.setRequestPointsCallback(
        [](const libera::core::PointFillRequest& request, std::vector<libera::core::LaserPoint>& out) {
            for (std::size_t i = 0; i < request.maximumPointsRequired; ++i) {
                libera::core::LaserPoint point;
                point.x = 0.5f;
                point.y = -0.25f;
                point.r = 0.0f;
                point.g = 1.0f;
                point.b = 0.0f;
                point.i = 1.0f;
                out.push_back(point);
            }
        });
    static_cast<libera::core::LaserControllerStreaming&>(controller).setPointRate(25000);
    auto connected = controller.connect(info);
    ASSERT_TRUE(static_cast<bool>(connected), "client connects");
    controller.setArmed(true);
    controller.startThread();

    const bool gotLitPoints = sink->waitFor(3000ms, [](const auto& points) {
        return std::count_if(points.begin(), points.end(), [](const auto& p) { return p.g > 0.5f; }) > 500;
    });
    controller.stopThread();
    controller.close();

    ASSERT_TRUE(gotLitPoints, "points from the Libera LaserCube client reach the target");
    for (const auto& point : sink->points()) {
        if (point.g > 0.5f) {
            ASSERT_NEAR(point.x, 0.5, 2e-3, "x round-trips through the LaserCube mirror");
            ASSERT_NEAR(point.y, -0.25, 2e-3, "y round-trips");
            break;
        }
    }
    ASSERT_EQ(sink->observedRate(), 25000u, "client point rate applied");
    const auto bufferState = controller.getBufferState();
    ASSERT_TRUE(bufferState.has_value(), "client tracks buffer state from acks");
}

std::optional<libera::lasercubenet::LaserCubeNetStatus> queryStatus(std::uint16_t commandPort) {
    Client client;
    client.send("127.0.0.1", commandPort, {0x77});
    auto reply = client.receive(1000ms);
    if (!reply) {
        return std::nullopt;
    }
    return libera::lasercubenet::LaserCubeNetStatus::parse(reply->data(), reply->size());
}

/// The reported max point rate follows the linked controller, limited by the
/// optional max_point_rate cap, and the default name is "Virtual LaserCube".
void testMaxPointRateAndName() {
    struct Case {
        std::uint32_t targetMax;
        const char* cap;
        std::uint32_t expected;
        const char* label;
    };
    const Case cases[] = {
        {100000, nullptr, 100000, "uses the linked controller's max rate"},
        {0, nullptr, 35000, "falls back when the controller reports no max rate"},
        {100000, "35000", 35000, "cap limits the controller's max rate"},
        {20000, "35000", 20000, "cap does not raise a lower controller max rate"},
    };
    for (const auto& c : cases) {
        auto sink = std::make_shared<RecordingSink>("helios:rate", c.targetMax);
        std::unordered_map<std::string, std::string> options{
            {"addresses", "127.0.0.1"},
            {"alive_port", "47456"},
            {"command_port", "47457"},
            {"data_port", "47458"},
            {"discovery", "false"},
        };
        if (c.cap != nullptr) {
            options["max_point_rate"] = c.cap;
        }
        std::string error;
        auto host = createHost(options, sink, error);
        ASSERT_TRUE(host != nullptr, error.c_str());
        if (!host) {
            continue;
        }
        const auto status = queryStatus(47457);
        ASSERT_TRUE(status.has_value(), "status reply");
        if (status) {
            ASSERT_EQ(status->pointRateMax, c.expected, c.label);
            ASSERT_TRUE(status->pointRate <= c.expected, "default rate within max");
            ASSERT_TRUE(status->modelName == "Virtual LaserCube", "default model name");
        }
        ASSERT_TRUE(host->endpoints().at(0).attributes.at("max_point_rate") == std::to_string(c.expected),
                    "endpoint reports the effective max rate");
        host->stop();
    }
}

void testSerialFilter() {
    ASSERT_TRUE(vc::isVirtualLaserCubeSerial("4C4C4B010203"), "virtual prefix");
    ASSERT_TRUE(vc::isVirtualLaserCubeSerial("4c4c4b010203"), "case insensitive");
    ASSERT_TRUE(!vc::isVirtualLaserCubeSerial("A1B2C3D4E5F6"), "real serial");
    ASSERT_TRUE(!vc::isVirtualLaserCubeSerial("4C4C"), "too short");
}

} // namespace

int main() {
    testSerialFilter();
    testProtocol();
    testMaxPointRateAndName();
    testWithLiberaLaserCubeClient();

    if (g_failures != 0) {
        std::fprintf(stderr, "LaserCube virtual controller host tests failed: %d\n", g_failures);
        return 1;
    }
    std::printf("LaserCube virtual controller host tests passed.\n");
    return 0;
}
