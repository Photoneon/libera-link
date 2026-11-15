#include "virtual_controller/LaserCubeVirtualControllerHost.hpp"

#include "virtual_controller/VirtualControllerHostRegistry.hpp"
#include "virtual_controller/VirtualControllerHostSupport.hpp"

#include "libera/core/ByteBuffer.hpp"
#include "libera/core/ByteRead.hpp"
#include "libera/log/Log.hpp"
#include "libera/net/NetConfig.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cctype>
#include <cstdint>
#include <deque>
#include <functional>
#include <iomanip>
#include <memory>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace libera_link::virtual_controller {
namespace {

// LaserCube / LaserDock network protocol, device side.
//
// UDP alive port (45456):
//   - LaserOS broadcasts ALIVE (0x27) to the subnet broadcast address from
//     its own port 45456 about twice a second. A LaserCube answers [0x27, 0x00]
//     from its port 45456 to the sender. This is how LaserOS finds devices.
// UDP command port (45457):
//   - Clients broadcast GET_FULL_INFO (0x77). Each device answers with a
//     64-byte status packet from its own address. The client takes the
//     device address from the reply's source address.
//   - Control commands are [cmd, payload...]. Some clients send each one
//     twice, so every handler is idempotent. Devices answer with
//     [cmd, 0x00, value...].
// UDP data port (45458):
//   - SAMPLE_DATA (0xA9): [0xA9, 0x00, messageNumber, frameNumber] followed
//     by 10-byte points: x, y, r, g, b as little-endian 12-bit values in
//     16-bit slots.
//   - The device acks each packet with
//     [0x8A, messageNumber, ringBufferFree (LE16)]. Clients pace on it.
//     ENABLE_BUFFER_RESPONSE (0x78) turns the ack on or off.

using libera::core::LaserPoint;
using libera::net::udp;
namespace asio = libera::net::asio;
using namespace std::chrono_literals;

constexpr std::uint8_t cmdAlive = 0x27;
constexpr std::uint8_t cmdGetFullInfo = 0x77;
constexpr std::uint8_t cmdEnableBufferResponse = 0x78;
constexpr std::uint8_t cmdSetOutput = 0x80;
constexpr std::uint8_t cmdGetOutput = 0x81;
constexpr std::uint8_t cmdSetIldaRate = 0x82;
constexpr std::uint8_t cmdGetIldaRate = 0x83;
constexpr std::uint8_t cmdGetMaxIldaRate = 0x84;
constexpr std::uint8_t cmdGetRingBufferSampleCount = 0x89;
constexpr std::uint8_t cmdGetRingBufferFree = 0x8a;
constexpr std::uint8_t cmdGetVersionMajor = 0x8b;
constexpr std::uint8_t cmdGetVersionMinor = 0x8c;
constexpr std::uint8_t cmdClearRingBuffer = 0x8d;
constexpr std::uint8_t cmdSampleData = 0xa9;

constexpr std::uint16_t defaultAlivePort = 45456;
constexpr std::uint16_t defaultCommandPort = 45457;
constexpr std::uint16_t defaultDataPort = 45458;
constexpr std::size_t fullInfoSize = 64;
constexpr std::size_t fullInfoModelNameOffset = 38;
constexpr std::size_t sampleHeaderSize = 4;
constexpr std::size_t bytesPerPoint = 10;
constexpr std::size_t maxDatagramSize = 2048;
// GET_FULL_INFO and ALIVE requests are a single byte. Replies from other
// LaserCubes (or our own, looped back) are longer and must be ignored.
constexpr std::size_t maxFullInfoRequestSize = 4;
constexpr std::size_t maxAliveRequestSize = 1;

struct HostOptions {
    support::IpAliasOptions alias;
    bool discoveryEnabled = true;
    bool discoveryBindAuto = true;
    std::vector<std::string> discoveryBindAddresses;
    std::uint16_t alivePort = defaultAlivePort;
    std::uint16_t commandPort = defaultCommandPort;
    std::uint16_t dataPort = defaultDataPort;
    std::uint16_t bufferCapacity = 6000;
    /// Upper limit for the reported max point rate; 0 means no limit.
    std::uint32_t maxPointRateCap = 0;
    /// Max point rate reported when the linked controller does not report one.
    std::uint32_t fallbackMaxPointRate = 35000;
    std::uint32_t defaultPointRate = 30000;
    std::string modelName = "Virtual LaserCube";
    std::uint8_t modelNumber = 6;
    std::uint8_t firmwareMajor = 0;
    std::uint8_t firmwareMinor = 23;
    std::uint8_t connectionType = 3;
    bool outputEnabledAtStart = true;
    bool flipX = true;
    bool flipY = false;
    std::uint32_t playbackSliceUs = 5000;
};

std::pair<std::uint8_t, std::uint8_t> parseFirmwareVersion(std::string_view text,
                                                           std::pair<std::uint8_t, std::uint8_t> fallback) {
    const auto dot = text.find('.');
    if (dot == std::string_view::npos) {
        return fallback;
    }
    const auto major = support::parseU32(support::trim(text.substr(0, dot)));
    const auto minor = support::parseU32(support::trim(text.substr(dot + 1)));
    if (!major || !minor || *major > 255 || *minor > 255) {
        return fallback;
    }
    return {static_cast<std::uint8_t>(*major), static_cast<std::uint8_t>(*minor)};
}

HostOptions makeHostOptions(const VirtualControllerHostConfig& config) {
    using namespace support;

    HostOptions options;
    options.alias.label = "LaserCube";
    options.alias.explicitAddresses = splitCsv(optionString(config, "addresses"));
    options.alias.ipMode = optionString(config, "ip_mode", "auto");
    options.alias.interfaceName = optionString(config, "interface");
    options.alias.baseAddress = optionString(config, "base_address");
    options.alias.autoManageAliases = optionBool(config, "auto_manage_aliases", true);
    options.alias.allowPrivilegePrompt = optionBool(config, "allow_privilege_prompt", true);
    // With no usable interface (e.g. Windows, where interfaces are not
    // enumerated), a single virtual LaserCube listens on all interfaces.
    options.alias.singleTargetFallbackAddress = "0.0.0.0";

    options.discoveryEnabled = optionBool(config, "discovery", options.discoveryEnabled);
    const auto bindIt = config.options.find("discovery_bind_addresses");
    if (bindIt != config.options.end()) {
        options.discoveryBindAuto = false;
        options.discoveryBindAddresses = splitCsv(bindIt->second);
    }
    options.alivePort = optionU16(config, "alive_port", options.alivePort);
    options.commandPort = optionU16(config, "command_port", options.commandPort);
    options.dataPort = optionU16(config, "data_port", options.dataPort);
    options.bufferCapacity = std::max<std::uint16_t>(
        bytesPerPoint, optionU16(config, "buffer_capacity", options.bufferCapacity));
    options.maxPointRateCap = optionU32(config, "max_point_rate", options.maxPointRateCap);
    if (options.maxPointRateCap > 0) {
        options.maxPointRateCap = std::max<std::uint32_t>(1000u, options.maxPointRateCap);
    }
    options.defaultPointRate = std::max<std::uint32_t>(
        1u, optionU32(config, "default_point_rate", options.defaultPointRate));
    options.modelName = optionString(config, "model_name", options.modelName);
    if (options.modelName.size() > fullInfoSize - fullInfoModelNameOffset - 1) {
        options.modelName.resize(fullInfoSize - fullInfoModelNameOffset - 1);
    }
    options.modelNumber = static_cast<std::uint8_t>(
        std::min<std::uint32_t>(255u, optionU32(config, "model_number", options.modelNumber)));
    const auto firmware = parseFirmwareVersion(
        optionString(config, "firmware_version"), {options.firmwareMajor, options.firmwareMinor});
    options.firmwareMajor = firmware.first;
    options.firmwareMinor = firmware.second;
    options.connectionType = static_cast<std::uint8_t>(
        std::min<std::uint32_t>(255u, optionU32(config, "connection_type", options.connectionType)));
    options.outputEnabledAtStart =
        optionBool(config, "output_enabled_at_start", options.outputEnabledAtStart);
    options.flipX = optionBool(config, "flip_x", options.flipX);
    options.flipY = optionBool(config, "flip_y", options.flipY);
    options.playbackSliceUs = std::clamp<std::uint32_t>(
        config.sliceDurationUs > 0 ? config.sliceDurationUs : options.playbackSliceUs, 1000u, 15000u);
    options.playbackSliceUs = std::max<std::uint32_t>(
        1000u, optionU32(config, "playback_slice_us", options.playbackSliceUs));

    const auto alivePort = options.alivePort;
    const auto commandPort = options.commandPort;
    const auto dataPort = options.dataPort;
    options.alias.canBind = [alivePort, commandPort, dataPort](const std::string& address) {
        return support::canBindUdpAddress(address, alivePort) &&
               support::canBindUdpAddress(address, commandPort) &&
               support::canBindUdpAddress(address, dataPort);
    };
    return options;
}

std::array<std::uint8_t, 6> makeSerial(const TargetInfo& targetInfo, std::size_t index) {
    const std::string& seed = !targetInfo.id.empty() ? targetInfo.id : targetInfo.label;
    // 0x4C 0x4C 0x4B ("LLK") marks Libera Link virtual LaserCubes.
    return {
        0x4cu,
        0x4cu,
        0x4bu,
        support::stableByteHash(seed, 0x21u),
        support::stableByteHash(seed, 0x45u),
        static_cast<std::uint8_t>((support::stableByteHash(seed, 0x69u) + index) & 0xffu),
    };
}

std::string formatSerial(const std::array<std::uint8_t, 6>& serial) {
    std::ostringstream out;
    out << std::uppercase << std::hex;
    for (const auto byte : serial) {
        out << std::setw(2) << std::setfill('0') << static_cast<unsigned>(byte);
    }
    return out.str();
}

float signedUnitFromU12(std::uint16_t raw) {
    const float value = static_cast<float>(std::min<std::uint16_t>(raw, 4095u)) / 4095.0f;
    return std::clamp(value * 2.0f - 1.0f, -1.0f, 1.0f);
}

float unitFromU12(std::uint16_t raw) {
    return static_cast<float>(std::min<std::uint16_t>(raw, 4095u)) / 4095.0f;
}

std::optional<asio::ip::address_v4> parseAddress(const std::string& text) {
    std::error_code ec;
    const auto address = asio::ip::make_address_v4(text, ec);
    if (ec) {
        return std::nullopt;
    }
    return address;
}

/// The IPv4 address to report in the status packet for a device listening on
/// address. A wildcard listener reports the default interface address.
std::array<std::uint8_t, 4> reportedAddressBytes(const std::string& address) {
    std::string reported = address;
    if (reported == "0.0.0.0") {
        reported.clear();
        const auto defaultIface = support::defaultInterfaceName();
        for (const auto& iface : support::interfaceAddresses()) {
            if (iface.loopback) {
                continue;
            }
            if (reported.empty() || (defaultIface && iface.name == *defaultIface)) {
                reported = iface.address;
            }
        }
    }
    std::array<std::uint8_t, 4> bytes{};
    if (const auto parsed = parseAddress(reported)) {
        bytes = parsed->to_bytes();
    }
    return bytes;
}

bool openUdpSocket(udp::socket& socket,
                   const asio::ip::address_v4& address,
                   std::uint16_t port,
                   std::string& error,
                   std::string_view what) {
    std::error_code ec;
    socket.open(udp::v4(), ec);
    if (!ec) {
        socket.set_option(asio::socket_base::reuse_address(true), ec);
    }
    if (!ec) {
        socket.set_option(asio::socket_base::broadcast(true), ec);
    }
    if (!ec) {
        socket.bind(udp::endpoint(address, port), ec);
    }
    if (ec) {
        error = "LaserCube " + std::string(what) + " socket bind failed for " +
                address.to_string() + ":" + std::to_string(port) + ": " + ec.message();
        if (ec == asio::error::address_in_use) {
            error += ". Another program (LaserOS, or Libera Link's own LaserCube Net "
                     "discovery) is using this port; disable LaserCube Net discovery in "
                     "Settings or run the virtual LaserCube on another machine.";
        }
        std::error_code ignored;
        socket.close(ignored);
        return false;
    }
    return true;
}

void sendDatagram(udp::socket& socket, const udp::endpoint& to, std::vector<std::uint8_t> bytes) {
    if (!socket.is_open()) {
        return;
    }
    auto packet = std::make_shared<std::vector<std::uint8_t>>(std::move(bytes));
    auto destination = std::make_shared<udp::endpoint>(to);
    socket.async_send_to(asio::buffer(*packet), *destination,
                         [packet, destination](const std::error_code&, std::size_t) {});
}

class VirtualLaserCube {
public:
    VirtualLaserCube(asio::io_context& io,
                     Target target,
                     std::string address,
                     std::array<std::uint8_t, 6> serial,
                     const HostOptions& options)
        : target_(std::move(target))
        , address_(std::move(address))
        , serial_(serial)
        , options_(options)
        , aliveSocket_(io)
        , commandSocket_(io)
        , dataSocket_(io)
        , playbackTimer_(io) {
        // Report the linked controller's max point rate, limited by the
        // optional max_point_rate cap.
        const auto targetMax = target_.sink ? target_.sink->targetInfo().maxPointRate : 0u;
        maxPointRate_ = targetMax > 0 ? targetMax : options_.fallbackMaxPointRate;
        if (options_.maxPointRateCap > 0) {
            maxPointRate_ = std::min(maxPointRate_, options_.maxPointRateCap);
        }
        resetState();
    }

    VirtualLaserCube(const VirtualLaserCube&) = delete;
    VirtualLaserCube& operator=(const VirtualLaserCube&) = delete;

    bool open(std::string& error) {
        const auto ip = parseAddress(address_);
        if (!ip) {
            error = "Invalid LaserCube listen address " + address_ + ".";
            return false;
        }
        if (!openUdpSocket(aliveSocket_, *ip, options_.alivePort, error, "alive")) {
            return false;
        }
        if (!openUdpSocket(commandSocket_, *ip, options_.commandPort, error, "command")) {
            close();
            return false;
        }
        if (!openUdpSocket(dataSocket_, *ip, options_.dataPort, error, "data")) {
            close();
            return false;
        }
        reportedAddress_ = reportedAddressBytes(address_);
        return true;
    }

    void start(std::function<bool(const udp::endpoint&)> isOwnEndpoint) {
        isOwnEndpoint_ = std::move(isOwnEndpoint);
        running_ = true;
        startAliveReceive();
        startCommandReceive();
        startDataReceive();
        startPlaybackTimer();
    }

    void close() {
        running_ = false;
        std::error_code ignored;
        aliveSocket_.close(ignored);
        commandSocket_.close(ignored);
        dataSocket_.close(ignored);
        (void)playbackTimer_.cancel();
    }

    /// Answer a GET_FULL_INFO probe that arrived on a shared discovery socket.
    void replyFullInfo(const udp::endpoint& to) {
        sendDatagram(commandSocket_, to, buildFullInfo());
    }

    /// Answer an ALIVE probe the way a LaserCube does: [0x27, 0x00] from the
    /// device's alive port.
    void replyAlive(const udp::endpoint& to) {
        if (aliveClients_.insert(to.address().to_string()).second) {
            libera::logInfo("[LaserCubeVirtual]", formatSerial(serial_),
                            "answering LaserCube software at", to.address().to_string());
        }
        sendDatagram(aliveSocket_, to, {cmdAlive, 0x00});
    }

    std::vector<udp::endpoint> localEndpoints() const {
        std::vector<udp::endpoint> result;
        for (const auto* socket : {&aliveSocket_, &commandSocket_, &dataSocket_}) {
            std::error_code ec;
            auto endpoint = socket->local_endpoint(ec);
            if (!ec) {
                result.push_back(endpoint);
            }
        }
        return result;
    }

    VirtualControllerEndpoint endpoint() const {
        VirtualControllerEndpoint endpoint;
        const auto& info = target_.sink->targetInfo();
        const std::string serial = formatSerial(serial_);
        endpoint.targetId = info.id;
        endpoint.label = "LaserCube " + serial;
        endpoint.value = address_ + ":" + std::to_string(options_.dataPort);
        endpoint.kind = "network-socket";
        endpoint.protocol = "LaserCube";
        endpoint.transport = "udp";
        endpoint.address = address_;
        endpoint.port = options_.dataPort;
        endpoint.attributes["serial"] = serial;
        endpoint.attributes["alive_port"] = std::to_string(options_.alivePort);
        endpoint.attributes["command_port"] = std::to_string(options_.commandPort);
        endpoint.attributes["data_port"] = std::to_string(options_.dataPort);
        endpoint.attributes["model_name"] = options_.modelName;
        endpoint.attributes["buffer_capacity"] = std::to_string(options_.bufferCapacity);
        endpoint.attributes["max_point_rate"] = std::to_string(maxPointRate_);
        return endpoint;
    }

private:
    std::uint16_t bufferFree() const {
        const auto used = std::min<std::size_t>(buffer_.size(), options_.bufferCapacity);
        return static_cast<std::uint16_t>(options_.bufferCapacity - used);
    }

    std::vector<std::uint8_t> buildFullInfo() const {
        std::vector<std::uint8_t> packet(fullInfoSize, 0);
        auto putLe16 = [&](std::size_t offset, std::uint16_t value) {
            packet[offset] = static_cast<std::uint8_t>(value & 0xffu);
            packet[offset + 1] = static_cast<std::uint8_t>((value >> 8) & 0xffu);
        };
        auto putLe32 = [&](std::size_t offset, std::uint32_t value) {
            for (std::size_t i = 0; i < 4; ++i) {
                packet[offset + i] = static_cast<std::uint8_t>((value >> (8 * i)) & 0xffu);
            }
        };

        packet[0] = cmdGetFullInfo;
        packet[1] = 0x00;
        packet[2] = 0x00; // payload version
        packet[3] = options_.firmwareMajor;
        packet[4] = options_.firmwareMinor;
        // Flags: bit 0 output enabled, bit 1 as reported by a real Cube2 Ultra.
        packet[5] = static_cast<std::uint8_t>(0x02u | (outputEnabled_ ? 0x01u : 0x00u));
        packet[8] = 0xff; // 0x0fff as reported by a real cube (likely the 12-bit DAC maximum)
        packet[9] = 0x0f;
        putLe32(10, pointRate_);
        putLe32(14, maxPointRate_);
        packet[18] = 0x03; // unknown, as reported by a real cube
        putLe16(19, bufferFree());
        putLe16(21, options_.bufferCapacity);
        packet[23] = 100; // battery percent
        packet[24] = 25;  // temperature in degrees C
        packet[25] = options_.connectionType;
        std::copy(serial_.begin(), serial_.end(), packet.begin() + 26);
        std::copy(reportedAddress_.begin(), reportedAddress_.end(), packet.begin() + 32);
        packet[36] = 0x02; // unknown, as reported by a real cube
        packet[37] = options_.modelNumber;
        std::copy(options_.modelName.begin(), options_.modelName.end(),
                  packet.begin() + static_cast<std::ptrdiff_t>(fullInfoModelNameOffset));
        return packet;
    }

    void startAliveReceive() {
        aliveSocket_.async_receive_from(
            asio::buffer(aliveBuffer_), aliveSender_,
            [this](const std::error_code& ec, std::size_t size) {
                if (!running_ || ec == asio::error::operation_aborted) {
                    return;
                }
                if (!ec && size > 0 && size <= maxAliveRequestSize && aliveBuffer_[0] == cmdAlive &&
                    !(isOwnEndpoint_ && isOwnEndpoint_(aliveSender_))) {
                    replyAlive(aliveSender_);
                }
                startAliveReceive();
            });
    }

    void startCommandReceive() {
        commandSocket_.async_receive_from(
            asio::buffer(commandBuffer_), commandSender_,
            [this](const std::error_code& ec, std::size_t size) {
                if (!running_ || ec == asio::error::operation_aborted) {
                    return;
                }
                if (!ec) {
                    handleCommand(commandBuffer_.data(), size, commandSender_);
                }
                startCommandReceive();
            });
    }

    void startDataReceive() {
        dataSocket_.async_receive_from(
            asio::buffer(dataBuffer_), dataSender_,
            [this](const std::error_code& ec, std::size_t size) {
                if (!running_ || ec == asio::error::operation_aborted) {
                    return;
                }
                if (!ec) {
                    handleData(dataBuffer_.data(), size, dataSender_);
                }
                startDataReceive();
            });
    }

    void reply(const udp::endpoint& to, std::uint8_t command, std::initializer_list<std::uint8_t> value = {}) {
        std::vector<std::uint8_t> packet{command, 0x00};
        packet.insert(packet.end(), value.begin(), value.end());
        sendDatagram(commandSocket_, to, std::move(packet));
    }

    void replyU16(const udp::endpoint& to, std::uint8_t command, std::uint16_t value) {
        reply(to, command, {static_cast<std::uint8_t>(value & 0xffu),
                            static_cast<std::uint8_t>((value >> 8) & 0xffu)});
    }

    void replyU32(const udp::endpoint& to, std::uint8_t command, std::uint32_t value) {
        reply(to, command, {static_cast<std::uint8_t>(value & 0xffu),
                            static_cast<std::uint8_t>((value >> 8) & 0xffu),
                            static_cast<std::uint8_t>((value >> 16) & 0xffu),
                            static_cast<std::uint8_t>((value >> 24) & 0xffu)});
    }

    void handleCommand(const std::uint8_t* data, std::size_t size, const udp::endpoint& sender) {
        if (size == 0 || (isOwnEndpoint_ && isOwnEndpoint_(sender))) {
            return;
        }

        const std::uint8_t command = data[0];
        switch (command) {
        case cmdGetFullInfo:
            if (size <= maxFullInfoRequestSize) {
                replyFullInfo(sender);
            }
            return;
        case cmdEnableBufferResponse:
            if (size >= 2) {
                bufferResponseEnabled_ = data[1] != 0;
            }
            reply(sender, command);
            return;
        case cmdSetOutput:
            if (size >= 2) {
                const bool enabled = data[1] != 0;
                if (enabled != outputEnabled_) {
                    libera::logInfo("[LaserCubeVirtual]", formatSerial(serial_),
                                    enabled ? "output enabled" : "output disabled");
                }
                outputEnabled_ = enabled;
            }
            reply(sender, command);
            return;
        case cmdGetOutput:
            reply(sender, command, {static_cast<std::uint8_t>(outputEnabled_ ? 1 : 0)});
            return;
        case cmdSetIldaRate:
            if (size >= 5) {
                const auto rate = libera::core::bytes::readLe32(&data[1]);
                setPointRate(rate);
            }
            reply(sender, command);
            return;
        case cmdGetIldaRate:
            replyU32(sender, command, pointRate_);
            return;
        case cmdGetMaxIldaRate:
            replyU32(sender, command, maxPointRate_);
            return;
        case cmdGetRingBufferSampleCount:
            replyU16(sender, command,
                     static_cast<std::uint16_t>(options_.bufferCapacity - bufferFree()));
            return;
        case cmdGetRingBufferFree:
            replyU16(sender, command, bufferFree());
            return;
        case cmdGetVersionMajor:
            replyU32(sender, command, options_.firmwareMajor);
            return;
        case cmdGetVersionMinor:
            replyU32(sender, command, options_.firmwareMinor);
            return;
        case cmdClearRingBuffer:
            buffer_.clear();
            resetPlaybackClock();
            reply(sender, command);
            return;
        default:
            if (unknownCommandsLogged_.insert(command).second) {
                libera::logInfo("[LaserCubeVirtual] unhandled command",
                                static_cast<int>(command), "size", size);
            }
            reply(sender, command);
            return;
        }
    }

    void setPointRate(std::uint32_t rate) {
        rate = std::clamp<std::uint32_t>(rate, 1u, maxPointRate_);
        if (rate != pointRate_) {
            pointRate_ = rate;
            resetPlaybackClock();
        }
    }

    void handleData(const std::uint8_t* data, std::size_t size, const udp::endpoint& sender) {
        if (size < sampleHeaderSize || data[0] != cmdSampleData) {
            if (size > 0 && data[0] != cmdSampleData &&
                unknownCommandsLogged_.insert(data[0]).second) {
                libera::logInfo("[LaserCubeVirtual] unexpected data packet",
                                static_cast<int>(data[0]), "size", size);
            }
            return;
        }

        const std::uint8_t messageNumber = data[2];
        const std::size_t pointCount = (size - sampleHeaderSize) / bytesPerPoint;
        const std::uint8_t* cursor = data + sampleHeaderSize;
        for (std::size_t i = 0; i < pointCount; ++i, cursor += bytesPerPoint) {
            if (buffer_.size() >= options_.bufferCapacity) {
                droppedPoints_ += pointCount - i;
                break;
            }
            LaserPoint point;
            const float x = signedUnitFromU12(libera::core::bytes::readLe16(cursor));
            const float y = signedUnitFromU12(libera::core::bytes::readLe16(cursor + 2));
            point.x = options_.flipX ? -x : x;
            point.y = options_.flipY ? -y : y;
            point.r = unitFromU12(libera::core::bytes::readLe16(cursor + 4));
            point.g = unitFromU12(libera::core::bytes::readLe16(cursor + 6));
            point.b = unitFromU12(libera::core::bytes::readLe16(cursor + 8));
            point.i = (point.r > 0.0f || point.g > 0.0f || point.b > 0.0f) ? 1.0f : 0.0f;
            buffer_.push_back(point);
        }

        if (bufferResponseEnabled_) {
            const std::uint16_t free = bufferFree();
            sendDatagram(dataSocket_, sender,
                         {cmdGetRingBufferFree,
                          messageNumber,
                          static_cast<std::uint8_t>(free & 0xffu),
                          static_cast<std::uint8_t>((free >> 8) & 0xffu)});
        }
    }

    void startPlaybackTimer() {
        playbackTimer_.expires_after(std::chrono::microseconds(options_.playbackSliceUs));
        playbackTimer_.async_wait([this](const std::error_code& ec) {
            if (ec || !running_) {
                return;
            }
            playbackTick();
            startPlaybackTimer();
        });
    }

    void resetPlaybackClock() {
        playbackClockValid_ = false;
        playbackAccumulator_ = 0.0;
    }

    void playbackTick() {
        if (buffer_.empty() || pointRate_ == 0) {
            resetPlaybackClock();
            return;
        }

        const auto now = std::chrono::steady_clock::now();
        if (!playbackClockValid_) {
            lastPlaybackAt_ = now;
            playbackClockValid_ = true;
            return;
        }

        const auto elapsed =
            std::chrono::duration_cast<std::chrono::microseconds>(now - lastPlaybackAt_);
        lastPlaybackAt_ = now;
        playbackAccumulator_ +=
            static_cast<double>(elapsed.count()) * static_cast<double>(pointRate_) / 1000000.0;
        const auto pointsDue = static_cast<std::size_t>(std::floor(playbackAccumulator_));
        if (pointsDue == 0) {
            return;
        }
        playbackAccumulator_ -= static_cast<double>(pointsDue);

        const auto toDrain = std::min<std::size_t>(pointsDue, buffer_.size());
        SliceSubmission submission;
        submission.points.reserve(toDrain);
        for (std::size_t i = 0; i < toDrain; ++i) {
            LaserPoint point = buffer_.front();
            buffer_.pop_front();
            if (!outputEnabled_) {
                point.r = point.g = point.b = point.i = 0.0f;
            }
            submission.points.push_back(point);
        }
        if (toDrain < pointsDue) {
            // Ring buffer ran dry; restart the clock when data arrives again.
            resetPlaybackClock();
        }

        if (!submission.points.empty() && target_.sink) {
            submission.effectivePointRate = pointRate_;
            submission.durationUs = static_cast<std::uint32_t>(std::max<double>(
                1.0,
                (1000000.0 * static_cast<double>(submission.points.size())) /
                    static_cast<double>(pointRate_)));
            target_.sink->submitContinuous(std::move(submission));
        }
    }

    void resetState() {
        buffer_.clear();
        pointRate_ = std::min(options_.defaultPointRate, maxPointRate_);
        outputEnabled_ = options_.outputEnabledAtStart;
        bufferResponseEnabled_ = true;
        droppedPoints_ = 0;
        resetPlaybackClock();
    }

    Target target_;
    std::string address_;
    std::array<std::uint8_t, 6> serial_;
    std::array<std::uint8_t, 4> reportedAddress_{};
    const HostOptions& options_;

    udp::socket aliveSocket_;
    udp::socket commandSocket_;
    udp::socket dataSocket_;
    asio::steady_timer playbackTimer_;
    std::array<std::uint8_t, maxDatagramSize> aliveBuffer_{};
    std::array<std::uint8_t, maxDatagramSize> commandBuffer_{};
    std::array<std::uint8_t, maxDatagramSize> dataBuffer_{};
    udp::endpoint aliveSender_;
    udp::endpoint commandSender_;
    udp::endpoint dataSender_;
    std::function<bool(const udp::endpoint&)> isOwnEndpoint_;
    bool running_ = false;

    // All state below is only touched on the host's io thread.
    std::deque<LaserPoint> buffer_;
    std::uint32_t maxPointRate_ = 35000;
    std::uint32_t pointRate_ = 30000;
    bool outputEnabled_ = true;
    bool bufferResponseEnabled_ = true;
    std::uint64_t droppedPoints_ = 0;
    std::set<std::uint8_t> unknownCommandsLogged_;
    std::set<std::string> aliveClients_;
    std::chrono::steady_clock::time_point lastPlaybackAt_{};
    double playbackAccumulator_ = 0.0;
    bool playbackClockValid_ = false;
};

/// Receives broadcast ALIVE or GET_FULL_INFO probes for all virtual LaserCubes. Device
/// sockets bound to a specific address do not see broadcasts on Linux or macOS,
/// so probes arrive here and every device answers from its own socket.
class DiscoveryListener {
public:
    DiscoveryListener(asio::io_context& io,
                      std::uint8_t command,
                      std::size_t maxRequestSize,
                      std::function<void(const udp::endpoint&)> onProbe,
                      std::function<bool(const udp::endpoint&)> isOwnEndpoint)
        : socket_(io)
        , command_(command)
        , maxRequestSize_(maxRequestSize)
        , onProbe_(std::move(onProbe))
        , isOwnEndpoint_(std::move(isOwnEndpoint)) {}

    bool open(const std::string& address, std::uint16_t port, std::string& error) {
        const auto ip = parseAddress(address);
        if (!ip) {
            error = "Invalid LaserCube discovery bind address " + address + ".";
            return false;
        }
        return openUdpSocket(socket_, *ip, port, error, "discovery");
    }

    void start() {
        running_ = true;
        startReceive();
    }

    void close() {
        running_ = false;
        std::error_code ignored;
        socket_.close(ignored);
    }

private:
    void startReceive() {
        socket_.async_receive_from(
            asio::buffer(buffer_), sender_,
            [this](const std::error_code& ec, std::size_t size) {
                if (!running_ || ec == asio::error::operation_aborted) {
                    return;
                }
                if (!ec && size > 0 && size <= maxRequestSize_ &&
                    buffer_[0] == command_ && !(isOwnEndpoint_ && isOwnEndpoint_(sender_))) {
                    onProbe_(sender_);
                }
                startReceive();
            });
    }

    udp::socket socket_;
    std::uint8_t command_;
    std::size_t maxRequestSize_;
    std::function<void(const udp::endpoint&)> onProbe_;
    std::function<bool(const udp::endpoint&)> isOwnEndpoint_;
    std::array<std::uint8_t, maxDatagramSize> buffer_{};
    udp::endpoint sender_;
    bool running_ = false;
};

/// Discovery bind addresses for the given device addresses. On Linux a socket
/// bound to a broadcast address receives only broadcasts, which leaves unicast
/// traffic on the port to other programs (e.g. a LaserCube client). Elsewhere a
/// wildcard socket is used; the more specific device sockets still win for
/// unicast to their own address.
std::vector<std::string> automaticDiscoveryBindAddresses(const std::vector<std::string>& deviceAddresses) {
    std::vector<std::string> result;
    for (const auto& address : deviceAddresses) {
        if (address == "0.0.0.0") {
            // A wildcard device socket already receives broadcasts itself.
            return {};
        }
    }
#if defined(__linux__)
    std::set<std::string> unique{"255.255.255.255"};
    result.push_back("255.255.255.255");
    const auto interfaces = support::interfaceAddresses();
    for (const auto& address : deviceAddresses) {
        const auto host = support::ipv4ToHost(address);
        if (!host) {
            continue;
        }
        for (const auto& iface : interfaces) {
            if (iface.loopback || iface.netmaskHost == 0) {
                continue;
            }
            if ((iface.addressHost & iface.netmaskHost) != (*host & iface.netmaskHost)) {
                continue;
            }
            if (!iface.broadcast.empty() && unique.insert(iface.broadcast).second) {
                result.push_back(iface.broadcast);
            }
        }
    }
#else
    result.push_back("0.0.0.0");
#endif
    return result;
}

VirtualControllerHostRegistrar gLaserCubeVirtualControllerHostRegistrar({
    {
        "lasercube",
        "LaserCube",
        "Expose linked controllers as network LaserCubes for LaserOS and other LaserCube software.",
        {
            {
                "ip_mode",
                "IP Mode",
                "Address selection: auto (this machine's address for one controller, IP aliases for "
                "more), alias (always IP aliases), loopback, or explicit addresses.",
                VirtualControllerHostOptionType::Choice,
                "auto",
                {"auto", "alias", "loopback", "explicit"},
                false,
            },
            {
                "addresses",
                "Addresses",
                "Comma-separated local IPv4 addresses, one per virtual LaserCube, instead of automatic "
                "selection.",
                VirtualControllerHostOptionType::String,
                "",
                {},
                false,
            },
            {
                "interface",
                "Interface",
                "Network interface to use for automatic addresses and IP aliases.",
                VirtualControllerHostOptionType::String,
                "",
                {},
                false,
            },
            {
                "auto_manage_aliases",
                "Auto IP Aliases",
                "Automatically add and remove local IP aliases when needed.",
                VirtualControllerHostOptionType::Boolean,
                "true",
                {},
                false,
            },
            {
                "model_name",
                "Model Name",
                "Model name reported to LaserCube software.",
                VirtualControllerHostOptionType::String,
                "Virtual LaserCube",
                {},
                false,
            },
            {
                "buffer_capacity",
                "Buffer Capacity",
                "Virtual ring buffer size in points.",
                VirtualControllerHostOptionType::Integer,
                "6000",
                {},
                false,
            },
            {
                "max_point_rate",
                "Max Point Rate",
                "Upper limit for the max point rate reported to LaserCube software. 0 reports the "
                "linked controller's own maximum (35000 when it reports none).",
                VirtualControllerHostOptionType::Integer,
                "0",
                {},
                false,
            },
        },
        false,
        false,
    },
    [](const VirtualControllerHostConfig& config) {
        return std::make_unique<LaserCubeVirtualControllerHost>(config);
    },
});

} // namespace

void ensureBuiltInLaserCubeVirtualControllerHostLinked() {}

bool isVirtualLaserCubeSerial(std::string_view serial) {
    if (serial.size() < virtualLaserCubeSerialPrefix.size()) {
        return false;
    }
    for (std::size_t i = 0; i < virtualLaserCubeSerialPrefix.size(); ++i) {
        if (std::toupper(static_cast<unsigned char>(serial[i])) != virtualLaserCubeSerialPrefix[i]) {
            return false;
        }
    }
    return true;
}

struct LaserCubeVirtualControllerHost::Impl {
    explicit Impl(HostOptions hostOptions)
        : options(std::move(hostOptions))
        , aliasManager(options.alias) {}

    bool isOwnEndpoint(const udp::endpoint& endpoint) const {
        for (const auto& own : ownEndpoints) {
            if (endpoint.port() != own.port()) {
                continue;
            }
            if (endpoint.address() == own.address() || own.address().is_unspecified()) {
                return true;
            }
        }
        return false;
    }

    void closeAll() {
        // Stop the io thread first so sockets are only touched from this thread.
        io.stop();
        if (ioThread.joinable()) {
            ioThread.join();
        }
        for (auto& listener : discovery) {
            listener->close();
        }
        for (auto& device : devices) {
            device->close();
        }
        // Drain the aborted handlers while the objects they reference still exist.
        io.restart();
        io.run();
        discovery.clear();
        devices.clear();
        ownEndpoints.clear();
        io.restart();
    }

    HostOptions options;
    support::IpAliasManager aliasManager;
    asio::io_context io;
    std::thread ioThread;
    std::vector<std::unique_ptr<VirtualLaserCube>> devices;
    std::vector<std::unique_ptr<DiscoveryListener>> discovery;
    std::vector<udp::endpoint> ownEndpoints;
    std::vector<VirtualControllerEndpoint> endpoints;
    std::atomic<bool> active{false};
};

LaserCubeVirtualControllerHost::LaserCubeVirtualControllerHost(const VirtualControllerHostConfig& config)
    : impl_(std::make_unique<Impl>(makeHostOptions(config))) {}

LaserCubeVirtualControllerHost::~LaserCubeVirtualControllerHost() {
    stop();
}

std::string_view LaserCubeVirtualControllerHost::name() const {
    return "lasercube";
}

std::string_view LaserCubeVirtualControllerHost::displayName() const {
    return "LaserCube";
}

bool LaserCubeVirtualControllerHost::start(const VirtualControllerHostContext& context,
                                           std::string& error) {
    if (!impl_) {
        error = "LaserCube virtual controller host not initialized.";
        return false;
    }
    if (running()) {
        error = "LaserCube virtual controller host is already running.";
        return false;
    }

    std::vector<Target> validTargets;
    for (const auto& target : context.targets) {
        if (target.sink) {
            validTargets.push_back(target);
        }
    }
    if (validTargets.empty()) {
        error = "No LaserCube targets were created.";
        return false;
    }

    std::vector<std::string> addresses;
    if (!impl_->aliasManager.allocate(validTargets.size(), addresses, error)) {
        return false;
    }

    auto fail = [&]() {
        impl_->closeAll();
        impl_->aliasManager.cleanup();
        return false;
    };

    for (std::size_t i = 0; i < validTargets.size(); ++i) {
        const auto serial = makeSerial(validTargets[i].sink->targetInfo(), i);
        auto device = std::make_unique<VirtualLaserCube>(
            impl_->io, validTargets[i], addresses[i], serial, impl_->options);
        if (!device->open(error)) {
            return fail();
        }
        for (const auto& local : device->localEndpoints()) {
            impl_->ownEndpoints.push_back(local);
        }
        impl_->devices.push_back(std::move(device));
    }

    if (impl_->options.discoveryEnabled) {
        const auto bindAddresses = impl_->options.discoveryBindAuto
            ? automaticDiscoveryBindAddresses(addresses)
            : impl_->options.discoveryBindAddresses;
        struct ProbeKind {
            std::uint16_t port;
            std::uint8_t command;
            std::size_t maxRequestSize;
            bool alive;
        };
        const ProbeKind kinds[] = {
            {impl_->options.alivePort, cmdAlive, maxAliveRequestSize, true},
            {impl_->options.commandPort, cmdGetFullInfo, maxFullInfoRequestSize, false},
        };
        for (const auto& bindAddress : bindAddresses) {
            for (const auto& kind : kinds) {
                const bool alive = kind.alive;
                auto listener = std::make_unique<DiscoveryListener>(
                    impl_->io,
                    kind.command,
                    kind.maxRequestSize,
                    [this, alive](const udp::endpoint& sender) {
                        for (auto& device : impl_->devices) {
                            if (alive) {
                                device->replyAlive(sender);
                            } else {
                                device->replyFullInfo(sender);
                            }
                        }
                    },
                    [this](const udp::endpoint& sender) { return impl_->isOwnEndpoint(sender); });
                std::string listenerError;
                if (!listener->open(bindAddress, kind.port, listenerError)) {
                    if (bindAddress != "255.255.255.255" && impl_->options.discoveryBindAuto) {
                        // Subnet broadcast binds are best effort.
                        libera::logInfo("[LaserCubeVirtual]", listenerError);
                        continue;
                    }
                    error = listenerError;
                    return fail();
                }
                impl_->discovery.push_back(std::move(listener));
            }
        }
    }

    std::vector<VirtualControllerEndpoint> endpoints;
    for (auto& device : impl_->devices) {
        device->start([this](const udp::endpoint& sender) { return impl_->isOwnEndpoint(sender); });
        endpoints.push_back(device->endpoint());
    }
    for (auto& listener : impl_->discovery) {
        listener->start();
    }

    impl_->ioThread = std::thread([this] { impl_->io.run(); });
    impl_->endpoints = std::move(endpoints);
    impl_->active.store(true, std::memory_order_release);
    return true;
}

void LaserCubeVirtualControllerHost::stop() {
    if (!impl_) {
        return;
    }
    impl_->closeAll();
    impl_->endpoints.clear();
    impl_->aliasManager.cleanup();
    impl_->active.store(false, std::memory_order_release);
}

bool LaserCubeVirtualControllerHost::running() const {
    return impl_ && impl_->active.load(std::memory_order_acquire);
}

std::vector<VirtualControllerEndpoint> LaserCubeVirtualControllerHost::endpoints() const {
    return impl_ ? impl_->endpoints : std::vector<VirtualControllerEndpoint>{};
}

} // namespace libera_link::virtual_controller
