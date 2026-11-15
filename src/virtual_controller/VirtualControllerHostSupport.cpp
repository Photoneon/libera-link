#include "virtual_controller/VirtualControllerHostSupport.hpp"

#include "libera/net/NetConfig.hpp"

#if defined(__unix__) || defined(__APPLE__)
#  include <arpa/inet.h>
#  include <ifaddrs.h>
#  include <net/if.h>
#  include <netinet/in.h>
#  include <sys/socket.h>
#  include <sys/wait.h>
#  include <unistd.h>
#endif

#if defined(_WIN32)
#  include <winsock2.h>
#  include <ws2tcpip.h>
#endif

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <limits>
#include <sstream>
#include <unordered_set>
#include <utility>

namespace libera_link::virtual_controller::support {
namespace {

namespace asio = libera::net::asio;
using libera::net::tcp;
using libera::net::udp;

std::string shellQuote(std::string_view text) {
    std::string quoted = "'";
    for (const char ch : text) {
        if (ch == '\'') {
            quoted += "'\\''";
        } else {
            quoted += ch;
        }
    }
    quoted += "'";
    return quoted;
}

[[maybe_unused]] std::string appleScriptQuote(std::string_view text) {
    std::string quoted = "\"";
    for (const char ch : text) {
        if (ch == '\\' || ch == '"') {
            quoted += '\\';
        }
        quoted += ch;
    }
    quoted += '"';
    return quoted;
}

[[maybe_unused]] bool systemCommandSucceeded(const std::string& command) {
    const int status = std::system(command.c_str());
    if (status == -1) {
        return false;
    }
#if defined(__unix__) || defined(__APPLE__)
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status) == 0;
    }
    return status == 0;
#else
    return status == 0;
#endif
}

[[maybe_unused]] std::optional<std::string> readCommandOutput(const char* command) {
#if defined(__unix__) || defined(__APPLE__)
    FILE* pipe = popen(command, "r");
    if (pipe == nullptr) {
        return std::nullopt;
    }
    std::string output;
    std::array<char, 256> buffer{};
    while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe) != nullptr) {
        output += buffer.data();
    }
    pclose(pipe);
    return output;
#else
    (void)command;
    return std::nullopt;
#endif
}

[[maybe_unused]] std::optional<unsigned> prefixLength(const std::string& netmask) {
    const auto mask = ipv4ToHost(netmask);
    if (!mask) {
        return std::nullopt;
    }
    unsigned prefix = 0;
    bool sawZero = false;
    for (int bit = 31; bit >= 0; --bit) {
        const bool set = ((*mask >> bit) & 1u) != 0;
        if (set && sawZero) {
            return std::nullopt;
        }
        if (set) {
            ++prefix;
        } else {
            sawZero = true;
        }
    }
    return prefix;
}

} // namespace

std::string trim(std::string_view text) {
    while (!text.empty() && std::isspace(static_cast<unsigned char>(text.front()))) {
        text.remove_prefix(1);
    }
    while (!text.empty() && std::isspace(static_cast<unsigned char>(text.back()))) {
        text.remove_suffix(1);
    }
    return std::string(text);
}

std::vector<std::string> splitCsv(std::string_view text) {
    std::vector<std::string> values;
    while (!text.empty()) {
        const auto comma = text.find(',');
        const auto piece = comma == std::string_view::npos
            ? text
            : text.substr(0, comma);
        auto value = trim(piece);
        if (!value.empty()) {
            values.push_back(std::move(value));
        }
        if (comma == std::string_view::npos) {
            break;
        }
        text.remove_prefix(comma + 1);
    }
    return values;
}

std::optional<std::uint32_t> parseU32(std::string_view text) {
    try {
        std::size_t parsed = 0;
        const auto raw = std::stoull(std::string(text), &parsed, 10);
        if (parsed != text.size() || raw > std::numeric_limits<std::uint32_t>::max()) {
            return std::nullopt;
        }
        return static_cast<std::uint32_t>(raw);
    } catch (...) {
        return std::nullopt;
    }
}

bool parseBool(std::string_view text, bool fallback) {
    std::string value = trim(text);
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    if (value == "1" || value == "true" || value == "yes" || value == "on") {
        return true;
    }
    if (value == "0" || value == "false" || value == "no" || value == "off") {
        return false;
    }
    return fallback;
}

std::uint16_t optionU16(const VirtualControllerHostConfig& config,
                        std::string_view key,
                        std::uint16_t fallback) {
    const auto it = config.options.find(std::string(key));
    if (it == config.options.end()) {
        return fallback;
    }
    const auto parsed = parseU32(trim(it->second));
    if (!parsed || *parsed > std::numeric_limits<std::uint16_t>::max()) {
        return fallback;
    }
    return static_cast<std::uint16_t>(*parsed);
}

std::uint32_t optionU32(const VirtualControllerHostConfig& config,
                        std::string_view key,
                        std::uint32_t fallback) {
    const auto it = config.options.find(std::string(key));
    if (it == config.options.end()) {
        return fallback;
    }
    return parseU32(trim(it->second)).value_or(fallback);
}

std::string optionString(const VirtualControllerHostConfig& config,
                         std::string_view key,
                         std::string fallback) {
    const auto it = config.options.find(std::string(key));
    if (it == config.options.end()) {
        return fallback;
    }
    return trim(it->second);
}

bool optionBool(const VirtualControllerHostConfig& config,
                std::string_view key,
                bool fallback) {
    const auto it = config.options.find(std::string(key));
    if (it == config.options.end()) {
        return fallback;
    }
    return parseBool(it->second, fallback);
}

std::optional<std::uint32_t> ipv4ToHost(std::string_view text) {
    in_addr addr{};
    const std::string value(text);
    if (::inet_pton(AF_INET, value.c_str(), &addr) != 1) {
        return std::nullopt;
    }
    return ntohl(addr.s_addr);
}

std::string hostToIpv4(std::uint32_t value) {
    in_addr addr{};
    addr.s_addr = htonl(value);
    char buffer[INET_ADDRSTRLEN]{};
    if (::inet_ntop(AF_INET, &addr, buffer, sizeof(buffer)) == nullptr) {
        return {};
    }
    return std::string(buffer);
}

bool isValidIpv4(std::string_view text) {
    return ipv4ToHost(text).has_value();
}

std::uint8_t stableByteHash(std::string_view text, std::uint8_t salt) {
    std::uint32_t value = 2166136261u ^ salt;
    for (unsigned char ch : text) {
        value ^= ch;
        value *= 16777619u;
    }
    return static_cast<std::uint8_t>((value >> 16) ^ (value >> 8) ^ value);
}

std::optional<std::string> defaultInterfaceName() {
#if defined(__APPLE__)
    auto output = readCommandOutput("/sbin/route -n get default 2>/dev/null");
    if (!output) {
        return std::nullopt;
    }
    std::istringstream input(*output);
    std::string line;
    while (std::getline(input, line)) {
        line = trim(line);
        constexpr std::string_view prefix = "interface:";
        if (line.rfind(prefix, 0) == 0) {
            auto value = trim(std::string_view(line).substr(prefix.size()));
            if (!value.empty()) {
                return value;
            }
        }
    }
    return std::nullopt;
#elif defined(__linux__)
    auto output = readCommandOutput("awk '$2 == \"00000000\" { print $1; exit }' /proc/net/route 2>/dev/null");
    if (!output) {
        return std::nullopt;
    }
    auto value = trim(*output);
    if (value.empty()) {
        return std::nullopt;
    }
    return value;
#else
    return std::nullopt;
#endif
}

std::vector<InterfaceAddress> interfaceAddresses() {
    std::vector<InterfaceAddress> result;
#if defined(__unix__) || defined(__APPLE__)
    ifaddrs* addrs = nullptr;
    if (getifaddrs(&addrs) != 0 || addrs == nullptr) {
        return result;
    }

    for (ifaddrs* it = addrs; it != nullptr; it = it->ifa_next) {
        if (it->ifa_addr == nullptr || it->ifa_addr->sa_family != AF_INET) {
            continue;
        }
        if ((it->ifa_flags & IFF_UP) == 0) {
            continue;
        }

        const auto* addr = reinterpret_cast<const sockaddr_in*>(it->ifa_addr);
        const auto* mask = reinterpret_cast<const sockaddr_in*>(it->ifa_netmask);
        const auto* bcast = (it->ifa_flags & IFF_BROADCAST) != 0
            ? reinterpret_cast<const sockaddr_in*>(it->ifa_broadaddr)
            : nullptr;

        char addressBuffer[INET_ADDRSTRLEN]{};
        char netmaskBuffer[INET_ADDRSTRLEN]{};
        char broadcastBuffer[INET_ADDRSTRLEN]{};
        if (::inet_ntop(AF_INET, &addr->sin_addr, addressBuffer, sizeof(addressBuffer)) == nullptr) {
            continue;
        }
        if (mask == nullptr ||
            ::inet_ntop(AF_INET, &mask->sin_addr, netmaskBuffer, sizeof(netmaskBuffer)) == nullptr) {
            continue;
        }
        if (bcast != nullptr) {
            (void)::inet_ntop(AF_INET, &bcast->sin_addr, broadcastBuffer, sizeof(broadcastBuffer));
        }

        InterfaceAddress info;
        info.name = it->ifa_name != nullptr ? it->ifa_name : "";
        info.address = addressBuffer;
        info.netmask = netmaskBuffer;
        info.broadcast = broadcastBuffer;
        info.addressHost = ntohl(addr->sin_addr.s_addr);
        info.netmaskHost = ntohl(mask->sin_addr.s_addr);
        info.broadcastHost = bcast != nullptr
            ? ntohl(bcast->sin_addr.s_addr)
            : ((info.addressHost & info.netmaskHost) | ~info.netmaskHost);
        if (info.broadcast.empty()) {
            info.broadcast = hostToIpv4(info.broadcastHost);
        }
        info.loopback = (it->ifa_flags & IFF_LOOPBACK) != 0;
        result.push_back(std::move(info));
    }

    freeifaddrs(addrs);
#endif
    return result;
}

bool canBindTcpAddress(std::string_view address, std::uint16_t port) {
    std::error_code ec;
    asio::io_context io;
    tcp::acceptor acceptor(io);
    acceptor.open(tcp::v4(), ec);
    if (ec) {
        return false;
    }
    acceptor.set_option(asio::socket_base::reuse_address(true), ec);
    const auto ip = asio::ip::make_address(std::string(address), ec);
    if (ec) {
        return false;
    }
    acceptor.bind(tcp::endpoint(ip, port), ec);
    return !ec;
}

bool canBindUdpAddress(std::string_view address, std::uint16_t port) {
    std::error_code ec;
    asio::io_context io;
    udp::socket socket(io);
    socket.open(udp::v4(), ec);
    if (ec) {
        return false;
    }
    socket.set_option(asio::socket_base::reuse_address(true), ec);
    const auto ip = asio::ip::make_address(std::string(address), ec);
    if (ec) {
        return false;
    }
    socket.bind(udp::endpoint(ip, port), ec);
    return !ec;
}

IpAliasManager::IpAliasManager(IpAliasOptions options)
    : options_(std::move(options)) {}

IpAliasManager::~IpAliasManager() {
    cleanup();
}

bool IpAliasManager::allocate(std::size_t count, std::vector<std::string>& addresses, std::string& error) {
    addresses.clear();
    cleanup();

    if (!options_.explicitAddresses.empty()) {
        if (options_.explicitAddresses.size() < count) {
            error = options_.label + " explicit address list has fewer addresses than targets.";
            return false;
        }
        for (std::size_t i = 0; i < count; ++i) {
            if (!isValidIpv4(options_.explicitAddresses[i])) {
                error = "Invalid " + options_.label + " explicit IPv4 address: " +
                        options_.explicitAddresses[i];
                return false;
            }
            addresses.push_back(options_.explicitAddresses[i]);
        }
        return true;
    }

    if (options_.ipMode == "explicit") {
        error = options_.label + " ip_mode=explicit requires addresses=ip1,ip2,...";
        return false;
    }

    if (count == 0) {
        return true;
    }

    if (options_.ipMode == "loopback") {
        return allocateLoopback(count, addresses, error);
    }

    return allocateLan(count, addresses, error);
}

void IpAliasManager::cleanup() {
    for (auto it = addedAliases_.rbegin(); it != addedAliases_.rend(); ++it) {
        removeAlias(*it);
    }
    addedAliases_.clear();
}

bool IpAliasManager::canBind(const std::string& address) const {
    return options_.canBind ? options_.canBind(address) : true;
}

bool IpAliasManager::allocateLoopback(std::size_t count,
                                      std::vector<std::string>& addresses,
                                      std::string& error) {
#if defined(_WIN32)
    if (count > 1) {
        error = "Automatic loopback IP aliases are not implemented on Windows.";
        return false;
    }
#endif
    const std::string interfaceName =
#if defined(__linux__)
        "lo";
#else
        "lo0";
#endif
    for (std::size_t i = 0; i < count; ++i) {
        const std::string address = "127.0.0." + std::to_string(static_cast<unsigned>(i + 1));
        AliasRecord record{interfaceName, address, "255.0.0.0", true};
        if (!ensureAlias(record, error)) {
            return false;
        }
        addresses.push_back(address);
    }
    return true;
}

bool IpAliasManager::allocateLan(std::size_t count,
                                 std::vector<std::string>& addresses,
                                 std::string& error) {
    const bool alwaysAlias = options_.ipMode == "alias";
    auto allInterfaces = interfaceAddresses();
    if (allInterfaces.empty()) {
        if (count == 1 && !alwaysAlias) {
            addresses.push_back(options_.singleTargetFallbackAddress);
            return true;
        }
        error = "No IPv4 interface is available for " + options_.label + " aliases.";
        return false;
    }

    std::unordered_set<std::uint32_t> existing;
    for (const auto& iface : allInterfaces) {
        existing.insert(iface.addressHost);
    }

    std::vector<InterfaceAddress> candidates;
    candidates.reserve(allInterfaces.size());
    const auto defaultIface = defaultInterfaceName();
    for (const auto& iface : allInterfaces) {
        if (iface.loopback) {
            continue;
        }
        if (!options_.interfaceName.empty() && iface.name != options_.interfaceName) {
            continue;
        }
        candidates.push_back(iface);
    }

    if (candidates.empty()) {
        if (count == 1 && !alwaysAlias) {
            addresses.push_back(options_.singleTargetFallbackAddress);
            return true;
        }
        error = options_.interfaceName.empty()
            ? "No non-loopback IPv4 interface is available for " + options_.label + " aliases."
            : "Configured " + options_.label + " interface is not available: " + options_.interfaceName;
        return false;
    }

    if (defaultIface) {
        std::stable_sort(candidates.begin(), candidates.end(),
                         [&](const InterfaceAddress& a, const InterfaceAddress& b) {
                             return (a.name == *defaultIface) > (b.name == *defaultIface);
                         });
    }

    const InterfaceAddress& iface = candidates.front();
    if (count == 1 && options_.baseAddress.empty() && !alwaysAlias) {
        addresses.push_back(iface.address);
        return true;
    }

    std::uint32_t network = iface.addressHost & iface.netmaskHost;
    std::uint32_t broadcast = iface.broadcastHost != 0
        ? iface.broadcastHost
        : (network | ~iface.netmaskHost);
    if (!options_.baseAddress.empty()) {
        const auto base = ipv4ToHost(options_.baseAddress);
        if (!base) {
            error = "Invalid " + options_.label + " base_address: " + options_.baseAddress;
            return false;
        }
        network = *base & iface.netmaskHost;
        broadcast = network | ~iface.netmaskHost;
    }

    if (broadcast <= network + 1) {
        error = options_.label + " interface subnet has no usable alias addresses.";
        return false;
    }

    std::vector<std::string> allocated;
    allocated.reserve(count);
    for (std::uint32_t candidate = broadcast - 1; candidate > network; --candidate) {
        if (existing.count(candidate) > 0 || candidate == iface.addressHost) {
            continue;
        }
        const std::string address = hostToIpv4(candidate);
        if (address.empty()) {
            continue;
        }
        AliasRecord record{iface.name, address, iface.netmask, false};
        if (!ensureAlias(record, error)) {
            return false;
        }
        allocated.push_back(address);
        existing.insert(candidate);
        if (allocated.size() == count) {
            addresses = std::move(allocated);
            return true;
        }
    }

    error = "Could not allocate enough " + options_.label + " alias addresses on interface " +
            iface.name + ".";
    return false;
}

bool IpAliasManager::ensureAlias(const AliasRecord& record, std::string& error) {
    if (canBind(record.address)) {
        return true;
    }

    if (!options_.autoManageAliases) {
        error = options_.label + " address " + record.address +
                " is not assigned locally and auto_manage_aliases is disabled.";
        return false;
    }

    if (!addAlias(record)) {
        error = "Failed to add " + options_.label + " IP alias " + record.address +
                " on " + record.interfaceName +
                ". Run with privileges or set addresses=... to preconfigured IPs.";
        return false;
    }

    if (!canBind(record.address)) {
        removeAlias(record);
        error = options_.label + " IP alias " + record.address +
                " was added but the app still cannot bind to it.";
        return false;
    }

    addedAliases_.push_back(record);
    return true;
}

bool IpAliasManager::addAlias(const AliasRecord& record) {
#if defined(__APPLE__)
    const std::string command = "/sbin/ifconfig " + shellQuote(record.interfaceName) +
                                " alias " + shellQuote(record.address) + " " +
                                shellQuote(record.netmask);
    if (systemCommandSucceeded(command + " >/dev/null 2>&1")) {
        return true;
    }
    if (!options_.allowPrivilegePrompt) {
        return false;
    }
    const std::string privileged = "/usr/bin/osascript -e " +
        shellQuote("do shell script " + appleScriptQuote(command) + " with administrator privileges");
    return systemCommandSucceeded(privileged + " >/dev/null 2>&1");
#elif defined(__linux__)
    const auto prefix = prefixLength(record.netmask).value_or(24);
    const std::string command = "/sbin/ip addr add " +
                                shellQuote(record.address + "/" + std::to_string(prefix)) +
                                " dev " + shellQuote(record.interfaceName);
    return systemCommandSucceeded(command + " >/dev/null 2>&1");
#else
    (void)record;
    return false;
#endif
}

void IpAliasManager::removeAlias(const AliasRecord& record) {
#if defined(__APPLE__)
    const std::string command = "/sbin/ifconfig " + shellQuote(record.interfaceName) +
                                " -alias " + shellQuote(record.address);
    if (systemCommandSucceeded(command + " >/dev/null 2>&1")) {
        return;
    }
    if (options_.allowPrivilegePrompt) {
        const std::string privileged = "/usr/bin/osascript -e " +
            shellQuote("do shell script " + appleScriptQuote(command) + " with administrator privileges");
        (void)systemCommandSucceeded(privileged + " >/dev/null 2>&1");
    }
#elif defined(__linux__)
    const auto prefix = prefixLength(record.netmask).value_or(24);
    const std::string command = "/sbin/ip addr del " +
                                shellQuote(record.address + "/" + std::to_string(prefix)) +
                                " dev " + shellQuote(record.interfaceName);
    (void)systemCommandSucceeded(command + " >/dev/null 2>&1");
#else
    (void)record;
#endif
}

} // namespace libera_link::virtual_controller::support
