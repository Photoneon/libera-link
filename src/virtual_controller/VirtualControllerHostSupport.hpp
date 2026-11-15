#pragma once

// Shared helpers for network virtual controller hosts: option parsing, IPv4
// utilities, local interface enumeration, and automatic IP alias management
// for protocols that identify each device by its own IPv4 address.

#include "virtual_controller/VirtualControllerHost.hpp"

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace libera_link::virtual_controller::support {

std::string trim(std::string_view text);
std::vector<std::string> splitCsv(std::string_view text);
std::optional<std::uint32_t> parseU32(std::string_view text);
bool parseBool(std::string_view text, bool fallback);

std::uint16_t optionU16(const VirtualControllerHostConfig& config,
                        std::string_view key,
                        std::uint16_t fallback);
std::uint32_t optionU32(const VirtualControllerHostConfig& config,
                        std::string_view key,
                        std::uint32_t fallback);
std::string optionString(const VirtualControllerHostConfig& config,
                         std::string_view key,
                         std::string fallback = {});
bool optionBool(const VirtualControllerHostConfig& config,
                std::string_view key,
                bool fallback);

std::optional<std::uint32_t> ipv4ToHost(std::string_view text);
std::string hostToIpv4(std::uint32_t value);
bool isValidIpv4(std::string_view text);

/// Stable FNV-1a derived byte, used to derive per-target identifiers.
std::uint8_t stableByteHash(std::string_view text, std::uint8_t salt);

struct InterfaceAddress {
    std::string name;
    std::string address;
    std::string netmask;
    std::string broadcast;
    std::uint32_t addressHost = 0;
    std::uint32_t netmaskHost = 0;
    std::uint32_t broadcastHost = 0;
    bool loopback = false;
};

/// Up IPv4 interfaces. Empty on platforms without getifaddrs (Windows).
std::vector<InterfaceAddress> interfaceAddresses();

/// Name of the interface holding the default route, when it can be determined.
std::optional<std::string> defaultInterfaceName();

bool canBindTcpAddress(std::string_view address, std::uint16_t port);
bool canBindUdpAddress(std::string_view address, std::uint16_t port);

struct IpAliasOptions {
    /// Protocol name used in error messages, e.g. "Ether Dream".
    std::string label;
    std::vector<std::string> explicitAddresses;
    /// auto: the interface's own address for a single target, aliases otherwise.
    /// alias: always allocate aliases, even for a single target.
    /// loopback: 127.0.0.x addresses.
    /// explicit: only use explicitAddresses.
    std::string ipMode = "auto";
    std::string interfaceName;
    std::string baseAddress;
    bool autoManageAliases = true;
    bool allowPrivilegePrompt = true;
    /// Address used for a single target when no usable interface is found.
    std::string singleTargetFallbackAddress = "127.0.0.1";
    /// Returns true when the protocol can bind its sockets on the address.
    std::function<bool(const std::string& address)> canBind;
};

/// Allocates one local IPv4 address per target, adding and later removing IP
/// aliases on the selected interface when needed.
class IpAliasManager {
public:
    explicit IpAliasManager(IpAliasOptions options);
    ~IpAliasManager();

    IpAliasManager(const IpAliasManager&) = delete;
    IpAliasManager& operator=(const IpAliasManager&) = delete;

    bool allocate(std::size_t count, std::vector<std::string>& addresses, std::string& error);
    void cleanup();

private:
    struct AliasRecord {
        std::string interfaceName;
        std::string address;
        std::string netmask;
        bool loopback = false;
    };

    bool allocateLoopback(std::size_t count, std::vector<std::string>& addresses, std::string& error);
    bool allocateLan(std::size_t count, std::vector<std::string>& addresses, std::string& error);
    bool ensureAlias(const AliasRecord& record, std::string& error);
    bool addAlias(const AliasRecord& record);
    void removeAlias(const AliasRecord& record);
    bool canBind(const std::string& address) const;

    IpAliasOptions options_;
    std::vector<AliasRecord> addedAliases_;
};

} // namespace libera_link::virtual_controller::support
