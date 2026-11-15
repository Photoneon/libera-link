#pragma once

#include "virtual_controller/VirtualControllerHost.hpp"

#include <memory>
#include <string>
#include <string_view>

namespace libera_link::virtual_controller {

void ensureBuiltInLaserCubeVirtualControllerHostLinked();

/// Serial-number prefix (hex, as reported by LaserCube discovery) used by every
/// virtual LaserCube. LinkRuntime uses it to avoid linking its own endpoints.
inline constexpr std::string_view virtualLaserCubeSerialPrefix = "4C4C4B";

bool isVirtualLaserCubeSerial(std::string_view serial);

/// Presents each linked target as a network LaserCube (LaserDock network
/// protocol: UDP command port 45457, UDP data port 45458), so LaserOS and other
/// LaserCube-aware software can discover and drive it.
class LaserCubeVirtualControllerHost final : public VirtualControllerHost {
public:
    explicit LaserCubeVirtualControllerHost(const VirtualControllerHostConfig& config);
    ~LaserCubeVirtualControllerHost() override;

    LaserCubeVirtualControllerHost(const LaserCubeVirtualControllerHost&) = delete;
    LaserCubeVirtualControllerHost& operator=(const LaserCubeVirtualControllerHost&) = delete;

    std::string_view name() const override;
    std::string_view displayName() const override;
    bool start(const VirtualControllerHostContext& context, std::string& error) override;
    void stop() override;
    bool running() const override;
    std::vector<VirtualControllerEndpoint> endpoints() const override;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace libera_link::virtual_controller
