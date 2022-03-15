#include "source/extensions/network/dns_resolver/cares/dns_impl.h"

#include <chrono>
#include <cstdint>
#include <list>
#include <memory>
#include <string>

#include "envoy/common/platform.h"
#include "envoy/registry/registry.h"

#include "source/common/api/os_sys_calls_impl.h"
#include "source/common/common/assert.h"
#include "source/common/common/fmt.h"
#include "source/common/common/thread.h"
#include "source/common/network/address_impl.h"
#include "source/common/network/resolver_impl.h"
#include "source/common/network/utility.h"

#include "absl/strings/str_join.h"
#include "ares.h"

namespace Envoy {
namespace Network {

DnsResolverImpl::DnsResolverImpl(
    const envoy::extensions::network::dns_resolver::cares::v3::CaresDnsResolverConfig& config,
    Event::Dispatcher& dispatcher,
    const std::vector<Network::Address::InstanceConstSharedPtr>& resolvers)
    : dispatcher_(dispatcher),
      timer_(dispatcher.createTimer([this] {})),
      dns_resolver_options_(config.dns_resolver_options()),
      use_resolvers_as_fallback_(config.use_resolvers_as_fallback()),
      resolvers_csv_(maybeBuildResolversCsv(resolvers)),
      filter_unroutable_families_(config.filter_unroutable_families()) {
  // AresOptions options = defaultAresOptions();
  // initializeChannel(&options.options_, options.optmask_);
}

DnsResolverImpl::~DnsResolverImpl() {
  timer_->disableTimer();
  // ares_destroy(channel_);
}

absl::optional<std::string> DnsResolverImpl::maybeBuildResolversCsv(
    const std::vector<Network::Address::InstanceConstSharedPtr>& resolvers) {
  if (resolvers.empty()) {
    return absl::nullopt;
  }

  std::vector<std::string> resolver_addrs;
  resolver_addrs.reserve(resolvers.size());
  for (const auto& resolver : resolvers) {
    // This should be an IP address (i.e. not a pipe).
    if (resolver->ip() == nullptr) {
      throw EnvoyException(
          fmt::format("DNS resolver '{}' is not an IP address", resolver->asString()));
    }
    // Note that the ip()->port() may be zero if the port is not fully specified by the
    // Address::Instance.
    // resolver->asString() is avoided as that format may be modified by custom
    // Address::Instance implementations in ways that make the <port> not a simple
    // integer. See https://github.com/envoyproxy/envoy/pull/3366.
    resolver_addrs.push_back(fmt::format(resolver->ip()->ipv6() ? "[{}]:{}" : "{}:{}",
                                         resolver->ip()->addressAsString(),
                                         resolver->ip()->port()));
  }
  return {absl::StrJoin(resolver_addrs, ",")};
}


void DnsResolverImpl::AddrInfoPendingResolution::GetAddrInfoCallback(
     int timeouts, const std::string& host_name) {

    pending_response_.status_ = ResolutionStatus::Success;
    sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = 0;
    address.sin_addr.s_addr = inet_addr(host_name.c_str());
    pending_response_.address_list_.emplace_back(
    DnsResponse(std::make_shared<const Address::Ipv4Instance>(&address),
                std::chrono::seconds(1)));


    if (!pending_response_.address_list_.empty() && dns_lookup_family_ != DnsLookupFamily::All) {
      completed_ = true;
    }

  if (timeouts > 0) {
    ENVOY_LOG(debug, "DNS request timed out {} times", timeouts);
  }

  if (completed_) {
    finishResolve();
    // Nothing can follow a call to finishResolve due to the deletion of this object upon
    // finishResolve().
    return;
  }

  if (dual_resolution_) {
    dual_resolution_ = false;

    if (dns_lookup_family_ == DnsLookupFamily::Auto) {
      ENVOY_LOG(info, "----- In DnsResolverImpl::AddrInfoPendingResolution::onAresGetAddrInfoCallback: startResolutionImpl(AF_INET)---------------");
      startResolutionImpl(AF_INET, host_name);
    } else if (dns_lookup_family_ == DnsLookupFamily::V4Preferred) {
      startResolutionImpl(AF_INET6, host_name);
    }

    return;
  }
}

ActiveDnsQuery* DnsResolverImpl::resolve(const std::string& dns_name,
                                         DnsLookupFamily dns_lookup_family, ResolveCb callback) {
  ENVOY_LOG_EVENT(info, "cares_dns_resolution_start", "dns resolution for {} started", dns_name);
  ENVOY_LOG(info, "------------------------DNS RESOLVE IMPL RESOLVE----------------------------------------");
  // TODO(hennna): Add DNS caching which will allow testing the edge case of a
  ENVOY_LOG(info, "-------------dns_name is : '{}'----------------------", dns_name);
  ENVOY_LOG(info, "-------------DnsLookupFamily is : '{}'----------------------", dns_lookup_family);

  auto pending_app_resolution = std::make_unique<AddrInfoPendingResolution>(
      *this, callback, dispatcher_, dns_name, dns_lookup_family);
  ENVOY_LOG(info, "IN resolve ,dns_name is {} ", dns_name);
  ENVOY_LOG(info, "IN resolve ,dns_lookup_family is {} ", dns_lookup_family);
  pending_app_resolution->startResolution(dns_name);
  if (pending_app_resolution->completed_) {
    ENVOY_LOG(info, "------pending_resolution->completed_ is true------");
    // Resolution does not need asynchronous behavior or network events. For
    // example, localhost lookup.
    return nullptr;
  } else {
    ENVOY_LOG(info, "------pending_resolution->completed_ is false------");

    pending_app_resolution->owned_ = true;
    return pending_app_resolution.release();
  }
}


void DnsResolverImpl::PendingResolution::finishResolve() {
  ENVOY_LOG_EVENT(debug, "cares_dns_resolution_complete",
                  "dns resolution for {} completed with status {}", dns_name_,
                  pending_response_.status_);

  if (!cancelled_) {
    // Use a raw try here because it is used in both main thread and filter.
    // Can not convert to use status code as there may be unexpected exceptions in server fuzz
    // tests, which must be handled. Potential exception may come from getAddressWithPort() or
    // portFromTcpUrl().
    // TODO(chaoqin-li1123): remove try catch pattern here once we figure how to handle unexpected
    // exception in fuzz tests.
    TRY_NEEDS_AUDIT {
      callback_(pending_response_.status_, std::move(pending_response_.address_list_));
    }
    catch (const EnvoyException& e) {
      ENVOY_LOG(critical, "EnvoyException in c-ares callback: {}", e.what());
      dispatcher_.post([s = std::string(e.what())] { throw EnvoyException(s); });
    }
    catch (const std::exception& e) {
      ENVOY_LOG(critical, "std::exception in c-ares callback: {}", e.what());
      dispatcher_.post([s = std::string(e.what())] { throw EnvoyException(s); });
    }
    catch (...) {
      ENVOY_LOG(critical, "Unknown exception in c-ares callback");
      dispatcher_.post([] { throw EnvoyException("unknown"); });
    }
  } else {
    ENVOY_LOG_EVENT(debug, "cares_dns_callback_cancelled",
                    "dns resolution callback for {} not issued. Cancelled with reason={}",
                    dns_name_, cancel_reason_);
  }
  if (owned_) {
    delete this;
    return;
  }
}


DnsResolverImpl::AddrInfoPendingResolution::AddrInfoPendingResolution(
    DnsResolverImpl& parent, ResolveCb callback, Event::Dispatcher& dispatcher,
    const std::string& dns_name, DnsLookupFamily dns_lookup_family)
    : PendingResolution(parent, callback, dispatcher, dns_name),
      dns_lookup_family_(dns_lookup_family), available_interfaces_(availableInterfaces()) {
  if (dns_lookup_family == DnsLookupFamily::Auto ||
      dns_lookup_family == DnsLookupFamily::V4Preferred ||
      dns_lookup_family == DnsLookupFamily::All) {
    dual_resolution_ = true;
  }

  switch (dns_lookup_family_) {
  case DnsLookupFamily::V4Only:
  case DnsLookupFamily::V4Preferred:
    family_ = AF_INET;
    break;
  case DnsLookupFamily::V6Only:
  case DnsLookupFamily::Auto:
    family_ = AF_INET6;
    break;
  // NOTE: DnsLookupFamily::All performs both lookups concurrently as addresses from both families
  // are being requested.
  case DnsLookupFamily::All:
    lookup_all_ = true;
    break;
  }
}

void DnsResolverImpl::AddrInfoPendingResolution::startResolution(const std::string& dns_name) {
  if (lookup_all_) {
    ENVOY_LOG(info, "--------DnsResolverImpl::AddrInfoPendingResolution --startResolution---------");
    startResolutionImpl(AF_INET, dns_name);
    startResolutionImpl(AF_INET6, dns_name);
  } else {
    ENVOY_LOG(info, "-------startResolutionImpl(family_)- DnsResolverImpl::AddrInfoPendingResolution --startResolution---------");
    startResolutionImpl(family_, dns_name);
  }
}

void DnsResolverImpl::AddrInfoPendingResolution::startResolutionImpl(int family, const std::string& dns_name) {

  // struct ares_addrinfo_hints hints = {};
  // hints.ai_family = family;
  ENVOY_LOG(info , "------------------In DnsResolverImpl::AddrInfoPendingResolution::startResolutionImpl-- family is {}----------------------",  family);
  GetAddrInfoCallback(0, dns_name);
  return;

}

DnsResolverImpl::AddrInfoPendingResolution::AvailableInterfaces
DnsResolverImpl::AddrInfoPendingResolution::availableInterfaces() {
  if (!Api::OsSysCallsSingleton::get().supportsGetifaddrs()) {
    // Maintain no-op behavior if the system cannot provide interface information.
    return {true, true};
  }

  Api::InterfaceAddressVector interface_addresses{};
  const Api::SysCallIntResult rc = Api::OsSysCallsSingleton::get().getifaddrs(interface_addresses);
  RELEASE_ASSERT(!rc.return_value_, fmt::format("getiffaddrs error: {}", rc.errno_));

  DnsResolverImpl::AddrInfoPendingResolution::AvailableInterfaces available_interfaces{false,
                                                                                       false};
  for (const auto& interface_address : interface_addresses) {
    if (!interface_address.interface_addr_->ip()) {
      continue;
    }

    if (Network::Utility::isLoopbackAddress(*interface_address.interface_addr_)) {
      continue;
    }

    switch (interface_address.interface_addr_->ip()->version()) {
    case Network::Address::IpVersion::v4:
      available_interfaces.v4_available_ = true;
      if (available_interfaces.v6_available_) {
        return available_interfaces;
      }
      break;
    case Network::Address::IpVersion::v6:
      available_interfaces.v6_available_ = true;
      if (available_interfaces.v4_available_) {
        return available_interfaces;
      }
      break;
    }
  }
  return available_interfaces;
}

// c-ares DNS resolver factory
class CaresDnsResolverFactory : public DnsResolverFactory {
public:
  std::string name() const override { return std::string(CaresDnsResolver); }

  ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return ProtobufTypes::MessagePtr{
        new envoy::extensions::network::dns_resolver::cares::v3::CaresDnsResolverConfig()};
  }

  DnsResolverSharedPtr createDnsResolver(Event::Dispatcher& dispatcher, Api::Api&,
                                         const envoy::config::core::v3::TypedExtensionConfig&
                                             typed_dns_resolver_config) const override {
    envoy::extensions::network::dns_resolver::cares::v3::CaresDnsResolverConfig cares;
    std::vector<Network::Address::InstanceConstSharedPtr> resolvers;

    ASSERT(dispatcher.isThreadSafe());
    // Only c-ares DNS factory will call into this function.
    // Directly unpack the typed config to a c-ares object.
    Envoy::MessageUtil::unpackTo(typed_dns_resolver_config.typed_config(), cares);
    if (!cares.resolvers().empty()) {
      const auto& resolver_addrs = cares.resolvers();
      resolvers.reserve(resolver_addrs.size());
      for (const auto& resolver_addr : resolver_addrs) {
        resolvers.push_back(Network::Address::resolveProtoAddress(resolver_addr));
      }
    }
    return std::make_shared<Network::DnsResolverImpl>(cares, dispatcher, resolvers);
  }
};

// Register the CaresDnsResolverFactory
REGISTER_FACTORY(CaresDnsResolverFactory, DnsResolverFactory);

} // namespace Network
} // namespace Envoy



