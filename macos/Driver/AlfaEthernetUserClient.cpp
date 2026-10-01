#include "AlfaEthernetUserClient.h"
#include "AlfaEthernetDriver.h"
#include "AlfaControlService.h"
#include "Authorization.h"
#include <DriverKit/IOLib.h>
#include <DriverKit/OSDictionary.h>
#include <DriverKit/OSString.h>
#include <os/log.h>

#ifndef ALFA_HOST_APPLICATION_IDENTIFIER
#define ALFA_HOST_APPLICATION_IDENTIFIER "UNCONFIGURED.io.github.clucas.AlfaWiFi"
#endif
#ifndef ALFA_TEAM_IDENTIFIER
#define ALFA_TEAM_IDENTIFIER "UNCONFIGURED"
#endif

#define super IOUserClient

struct AlfaEthernetUserClient_IVars {
    AlfaEthernetDriver *driver;
    bool attached;
};

bool AlfaEthernetUserClient::init() {
    os_log(OS_LOG_DEFAULT, "ALFA userclient initializing");
    if (!super::init()) return false;
    ivars = static_cast<AlfaEthernetUserClient_IVars *>(IOMallocZero(sizeof(*ivars)));
    return ivars != nullptr;
}

void AlfaEthernetUserClient::free() {
    if (ivars) {
        OSSafeReleaseNULL(ivars->driver);
        IOFree(ivars, sizeof(*ivars));
    }
    super::free();
}

kern_return_t IMPL(AlfaEthernetUserClient, Start) {
    os_log(OS_LOG_DEFAULT, "ALFA userclient starting");
    kern_return_t result = super::Start(provider, SUPERDISPATCH);
    if (result != kIOReturnSuccess) {
        os_log(OS_LOG_DEFAULT, "ALFA userclient superclass Start failed");
        os_log(OS_LOG_DEFAULT, "ALFA userclient superclass Start failed: 0x%{public}x", result);
        return result;
    }
    os_log(OS_LOG_DEFAULT, "ALFA userclient superclass Start completed");
    if (!Authorize()) return kIOReturnNotPermitted;
    auto *control = OSDynamicCast(AlfaControlService, provider);
    if (!control) return kIOReturnBadArgument;
    ivars->driver = control->CopyDriver();
    if (!ivars->driver) return kIOReturnBadArgument;
    result = ivars->driver->AttachClient(this);
    if (result != kIOReturnSuccess) {
        OSSafeReleaseNULL(ivars->driver);
        return result;
    }
    ivars->attached = true;
    os_log(OS_LOG_DEFAULT, "ALFA userclient authorized and attached");
    return kIOReturnSuccess;
}

bool AlfaEthernetUserClient::Authorize() {
    os_log(OS_LOG_DEFAULT, "ALFA userclient reading identity");
    OSDictionary *entitlements = nullptr;
    const kern_return_t result = CopyClientEntitlements(&entitlements);
    if (result != kIOReturnSuccess || !entitlements) {
        os_log(OS_LOG_DEFAULT, "ALFA userclient entitlement lookup failed");
        os_log(OS_LOG_DEFAULT, "ALFA userclient entitlement lookup failed: 0x%{public}x present=%{public}d", result, entitlements != nullptr);
    }
    bool authorized = false;
    if (result == kIOReturnSuccess && entitlements) {
        auto *identifier = OSDynamicCast(OSString, entitlements->getObject("com.apple.application-identifier"));
        if (!identifier) identifier = OSDynamicCast(OSString, entitlements->getObject("application-identifier"));
        auto *team = OSDynamicCast(OSString, entitlements->getObject("com.apple.developer.team-identifier"));
        authorized = identifier && team && AlfaAuthorizedIdentity(identifier->getCStringNoCopy(),
            identifier->getLength(), team->getCStringNoCopy(), team->getLength(),
            ALFA_HOST_APPLICATION_IDENTIFIER, ALFA_TEAM_IDENTIFIER);
        if (!authorized) os_log(OS_LOG_DEFAULT, "ALFA userclient identity rejected: application-present=%{public}d team-present=%{public}d", identifier != nullptr, team != nullptr);
    }
    OSSafeReleaseNULL(entitlements);
    if (authorized) os_log(OS_LOG_DEFAULT, "ALFA userclient identity accepted");
    else os_log(OS_LOG_DEFAULT, "ALFA userclient identity rejected");
    return authorized;
}

kern_return_t IMPL(AlfaEthernetUserClient, Stop) {
    if (ivars->attached && ivars->driver) {
        ivars->driver->DetachClient(this);
        ivars->attached = false;
    }
    OSSafeReleaseNULL(ivars->driver);
    return super::Stop(provider, SUPERDISPATCH);
}

kern_return_t AlfaEthernetUserClient::ExternalMethod(uint64_t selector,
    IOUserClientMethodArguments *arguments, const IOUserClientMethodDispatch *, OSObject *, void *) {
    if (!ivars->attached || !ivars->driver) return kIOReturnNotOpen;
    return ivars->driver->HandleClientMethod(this, selector, arguments);
}

kern_return_t IMPL(AlfaEthernetUserClient, CopyClientMemoryForType) {
    if (memory) *memory = nullptr;
    return kIOReturnUnsupported;
}
