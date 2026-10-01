#include "AlfaControlService.h"
#include "AlfaEthernetUserClient.h"
#include <DriverKit/IODispatchQueue.h>
#include <DriverKit/IOLib.h>
#include <os/log.h>

#define super IOService

struct AlfaControlService_IVars {
    AlfaEthernetDriver *driver;
    IODispatchQueue *queue;
    bool stopped;
};

bool AlfaControlService::init() {
    if (!super::init()) return false;
    ivars = static_cast<AlfaControlService_IVars *>(IOMallocZero(sizeof(*ivars)));
    return ivars != nullptr;
}

void AlfaControlService::free() {
    if (ivars) {
        OSSafeReleaseNULL(ivars->driver);
        OSSafeReleaseNULL(ivars->queue);
        IOFree(ivars, sizeof(*ivars));
    }
    super::free();
}

kern_return_t IMPL(AlfaControlService, Start) {
    os_log(OS_LOG_DEFAULT, "ALFA control service starting");
    kern_return_t result = super::Start(provider, SUPERDISPATCH);
    if (result != kIOReturnSuccess) return result;
    ivars->driver = OSDynamicCast(AlfaEthernetDriver, provider);
    if (!ivars->driver) {
        super::Stop(provider, SUPERDISPATCH);
        return kIOReturnBadArgument;
    }
    ivars->driver->retain();
    result = ivars->driver->CopyDispatchQueue("Default", &ivars->queue);
    if (result == kIOReturnSuccess) result = SetDispatchQueue("Default", ivars->queue);
    if (result == kIOReturnSuccess) result = SetName("ALFA Wi-Fi Control");
    if (result == kIOReturnSuccess) result = RegisterService();
    if (result != kIOReturnSuccess) {
        os_log(OS_LOG_DEFAULT, "ALFA control service startup failed");
        Stop_Impl(provider);
        return result;
    }
    os_log(OS_LOG_DEFAULT, "ALFA control service registered");
    return kIOReturnSuccess;
}

kern_return_t IMPL(AlfaControlService, Stop) {
    if (ivars->stopped) return kIOReturnSuccess;
    ivars->stopped = true;
    OSSafeReleaseNULL(ivars->driver);
    OSSafeReleaseNULL(ivars->queue);
    os_log(OS_LOG_DEFAULT, "ALFA control service stopped");
    return super::Stop(provider, SUPERDISPATCH);
}

AlfaEthernetDriver *AlfaControlService::CopyDriver() {
    if (ivars->stopped || !ivars->driver) return nullptr;
    ivars->driver->retain();
    return ivars->driver;
}

kern_return_t IMPL(AlfaControlService, NewUserClient) {
    os_log(OS_LOG_DEFAULT, "ALFA control NewUserClient entered");
    if (!userClient || type != 0) return kIOReturnBadArgument;
    *userClient = nullptr;
    if (ivars->stopped || !ivars->driver) return kIOReturnNotReady;
    IOService *service = nullptr;
    os_log(OS_LOG_DEFAULT, "ALFA control creating userclient");
    kern_return_t result = Create(this, "UserClientProperties", &service);
    if (result != kIOReturnSuccess) {
        os_log(OS_LOG_DEFAULT, "ALFA control userclient creation failed");
        return result;
    }
    if (!service) return kIOReturnError;
    auto *client = OSDynamicCast(AlfaEthernetUserClient, service);
    if (!client) {
        service->Terminate(0);
        OSSafeReleaseNULL(service);
        return kIOReturnError;
    }
    // Client RPCs and teardown must serialize with the parent packet queues.
    result = client->SetDispatchQueue("Default", ivars->queue);
    if (result == kIOReturnSuccess)
        result = client->SetDispatchQueue(kIOUserClientQueueNameExternalMethod, ivars->queue);
    if (result != kIOReturnSuccess) {
        os_log(OS_LOG_DEFAULT, "ALFA control userclient queue binding failed");
        client->Terminate(0);
        OSSafeReleaseNULL(service);
        return result;
    }
    *userClient = client;
    os_log(OS_LOG_DEFAULT, "ALFA control userclient created and queues bound");
    return kIOReturnSuccess;
}
