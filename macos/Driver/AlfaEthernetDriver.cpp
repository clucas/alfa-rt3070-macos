// Packet queue setup follows Apple's Connecting a Network Driver sample (LICENSE.apple.txt).
#include "AlfaEthernetDriver.h"
#include "AlfaControlService.h"
#include "AlfaEthernetUserClient.h"
#include "FrameQueue.h"
#include <DriverKit/IODispatchQueue.h>
#include <DriverKit/IOLib.h>
#include <DriverKit/OSAction.h>
#include <DriverKit/OSData.h>
#include <NetworkingDriverKit/NetworkingDriverKit.h>
#include <os/log.h>

#define super IOUserNetworkEthernet

static constexpr uint32_t kPacketBufferSize = 2048;
static constexpr uint32_t kQueueSize = 64;

struct AlfaEthernetDriver_IVars {
    IOService *control;
    IODispatchQueue *queue;
    IOUserNetworkPacketBufferPool *pool;
    IOUserNetworkTxSubmissionQueue *txSubmission;
    IOUserNetworkTxCompletionQueue *txCompletion;
    IOUserNetworkRxSubmissionQueue *rxSubmission;
    IOUserNetworkRxCompletionQueue *rxCompletion;
    IODataQueueDispatchSource *txDataSource;
    OSAction *txAction;
    IOUserClient *client;
    AlfaFrameQueue frames;
    uint8_t mac[6];
    uint64_t txDrops;
    uint64_t rxDrops;
    bool configured;
    bool published;
    bool enabled;
    bool radioReady;
    bool stopped;
    bool stopPending;
    bool stopCompleted;
};

bool AlfaEthernetDriver::init() {
    if (!super::init()) {
        os_log(OS_LOG_DEFAULT, "ALFA driver superclass initialization failed");
        return false;
    }
    ivars = static_cast<AlfaEthernetDriver_IVars *>(IOMallocZero(sizeof(*ivars)));
    if (!ivars) os_log(OS_LOG_DEFAULT, "ALFA driver allocation failed");
    return ivars != nullptr;
}

void AlfaEthernetDriver::free() {
    if (ivars) IOFree(ivars, sizeof(*ivars));
    super::free();
}

kern_return_t IMPL(AlfaEthernetDriver, Start) {
    os_log(OS_LOG_DEFAULT, "ALFA driver starting");
    kern_return_t result = super::Start(provider, SUPERDISPATCH);
    if (result != kIOReturnSuccess) {
        os_log(OS_LOG_DEFAULT, "ALFA superclass Start failed: 0x%{public}x", result);
        return result;
    }
    IOUserNetworkPacketBufferPoolOptions options = {};
    const IOUserNetworkMediaType media[] = {kIOUserNetworkMediaEthernetAuto};
    const char *stage = "CopyDispatchQueue";

    result = CopyDispatchQueue("Default", &ivars->queue);
    if (result != kIOReturnSuccess) goto fail;
    options.packetCount = 128;
    options.bufferCount = 128;
    options.bufferSize = kPacketBufferSize;
    options.maxBuffersPerPacket = 1;
    options.poolFlags = PoolFlagMapToDext | PoolFlagVirtualDevice;
    stage = "CreatePacketBufferPool";
    result = IOUserNetworkPacketBufferPool::CreateWithOptions(this, "ALFA Wi-Fi", &options, &ivars->pool);
    if (result != kIOReturnSuccess) goto fail;
    stage = "CreateTxAction";
    result = CreateActionTxPacketAvailable(0, &ivars->txAction);
    if (result != kIOReturnSuccess) goto fail;
    stage = "CreateTxSubmissionQueue";
    result = IOUserNetworkTxSubmissionQueue::Create(ivars->pool, this, kQueueSize, 0, ivars->queue, &ivars->txSubmission);
    if (result != kIOReturnSuccess) goto fail;
    stage = "CreateTxCompletionQueue";
    result = IOUserNetworkTxCompletionQueue::Create(ivars->pool, this, kQueueSize, 0, ivars->queue, &ivars->txCompletion);
    if (result != kIOReturnSuccess) goto fail;
    stage = "CreateRxSubmissionQueue";
    result = IOUserNetworkRxSubmissionQueue::Create(ivars->pool, this, kQueueSize, 0, ivars->queue, &ivars->rxSubmission);
    if (result != kIOReturnSuccess) goto fail;
    stage = "CreateRxCompletionQueue";
    result = IOUserNetworkRxCompletionQueue::Create(ivars->pool, this, kQueueSize, 0, ivars->queue, &ivars->rxCompletion);
    if (result != kIOReturnSuccess) goto fail;
    stage = "CopyTxDataQueue";
    result = ivars->txSubmission->CopyDataQueue(&ivars->txDataSource);
    if (result != kIOReturnSuccess) goto fail;
    stage = "SetTxDataAvailableHandler";
    result = ivars->txDataSource->SetDataAvailableHandler(ivars->txAction);
    if (result != kIOReturnSuccess) goto fail;
    stage = "ReportAvailableMediaTypes";
    result = ReportAvailableMediaTypes(media, 1);
    if (result != kIOReturnSuccess) goto fail;
    stage = "SetTxPacketHeadroom";
    result = SetTxPacketHeadroom(0);
    if (result != kIOReturnSuccess) goto fail;
    stage = "SetTxPacketTailroom";
    result = SetTxPacketTailroom(0);
    if (result != kIOReturnSuccess) goto fail;
    stage = "SetWakeOnMagicPacketSupport";
    result = SetWakeOnMagicPacketSupport(false);
    if (result != kIOReturnSuccess) goto fail;
    stage = "SetName";
    result = SetName("ALFA Wi-Fi");
    if (result != kIOReturnSuccess) goto fail;
    // The network kernel class rejects user clients until an Ethernet interface exists.
    stage = "CreateControlService";
    result = Create(this, "ControlProperties", &ivars->control);
    if (result != kIOReturnSuccess) goto fail;
    os_log(OS_LOG_DEFAULT, "ALFA driver started; waiting for radio configuration");
    return kIOReturnSuccess;
fail:
    os_log(OS_LOG_DEFAULT, "ALFA startup failed at %{public}s: 0x%{public}x", stage, result);
    Stop_Impl(provider);
    return result;
}

kern_return_t IMPL(AlfaEthernetDriver, Stop) {
    if (ivars->stopPending || ivars->stopCompleted) return kIOReturnSuccess;
    os_log(OS_LOG_DEFAULT, "ALFA driver stopping");
    ivars->stopPending = true;
    ivars->stopped = true;
    ivars->radioReady = false;
    ivars->client = nullptr;
    if (ivars->control) {
        ivars->control->Terminate(0);
        OSSafeReleaseNULL(ivars->control);
    }
    if (ivars->configured) ReportLinkStatus(kIOUserNetworkLinkStatusInactive, kIOUserNetworkMediaEthernetAuto);
    if (ivars->txSubmission) ivars->txSubmission->SetEnable(false);
    if (ivars->rxSubmission) ivars->rxSubmission->SetEnable(false);
    if (ivars->txCompletion) ivars->txCompletion->SetEnable(false);
    if (ivars->rxCompletion) ivars->rxCompletion->SetEnable(false);
    ivars->enabled = false;
    ivars->frames.clear();
    if (ivars->txDataSource) {
        // Cancellation must finish before releasing the action that retains this driver.
        retain();
        const kern_return_t result = ivars->txDataSource->Cancel(^{
            ivars->queue->DispatchAsync(^{
                OSSafeReleaseNULL(ivars->txDataSource);
                FinishStop(provider);
                release();
            });
        });
        if (result != kIOReturnSuccess) {
            os_log(OS_LOG_DEFAULT, "ALFA TX source cancellation failed: 0x%{public}x", result);
            ivars->stopPending = false;
            release();
        }
        return result;
    }
    return FinishStop(provider);
}

kern_return_t AlfaEthernetDriver::FinishStop(IOService *provider) {
    ivars->stopCompleted = true;
    ivars->stopPending = false;
    OSSafeReleaseNULL(ivars->rxCompletion);
    OSSafeReleaseNULL(ivars->rxSubmission);
    OSSafeReleaseNULL(ivars->txCompletion);
    OSSafeReleaseNULL(ivars->txSubmission);
    OSSafeReleaseNULL(ivars->txAction);
    OSSafeReleaseNULL(ivars->pool);
    OSSafeReleaseNULL(ivars->queue);
    os_log(OS_LOG_DEFAULT, "ALFA driver callbacks canceled; completing Stop");
    return super::Stop(provider, SUPERDISPATCH);
}

kern_return_t AlfaEthernetDriver::AttachClient(IOUserClient *client) {
    if (!client) return kIOReturnBadArgument;
    if (ivars->stopped) return kIOReturnNotReady;
    if (ivars->client) return kIOReturnExclusiveAccess;
    ivars->client = client;
    return kIOReturnSuccess;
}

void AlfaEthernetDriver::DetachClient(IOUserClient *client) {
    if (ivars->client != client) return;
    ivars->client = nullptr;
    ivars->radioReady = false;
    ivars->frames.clear();
    UpdateLink();
    DrainTransmit();
}

kern_return_t AlfaEthernetDriver::UpdateLink() {
    if (!ivars->configured || ivars->stopped) return kIOReturnSuccess;
    const char *name = getBSDName();
    if (!name || !*name) return kIOReturnSuccess;
    const bool active = ivars->enabled && ivars->radioReady && ivars->client;
    return ReportLinkStatus(active ? kIOUserNetworkLinkStatusActive : kIOUserNetworkLinkStatusInactive,
        kIOUserNetworkMediaEthernetAuto);
}

kern_return_t IMPL(AlfaEthernetDriver, SetInterfaceEnable) {
    if (ivars->stopped) return kIOReturnNotReady;
    kern_return_t result = kIOReturnSuccess;
    if (enable) {
        result = ivars->txCompletion->SetEnable(true);
        if (result == kIOReturnSuccess) result = ivars->rxCompletion->SetEnable(true);
        if (result == kIOReturnSuccess) result = ivars->txSubmission->SetEnable(true);
        if (result == kIOReturnSuccess) result = ivars->rxSubmission->SetEnable(true);
    }
    ivars->enabled = enable && result == kIOReturnSuccess;
    if (!ivars->enabled) {
        ivars->txSubmission->SetEnable(false);
        ivars->rxSubmission->SetEnable(false);
        ivars->txCompletion->SetEnable(false);
        ivars->rxCompletion->SetEnable(false);
        ivars->frames.clear();
    }
    const kern_return_t linkResult = UpdateLink();
    DrainTransmit();
    return result == kIOReturnSuccess ? linkResult : result;
}

kern_return_t AlfaEthernetDriver::HandleClientMethod(IOUserClient *client, uint64_t selector,
    IOUserClientMethodArguments *arguments) {
    if (ivars->stopped || client != ivars->client) return kIOReturnNotOpen;
    if (!arguments || arguments->completion || arguments->structureInputDescriptor ||
        arguments->structureOutputDescriptor || arguments->scalarOutputCount ||
        arguments->structureOutput) return kIOReturnBadArgument;
    const size_t size = arguments->structureInput ? arguments->structureInput->getLength() : 0;
    const void *bytes = size ? arguments->structureInput->getBytesNoCopy() : nullptr;
    if (arguments->scalarInputCount != (selector == AlfaSetLink ? 1u : 0u)) return kIOReturnBadArgument;
    if (selector != AlfaReceiveFrame && selector != AlfaGetStatus && arguments->structureOutputMaximumSize)
        return kIOReturnBadArgument;

    switch (selector) {
    case AlfaConfigure: {
        if (size != sizeof(AlfaConfiguration)) return kIOReturnBadArgument;
        AlfaConfiguration configuration;
        memcpy(&configuration, bytes, sizeof(configuration));
        if (configuration.version != ALFA_PROTOCOL_VERSION || configuration.reserved || !AlfaValidMAC(configuration.mac))
            return kIOReturnBadArgument;
        if (ivars->configured && memcmp(ivars->mac, configuration.mac, 6)) return kIOReturnNotPermitted;
        if (!ivars->configured) {
            memcpy(ivars->mac, configuration.mac, 6);
            ether_addr_t mac = {};
            memcpy(&mac, ivars->mac, 6);
            IOUserNetworkPacketQueue *queues[] = {ivars->txSubmission, ivars->txCompletion, ivars->rxSubmission, ivars->rxCompletion};
            os_log(OS_LOG_DEFAULT, "ALFA registering Ethernet interface");
            const kern_return_t result = RegisterEthernetInterface(mac, ivars->pool, queues, 4);
            if (result != kIOReturnSuccess) {
                os_log(OS_LOG_DEFAULT, "ALFA Ethernet registration failed: 0x%{public}x", result);
                memset(ivars->mac, 0, 6);
                return result;
            }
            ivars->configured = true;
            os_log(OS_LOG_DEFAULT, "ALFA Ethernet interface registration succeeded");
        }
        if (!ivars->published) {
            const kern_return_t result = RegisterService();
            if (result != kIOReturnSuccess) {
                os_log(OS_LOG_DEFAULT, "ALFA Ethernet service publication failed: 0x%{public}x", result);
                return result;
            }
            ivars->published = true;
            os_log(OS_LOG_DEFAULT, "ALFA Ethernet service published");
        }
        return kIOReturnSuccess;
    }
    case AlfaSetLink: {
        if (size || !arguments->scalarInput || arguments->scalarInput[0] > 1) return kIOReturnBadArgument;
        if (!ivars->configured) return kIOReturnNotReady;
        ivars->radioReady = arguments->scalarInput[0] != 0;
        if (!ivars->radioReady) ivars->frames.clear();
        const kern_return_t result = UpdateLink();
        DrainTransmit();
        return result;
    }
    case AlfaSendFrame: {
        if (!AlfaValidFrame(bytes, size)) return kIOReturnBadArgument;
        if (!ivars->configured || !ivars->enabled || !ivars->radioReady) return kIOReturnNotReady;
        const auto *frame = static_cast<const uint8_t *>(bytes);
        if (!(frame[0] & 1u) && memcmp(frame, ivars->mac, 6)) return kIOReturnBadArgument;
        IOUserNetworkPacket *packet = nullptr;
        if (ivars->rxSubmission->DequeuePackets(&packet, 1) != 1) {
            ++ivars->rxDrops;
            return kIOReturnNoResources;
        }
        const uint64_t address = packet->getDataVirtualAddress();
        const size_t offset = packet->getDataOff();
        kern_return_t result = kIOReturnBadArgument;
        if (address && offset <= kPacketBufferSize && size <= kPacketBufferSize - offset) {
            memcpy(reinterpret_cast<void *>(address + offset), bytes, size);
            result = packet->setDataLength(static_cast<uint32_t>(size));
            if (result == kIOReturnSuccess) result = packet->setLinkHeaderLength(ALFA_MIN_FRAME_SIZE);
            if (result == kIOReturnSuccess) result = packet->setIsLinkMulticast((frame[0] & 1u) != 0);
            if (result == kIOReturnSuccess) result = ivars->rxCompletion->EnqueuePacket(packet);
        }
        if (result != kIOReturnSuccess) {
            ++ivars->rxDrops;
            ivars->pool->DeallocatePacket(packet);
        }
        return result;
    }
    case AlfaReceiveFrame: {
        if (size || arguments->structureOutputMaximumSize > ALFA_MAX_FRAME_SIZE) return kIOReturnBadArgument;
        if (!ivars->configured || !ivars->enabled || !ivars->radioReady) return kIOReturnNotReady;
        DrainTransmit();
        const AlfaFrame *frame = ivars->frames.peek();
        if (!frame) return kIOReturnNotReady;
        if (arguments->structureOutputMaximumSize < frame->length) return kIOReturnNoSpace;
        arguments->structureOutput = OSData::withBytes(frame->bytes, frame->length);
        if (!arguments->structureOutput) return kIOReturnNoMemory;
        ivars->frames.pop();
        // The submission queue may still be nonempty, so no new notification is guaranteed.
        DrainTransmit();
        return kIOReturnSuccess;
    }
    case AlfaGetStatus: {
        if (size || arguments->structureOutputMaximumSize != sizeof(AlfaStatus)) return kIOReturnBadArgument;
        AlfaStatus status = {};
        status.version = ALFA_PROTOCOL_VERSION;
        if (ivars->configured) status.flags |= AlfaConfigured;
        if (ivars->enabled) status.flags |= AlfaInterfaceEnabled;
        if (ivars->configured && ivars->enabled && ivars->radioReady) status.flags |= AlfaLinkUp;
        if (ivars->configured && getBSDName()) strlcpy(status.bsdName, getBSDName(), sizeof(status.bsdName));
        status.txDrops = ivars->txDrops;
        status.rxDrops = ivars->rxDrops;
        arguments->structureOutput = OSData::withBytes(&status, sizeof(status));
        return arguments->structureOutput ? kIOReturnSuccess : kIOReturnNoMemory;
    }
    default:
        return kIOReturnUnsupported;
    }
}

void IMPL(AlfaEthernetDriver, TxPacketAvailable) {
    DrainTransmit();
}

void AlfaEthernetDriver::DrainTransmit() {
    if (ivars->stopped || !ivars->enabled) return;
    const bool ready = ivars->configured && ivars->client && ivars->radioReady;
    AlfaDrainFrames<IOUserNetworkPacket>(ivars->frames, ready,
      [this](IOUserNetworkPacket **packets, uint32_t limit) {
        return ivars->txSubmission->DequeuePackets(packets, limit);
      },
      [this, ready](IOUserNetworkPacket *packet) {
        const uint64_t address = packet->getDataVirtualAddress();
        const size_t offset = packet->getDataOff();
        const size_t length = packet->getDataLength();
        bool copied = false;
        if (ready && address &&
            offset <= kPacketBufferSize && length <= kPacketBufferSize - offset &&
            length >= ALFA_MIN_FRAME_SIZE && length <= ALFA_MAX_FRAME_SIZE) {
            const auto *bytes = reinterpret_cast<const uint8_t *>(address + offset);
            if (memcmp(bytes + 6, ivars->mac, 6) == 0) copied = ivars->frames.push(bytes, length);
        }
        if (!copied) ++ivars->txDrops;
        packet->setCompletionStatus(copied ? kIOReturnSuccess : kIOReturnNoResources);
        if (ivars->txCompletion->EnqueuePacket(packet) != kIOReturnSuccess) ivars->pool->DeallocatePacket(packet);
      });
}

kern_return_t IMPL(AlfaEthernetDriver, SetMTU) { return mtu >= 576 && mtu <= 1500 ? kIOReturnSuccess : kIOReturnUnsupported; }
kern_return_t IMPL(AlfaEthernetDriver, GetMaxTransferUnit) { *mtu = 1500; return kIOReturnSuccess; }
kern_return_t IMPL(AlfaEthernetDriver, GetHardwareAssists) { *hardwareAssists = 0; return kIOReturnSuccess; }
kern_return_t IMPL(AlfaEthernetDriver, SetHardwareAssists) { return hardwareAssists ? kIOReturnUnsupported : kIOReturnSuccess; }
kern_return_t IMPL(AlfaEthernetDriver, SetPromiscuousModeEnable) { return enable ? kIOReturnUnsupported : kIOReturnSuccess; }
kern_return_t IMPL(AlfaEthernetDriver, SetMulticastAddresses) { return count && !addresses ? kIOReturnBadArgument : kIOReturnSuccess; }
kern_return_t IMPL(AlfaEthernetDriver, SetAllMulticastModeEnable) { return kIOReturnSuccess; }
kern_return_t IMPL(AlfaEthernetDriver, SetWakeOnMagicPacketEnable) { return enable ? kIOReturnUnsupported : kIOReturnSuccess; }
kern_return_t IMPL(AlfaEthernetDriver, SelectMediaType) { return mediaType == kIOUserNetworkMediaEthernetAuto ? kIOReturnSuccess : kIOReturnUnsupported; }

IOReturn AlfaEthernetDriver::getHardwareAddress(ether_addr_t *address) {
    if (!address || !AlfaValidMAC(ivars->mac)) return kIOReturnNotReady;
    memcpy(address, ivars->mac, 6);
    return kIOReturnSuccess;
}

IOReturn AlfaEthernetDriver::setHardwareAddress(ether_addr_t *address) {
    return address && memcmp(address, ivars->mac, 6) == 0 ? kIOReturnSuccess : kIOReturnUnsupported;
}
