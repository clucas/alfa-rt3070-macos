#ifndef ALFA_PROTOCOL_H
#define ALFA_PROTOCOL_H

#include <stdint.h>

#define ALFA_DRIVER_BUNDLE_ID "io.github.clucas.AlfaWiFi.Driver"
#define ALFA_HOST_BUNDLE_ID "io.github.clucas.AlfaWiFi"
#define ALFA_SERVICE_CLASS "AlfaEthernetDriver"
#define ALFA_PROTOCOL_VERSION 1u
#define ALFA_MIN_FRAME_SIZE 14u
#define ALFA_MAX_FRAME_SIZE 1514u
#define ALFA_FRAME_QUEUE_CAPACITY 64u

enum AlfaMethod {
    AlfaConfigure = 0,
    AlfaSetLink = 1,
    AlfaSendFrame = 2,
    AlfaReceiveFrame = 3,
    AlfaGetStatus = 4
};

enum AlfaStatusFlag {
    AlfaConfigured = 1u << 0,
    AlfaLinkUp = 1u << 1,
    AlfaInterfaceEnabled = 1u << 2
};

typedef struct AlfaConfiguration {
    uint8_t version;
    uint8_t mac[6];
    uint8_t reserved;
} AlfaConfiguration;

typedef struct AlfaStatus {
    uint32_t version;
    uint32_t flags;
    char bsdName[16];
    uint64_t txDrops;
    uint64_t rxDrops;
} AlfaStatus;

#ifdef __cplusplus
static_assert(sizeof(AlfaConfiguration) == 8, "Configuration ABI");
static_assert(sizeof(AlfaStatus) == 40, "Status ABI");
#endif

#endif
