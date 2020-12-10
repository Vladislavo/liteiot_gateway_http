#ifndef __GATEWAY_PROTOCOL_H__
#define __GATEWAY_PROTOCOL_H__

#include <stdint.h>
#include <string.h>

#define GATEWAY_PROTOCOL_PACKET_SIZE_MAX    128

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    GATEWAY_PROTOCOL_PACKET_TYPE_DATA_SEND = 0x00,
    GATEWAY_PROTOCOL_PACKET_TYPE_PEND_REQ = 0x04,
    GATEWAY_PROTOCOL_PACKET_TYPE_PEND_SEND = 0x05,
    GATEWAY_PROTOCOL_PACKET_TYPE_STAT = 0x10,
    GATEWAY_PROTOCOL_PACKET_TYPE_TIME_REQ = 0x20,
    GATEWAY_PROTOCOL_PACKET_TYPE_TIME_SEND = 0x21,
    GATEWAY_PROTOCOL_PACKET_TYPE_UNKNOWN = 0xFF
} gateway_protocol_packet_type_t;

typedef enum {
    GATEWAY_PROTOCOL_STAT_ACK = 0,
    GATEWAY_PROTOCOL_STAT_ACK_PEND,
    GATEWAY_PROTOCOL_STAT_NACK = 0xFF
} gateway_protocol_stat_t;

void gateway_protocol_init(const uint8_t *appkey, const uint8_t devid);

void gateway_protocol_packet_encode (
    const gateway_protocol_packet_type_t packet_type,
    const uint8_t payload_length,
    const uint8_t *payload,
    uint8_t *packet_length,
    uint8_t *packet);

uint8_t gateway_protocol_packet_decode (
    gateway_protocol_packet_type_t *packet_type,
    uint8_t *payload_length,
    uint8_t *payload,
    const uint8_t packet_length,
    const uint8_t *packet);

#ifdef __cplusplus
}
#endif

#endif // __GATEWAY_PROTOCOL_H__