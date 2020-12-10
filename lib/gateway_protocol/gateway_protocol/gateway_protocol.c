#include <gateway_protocol/gateway_protocol.h>

#define GATEWAY_PROTOCOL_APP_KEY_SIZE       8

static uint8_t app_key[GATEWAY_PROTOCOL_APP_KEY_SIZE];
static uint8_t dev_id = 0xFF;

void gateway_protocol_init(const uint8_t *appkey, const uint8_t devid) {
    memcpy(app_key, appkey, GATEWAY_PROTOCOL_APP_KEY_SIZE);
    dev_id = devid;
}

void gateway_protocol_packet_encode (
    const gateway_protocol_packet_type_t packet_type,
    const uint8_t payload_length,
    const uint8_t *payload,
    uint8_t *packet_length,
    uint8_t *packet)
{
    *packet_length = 0;

    memcpy(&packet[*packet_length], app_key, GATEWAY_PROTOCOL_APP_KEY_SIZE);
    (*packet_length) += GATEWAY_PROTOCOL_APP_KEY_SIZE;

    packet[*packet_length] = dev_id;
    (*packet_length)++;

    packet[*packet_length] = packet_type;
    (*packet_length)++;

    packet[*packet_length] = payload_length;
    (*packet_length)++;

    memcpy(&packet[*packet_length], payload, payload_length);
    (*packet_length) += payload_length;
}

uint8_t gateway_protocol_packet_decode (
    gateway_protocol_packet_type_t *packet_type,
    uint8_t *payload_length,
    uint8_t *payload,
    const uint8_t packet_length,
    const uint8_t *packet)
{
    uint8_t p_len = 0;
    uint8_t appkey[GATEWAY_PROTOCOL_APP_KEY_SIZE];
    uint8_t dev;

    memcpy(appkey, &packet[p_len], GATEWAY_PROTOCOL_APP_KEY_SIZE);
    p_len += GATEWAY_PROTOCOL_APP_KEY_SIZE;

    dev = packet[p_len];
    p_len++;

    *packet_type = (gateway_protocol_packet_type_t) packet[p_len];
    p_len++;

    p_len++;
    *payload_length = packet_length - p_len;

    memcpy(payload, &packet[p_len], *payload_length);
    p_len += *payload_length;

    return (memcmp(appkey, app_key, GATEWAY_PROTOCOL_APP_KEY_SIZE) && 
            dev == dev_id &&
            p_len == packet_length);
}