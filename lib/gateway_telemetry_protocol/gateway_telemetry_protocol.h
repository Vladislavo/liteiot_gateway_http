#ifndef GATEWAY_TELEMETRY_PROTOCOL_H
#define GATEWAY_TELEMETRY_PROTOCOL_H

#include<stdint.h>

#define GATEWAY_TELEMETRY_PROTOCOL_SECURE_KEY_SIZE	16
#define GATEWAY_TELEMETRY_PROTOCOL_GATEWAY_ID_SIZE	6

typedef enum {
	// auth packet to the platform
	GATEWAY_TELEMETRY_PROTOCOL_AUTH = 0,
	// config sent from the platform
	GATEWAY_TELEMETRY_PROTOCOL_CONFIG,
	// application and devices serving report
	GATEWAY_TELEMETRY_PROTOCOL_REPORT
} gateway_telemetry_protocol_packet_type_t;

void gateway_telemetry_protocol_init(
	const uint8_t *gw_id,
	const uint8_t *sk);

void gateway_telemetry_protocol_encode_packet(
	const uint8_t *payload,
	const uint16_t payload_length,
	const gateway_telemetry_protocol_packet_type_t pt,
	uint8_t *packet,
	uint16_t *packet_length);

uint8_t gateway_telemetry_protocol_decode_packet(
	uint8_t *payload,
	uint16_t *payload_length,
	gateway_telemetry_protocol_packet_type_t *pt,
	const uint8_t *packet,
	const uint16_t packet_length);

#endif // GATEWAY_TELEMETRY_PROTOCOL_H
