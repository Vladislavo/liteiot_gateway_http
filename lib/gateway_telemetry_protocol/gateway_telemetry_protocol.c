#include "gateway_telemetry_protocol.h"
#include "security_adapter.h"


static uint8_t secure_key[GATEWAY_TELEMETRY_PROTOCOL_SECURE_KEY_SIZE];
static uint8_t gateway_id[GATEWAY_TELEMETRY_PROTOCOL_GATEWAY_ID_SIZE];

void gateway_telemetry_protocol_init(const uint8_t *gw_id, const uint8_t *sk) {
	memcpy(gateway_id, gw_id, GATEWAY_TELEMETRY_PROTOCOL_GATEWAY_ID_SIZE);
	memcpy(secure_key, sk, GATEWAY_TELEMETRY_PROTOCOL_SECURE_KEY_SIZE);
}

void gateway_telemetry_protocol_encode_packet(
	const uint8_t *payload,
	const uint16_t payload_length,
	const gateway_telemetry_protocol_packet_type_t pt,
	uint8_t *packet,
	uint16_t *packet_length)
{
	*packet_length = 0;
	
	memcpy(&packet[*packet_length], gateway_id, GATEWAY_TELEMETRY_PROTOCOL_GATEWAY_ID_SIZE);
	(*packet_length) += GATEWAY_TELEMETRY_PROTOCOL_GATEWAY_ID_SIZE;

	packet[*packet_length] = (uint8_t) pt;
	(*packet_length)++;

	memcpy(&packet[*packet_length], &payload_length, sizeof(payload_length));
	*packet_length += sizeof(payload_length);

	memcpy(&packet[*packet_length], payload, payload_length);
	*packet_length += payload_length;

	security_adapter_encrypt(secure_key,
				 &packet[GATEWAY_TELEMETRY_PROTOCOL_GATEWAY_ID_SIZE], 
				 packet_length,
				 &packet[GATEWAY_TELEMETRY_PROTOCOL_GATEWAY_ID_SIZE], 
				 (*packet_length-GATEWAY_TELEMETRY_PROTOCOL_GATEWAY_ID_SIZE)
	);
	(*packet_length) += GATEWAY_TELEMETRY_PROTOCOL_GATEWAY_ID_SIZE;
}

uint8_t gateway_telemetry_protocol_decode_packet(
	uint8_t *payload,
	uint16_t *payload_length,
	gateway_telemetry_protocol_packet_type_t *pt,
	const uint8_t *packet,
	const uint16_t packet_length)
{
	uint16_t p_len = GATEWAY_TELEMETRY_PROTOCOL_GATEWAY_ID_SIZE;

	if (!memcmp(gateway_id, packet, GATEWAY_TELEMETRY_PROTOCOL_GATEWAY_ID_SIZE)) {
		// assert (packet_length - GATEWAY_TELEMETRY_PROTOCOL_GATEWAY_ID_SIZE % GATEWAY_TELEMETRY_PROTOCOL_SECURE_KEY_SIZE);
		security_adapter_decrypt(secure_key,
					 &packet[GATEWAY_TELEMETRY_PROTOCOL_GATEWAY_ID_SIZE], 
					 (packet_length-GATEWAY_TELEMETRY_PROTOCOL_GATEWAY_ID_SIZE),
					 &packet[GATEWAY_TELEMETRY_PROTOCOL_GATEWAY_ID_SIZE], 
					 &packet_length
		);
		
		*pt = (gateway_telemetry_protocol_packet_type_t) packet[p_len];
		p_len++;

		memcpy(payload_length, &packet[p_len], sizeof(*payload_length));
		p_len += sizeof(*payload_length);

		memcpy(payload, &packet[p_len], *payload_length);
		p_len += *payload_length;

		ret = 1;
	}

	return p_len > GATEWAY_TELEMETRY_PROTOCOL_GATEWAY_ID_SIZE;
}
