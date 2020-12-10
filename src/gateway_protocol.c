#include "gateway_protocol.h"
#include "security_adapter.h"

#define GATEWAY_PROTOCOL_APP_KEY_SIZE       8

static gateway_protocol_checkup_callback_t checkup_callback;

void gateway_protocol_packet_encode (
    const gateway_protocol_conf_t *gwp_conf,
    const gateway_protocol_packet_type_t packet_type,
    const uint8_t payload_length,
    const uint8_t *payload,
    uint8_t *packet_length,
    uint8_t *packet)
{
    *packet_length = 0;

    memcpy(&packet[*packet_length], gwp_conf->app_key, GATEWAY_PROTOCOL_APP_KEY_SIZE);
    (*packet_length) += GATEWAY_PROTOCOL_APP_KEY_SIZE;

    packet[*packet_length] = gwp_conf->dev_id;
    (*packet_length)++;

    packet[*packet_length] = packet_type;
    (*packet_length)++;

    packet[*packet_length] = payload_length;
    (*packet_length)++;

    memcpy(&packet[*packet_length], payload, payload_length);
    (*packet_length) += payload_length;

    if (gwp_conf->secure) {
	    security_adapter_encrypt(	gwp_conf->secure_key, 
					&packet[GATEWAY_PROTOCOL_APP_KEY_SIZE], 
					(uint16_t *)packet_length,
					&packet[GATEWAY_PROTOCOL_APP_KEY_SIZE], 
					(*packet_length-GATEWAY_PROTOCOL_APP_KEY_SIZE)
	    );
	    (*packet_length) += GATEWAY_PROTOCOL_APP_KEY_SIZE; 
    }
}

uint8_t gateway_protocol_packet_decode (
    gateway_protocol_conf_t *gwp_conf,
    gateway_protocol_packet_type_t *packet_type,
    uint8_t *payload_length,
    uint8_t *payload,
    uint8_t packet_length,
    uint8_t *packet)
{
    uint8_t p_len = 0;

    memcpy(gwp_conf->app_key, &packet[p_len], GATEWAY_PROTOCOL_APP_KEY_SIZE);
    p_len += GATEWAY_PROTOCOL_APP_KEY_SIZE;

    gwp_conf->app_key[GATEWAY_PROTOCOL_APP_KEY_SIZE] = '\0';

    if (checkup_callback(gwp_conf)) {
	    if (gwp_conf->secure) {
		    security_adapter_decrypt(	gwp_conf->secure_key, 
						&packet[GATEWAY_PROTOCOL_APP_KEY_SIZE], 
						(packet_length-GATEWAY_PROTOCOL_APP_KEY_SIZE),
						&packet[GATEWAY_PROTOCOL_APP_KEY_SIZE], 
						(uint16_t *)&packet_length
		    );
	    }

	    gwp_conf->dev_id = packet[p_len];
	    p_len++;

	    *packet_type = (gateway_protocol_packet_type_t) packet[p_len];
	    p_len++;

	    *payload_length = packet[p_len];
	    p_len++;

	    memcpy(payload, &packet[p_len], *payload_length);
	    p_len += *payload_length;
    } else {
	    p_len = 0;
    }

    return p_len;
}

void gateway_protocol_set_checkup_callback(gateway_protocol_checkup_callback_t callback) {
    checkup_callback = callback;
}

