#ifndef __SECURITY_ADAPTER_H__
#define __SECURITY_ADAPTER_H__

#include <stdint.h>
#include <string.h>

#define SECURITY_KEY_SIZE	16

#ifdef __cplusplus
extern "C" {
#endif


void security_adapter_encrypt(
	const uint8_t *secure_key,
	uint8_t *encrypted_payload, 
	uint16_t *encrypted_payload_length,
	uint8_t *decrypted_payload,
	uint16_t decrypted_payload_length);


void security_adapter_decrypt(
	const uint8_t *secure_key,
	uint8_t *encrypted_payload, 
	uint16_t encrypted_payload_length,
	uint8_t *decrypted_payload,
	uint16_t *decrypted_payload_length);


#ifdef __cplusplus
}
#endif

#endif
