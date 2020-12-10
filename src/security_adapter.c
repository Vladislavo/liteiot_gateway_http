#include "security_adapter.h"
#include "aes.h"

void security_adapter_encrypt(
	const uint8_t *secure_key,
	uint8_t *encrypted_payload, 
	uint16_t *encrypted_payload_length,
	uint8_t *decrypted_payload,
	uint16_t decrypted_payload_length) 
{
	uint16_t i;
	struct AES_ctx ctx;
	AES_init_ctx(&ctx, secure_key);
	
	for (i = 0; i < decrypted_payload_length; i+= SECURITY_KEY_SIZE) {
		AES_ECB_encrypt(&ctx, &decrypted_payload[i]);
	}

	*encrypted_payload_length = i;
	memcpy(encrypted_payload, decrypted_payload, *encrypted_payload_length);
}



void security_adapter_decrypt(
	const uint8_t *secure_key,
	uint8_t *encrypted_payload, 
	uint16_t encrypted_payload_length,
	uint8_t *decrypted_payload,
	uint16_t *decrypted_payload_length)
{
	// assert(encrypted_payload_length % SECURITY_KEY_SIZE == 0);	

	uint16_t i;
	struct AES_ctx ctx;
	AES_init_ctx(&ctx, secure_key);
	
	for (i = 0; i < encrypted_payload_length; i+= SECURITY_KEY_SIZE) {
		AES_ECB_decrypt(&ctx, &encrypted_payload[i]);
	}

	*decrypted_payload_length = i;
	memcpy(decrypted_payload, encrypted_payload, *decrypted_payload_length);
}
