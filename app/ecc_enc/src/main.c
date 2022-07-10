/* main.c - Application main entry point */

/*
 * Copyright (c) 2015-2016 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdbool.h>
#include <zephyr/types.h>
#include <stddef.h>
#include <errno.h>
#include <sys/printk.h>
#include <sys/byteorder.h>
#include <zephyr.h>
#include <device.h>
#include <string.h>

#include <crypto/cipher.h>

#define LOG_LEVEL CONFIG_CRYPTO_LOG_LEVEL
#include <logging/log.h>
LOG_MODULE_REGISTER(main);

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_vs.h>
#include <bluetooth/conn.h>
#include <bluetooth/uuid.h>
#include <bluetooth/gatt.h>
#include <bluetooth/services/bas.h>
#include <bluetooth/ecc.h>

#include <debug/stack.h>
#include <tinycrypt/ecc.h>
#include <tinycrypt/ecc_dh.h>
#include <tinycrypt/ecc_platform_specific.h>
#include <tinycrypt/constants.h>
#include <tinycrypt/utils.h>
#include <drivers/bluetooth/hci_driver.h>

uint8_t private_key_be[32] = {0};
uint8_t public_key_be[64] = {0};
uint8_t C2[64] = {0}, C1[32] = {0};
uint8_t OC2[64] = {0}, OC1[64] = {0};

static uint8_t generate_keys(void)
{	
	int rc;
	
	const struct uECC_Curve_t *curve = uECC_secp256r1();
	rc = uECC_make_key(public_key_be, private_key_be, curve);
	if (rc == TC_CRYPTO_FAIL) {
		LOG_DBG("Failed to create ECC public/private pair");
		return 1;
	}

	// LOG_DBG("SC private key 0x%s", bt_hex(&private_key_be[0], 32));
	// LOG_DBG("SC public  key 0x%s", bt_hex(&public_key_be[0], 64));

	return 0;
}

static uint8_t ecc_data_encrypt(uint8_t *m){
	uint8_t r[32] = {0}, secret[32] = {0};
	int rc;
	
	const struct uECC_Curve_t *curve = uECC_secp256r1();
	// caculate C2	
	rc = uECC_make_key(C2, r, curve); 
	if (rc == TC_CRYPTO_FAIL) { 
		LOG_DBG("caculate C2 failed");
		return rc;
	}
	// caculate r*K
	rc = uECC_shared_secret(public_key_be, r, secret, curve); 
	if (rc == TC_CRYPTO_FAIL) { 
		LOG_DBG("caculate r*K failed");
		return rc;
	}
	// caculate C1
	uECC_vli_xor(C1, m, secret, 32); 
	// LOG_DBG("ALG");
	// LOG_DBG("m\t\t%s", bt_hex(m,32));
	// LOG_DBG("r\t\t%s", bt_hex(r,32));
	// LOG_DBG("remote_pk\t%s", bt_hex(&public_key_be[0], 64));
	// LOG_DBG("secret\t%s", bt_hex(secret,32));
	// LOG_DBG("C1\t\t%s", bt_hex(C1,32));
	// LOG_DBG("C2\t\t%s", bt_hex(C2,64));
	return rc;
}

static uint8_t ecc_data_decrypt(uint8_t *M){
	LOG_DBG("ecc_data_decrypt");
	const struct uECC_Curve_t *curve = uECC_secp256r1();
	uint8_t secret[32] = {0};
	// uint8_t private_key_le[32] = {0};
	int rc;
	// sys_memcpy_swap(&private_key_le[0], private_key_be, sizeof(private_key_be));	
	sys_mem_swap(C2, 64);	
	sys_mem_swap(C1, 32);	
	// caculate secret	
	// rc = uECC_shared_secret(C2, &private_key_le[0], secret, curve); // prv C2
	rc = uECC_shared_secret(C2, private_key_be, secret, curve); // prv C2
	if (rc == TC_CRYPTO_FAIL) { 
		LOG_DBG("shared_secret() failed (1)\n");
		return rc;
	}
	// caculate M
	uECC_vli_xor(M, C1, secret, 32); 

	// LOG_DBG("ALG");
	// LOG_DBG("secret\t\t%s", bt_hex(secret, 32));
	// LOG_DBG("C1\t\t%s", bt_hex(C1, 32));
	// LOG_DBG("C2\t\t%s", bt_hex(C2, 64));
	// LOG_DBG("M\t\t%s", bt_hex(M, 32));
	return rc;
}


static uint8_t o_ecc_data_encrypt(uint8_t *m){
	LOG_DBG("o_ecc_data_encrypt");
	uint8_t r[32] = {0}, secret[64] = {0};
	int rc;
	
	const struct uECC_Curve_t *curve = uECC_secp256r1();
	// caculate C2	
	rc = uECC_make_key(OC2, r, curve); 
	if (rc == TC_CRYPTO_FAIL) { 
		LOG_DBG("caculate C2 failed");
		return rc;
	}
	// caculate r*K
	rc = uECC_shared_secret(public_key_be, r, secret, curve); 
	if (rc == TC_CRYPTO_FAIL) { 
		LOG_DBG("caculate r*K failed");
		return rc;
	}
	// caculate C1
	uECC_vli_addo(OC1, m, secret, 64); 
	return rc;
}

static uint8_t o_ecc_data_decrypt(uint8_t *M){
	LOG_DBG("o_ecc_data_decrypt");
	const struct uECC_Curve_t *curve = uECC_secp256r1();
	uint8_t secret[64] = {0};
	// uint8_t private_key_le[32] = {0};
	int rc;
	LOG_DBG("1");
	// sys_memcpy_swap(&private_key_le[0], private_key_be, sizeof(private_key_be));	
	sys_mem_swap(OC2, 64);	
	sys_mem_swap(OC1, 64);	
	LOG_DBG("1");
	// caculate secret	
	// rc = uECC_shared_secret(C2, &private_key_le[0], secret, curve); // prv C2
	rc = uECC_shared_secret(OC2, private_key_be, secret, curve); // prv C2
	if (rc == TC_CRYPTO_FAIL) { 
		LOG_DBG("shared_secret() failed (1)\n");
		return rc;
	}
	LOG_DBG("1");
	// caculate M
	uECC_vli_addo(M, OC1, secret, 64); 
	return rc;
}


static void pro_ecc_enc(){
	uint8_t text_val[32] = {
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00
	};
	ecc_data_encrypt(&text_val[0]);
}

static void pro_ecc_dec(){
	uint8_t text_val[32] = {
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00
	};
	ecc_data_decrypt(&text_val[0]);
}

static void o_ecc_enc(){
	uint8_t text_val[32] = {
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00
	};
	o_ecc_data_encrypt(&text_val[0]);
}

static void o_ecc_dec(){
	uint8_t text_val[32] = {
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00
	};
	o_ecc_data_decrypt(&text_val[0]);
}


void main(void)
{	

	int err = bt_enable(NULL);
	if (err) {
		LOG_DBG("Bluetooth init failed (err %d)", err);
		return;
	}
	k_sleep(K_SECONDS(5));


	generate_keys();

	LOG_DBG("start");
	for (int i = 1; i <= 5; i++)
	{
		k_sleep(K_SECONDS(1));
		for (int j = 0; j < 1000; j++){
			for (int k = 0; k < i; k++){
				pro_ecc_enc();
			}
		}
		LOG_DBG("finished %i",i);
	}
	k_sleep(K_SECONDS(5));

	LOG_DBG("start");
	for (int i = 1; i <= 5; i++)
	{
		k_sleep(K_SECONDS(1));
		for (int j = 0; j < 1000; j++)
			for (int k = 0; k < i; k++)
				pro_ecc_dec();
		LOG_DBG("finished %i",i);
	}
	k_sleep(K_SECONDS(5));

	LOG_DBG("start");
	for (int i = 1; i <= 3; i++)
	{
		k_sleep(K_SECONDS(1));
		for (int j = 0; j < 1000; j++)
			for (int k = 0; k < i; k++)
				o_ecc_enc();
		LOG_DBG("finished %i",i);
	}
	k_sleep(K_SECONDS(5));

	LOG_DBG("start");
	for (int i = 1; i <= 3; i++)
	{
		k_sleep(K_SECONDS(1));
		for (int j = 0; j < 1000; j++)
			for (int k = 0; k < i; k++)
				o_ecc_dec();
		LOG_DBG("finished %i",i);
	}

}