/**
 * @file hci_ecc.c
 * HCI ECC emulation
 */

/*
 * Copyright (c) 2016 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr.h>
#include <sys/atomic.h>
#include <debug/stack.h>
#include <sys/byteorder.h>
#include <tinycrypt/constants.h>
#include <tinycrypt/utils.h>
#include <tinycrypt/ecc.h>
#include <tinycrypt/ecc_dh.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/conn.h>
#include <bluetooth/hci.h>
#include <drivers/bluetooth/hci_driver.h>

#define BT_DBG_ENABLED IS_ENABLED(CONFIG_BT_DEBUG_HCI_CORE)
#define LOG_MODULE_NAME bt_hci_ecc
#include "common/log.h"

#include "hci_ecc.h"
#ifdef CONFIG_BT_HCI_RAW
#include <bluetooth/hci_raw.h>
#include "hci_raw_internal.h"
#else
#include "hci_core.h"
#endif

static struct k_thread ecc_thread_data;
static K_KERNEL_STACK_DEFINE(ecc_thread_stack, CONFIG_BT_HCI_ECC_STACK_SIZE);

/* based on Core Specification 4.2 Vol 3. Part H 2.3.5.6.1 */
static const uint8_t debug_private_key_be[32] = {
	0x3f, 0x49, 0xf6, 0xd4, 0xa3, 0xc5, 0x5f, 0x38,
	0x74, 0xc9, 0xb3, 0xe3, 0xd2, 0x10, 0x3f, 0x50,
	0x4a, 0xff, 0x60, 0x7b, 0xeb, 0x40, 0xb7, 0x99,
	0x58, 0x99, 0xb8, 0xa6, 0xcd, 0x3c, 0x1a, 0xbd,
};

enum {
	PENDING_PUB_KEY,
	PENDING_DHKEY,
	PENDING_ECC_DATA_ENCRYPT,
	PENDING_ECC_DATA_DECRYPT,

	USE_DEBUG_KEY,

	/* Total number of flags - must be at the end of the enum */
	NUM_FLAGS,
};

static ATOMIC_DEFINE(flags, NUM_FLAGS);

static K_SEM_DEFINE(cmd_sem, 0, 1);

static struct {
	uint8_t private_key_be[32];

	union {
		uint8_t public_key_be[64];
		uint8_t dhkey_be[32];
	};
} ecc;

static struct bt_hci_cp_le_ecc_data_encrypt ecc_encrypt_data;
static struct bt_hci_cp_le_ecc_data_decrypt ecc_decrypt_data;

static void send_cmd_status(uint16_t opcode, uint8_t status)
{
	struct bt_hci_evt_cmd_status *evt;
	struct bt_hci_evt_hdr *hdr;
	struct net_buf *buf;

	BT_DBG("opcode %x status %x", opcode, status);

	buf = bt_buf_get_evt(BT_HCI_EVT_CMD_STATUS, false, K_FOREVER);
	bt_buf_set_type(buf, BT_BUF_EVT);

	hdr = net_buf_add(buf, sizeof(*hdr));
	hdr->evt = BT_HCI_EVT_CMD_STATUS;
	hdr->len = sizeof(*evt);

	evt = net_buf_add(buf, sizeof(*evt));
	evt->ncmd = 1U;
	evt->opcode = sys_cpu_to_le16(opcode);
	evt->status = status;

	if (IS_ENABLED(CONFIG_BT_RECV_IS_RX_THREAD)) {
		bt_recv_prio(buf);
	} else {
		bt_recv(buf);
	}
}

static uint8_t generate_keys(void)
{
	do {
		int rc;

		rc = uECC_make_key(ecc.public_key_be, ecc.private_key_be,
				   &curve_secp256r1);
		if (rc == TC_CRYPTO_FAIL) {
			BT_ERR("Failed to create ECC public/private pair");
			return BT_HCI_ERR_UNSPECIFIED;
		}

	/* make sure generated key isn't debug key */
	} while (memcmp(ecc.private_key_be, debug_private_key_be, 32) == 0);

	if (IS_ENABLED(CONFIG_BT_LOG_SNIFFER_INFO)) {
		BT_INFO("SC private key 0x%s", bt_hex(ecc.private_key_be, 32));
	}
	BT_INFO("SC private key 0x%s", bt_hex(&ecc.private_key_be[0], 32));
	BT_INFO("SC public  key 0x%s", bt_hex(&ecc.public_key_be[0], 64));

	return 0;
}

static uint8_t ecc_data_encrypt(uint8_t *m, uint8_t *C1, uint8_t *C2){
	uint8_t r[32] = {0}, secret[32] = {0};
	int rc;
	
	// caculate C2	
	rc = uECC_make_key(C2, r, &curve_secp256r1); 
	if (rc == TC_CRYPTO_FAIL) { 
		BT_ERR("caculate C2 failed");
		return rc;
	}
	// caculate r*K
	rc = uECC_shared_secret(ecc_encrypt_data.remote_pk, r, secret, &curve_secp256r1); 
	if (rc == TC_CRYPTO_FAIL) { 
		BT_ERR("caculate r*K failed");
		return rc;
	}
	// caculate C1
	uECC_vli_xor(C1, m, secret, 32); 
	BT_DBG("ALG");
	BT_DBG("m\t\t%s", bt_hex(m,32));
	BT_DBG("r\t\t%s", bt_hex(r,32));
	BT_DBG("remote_pk\t%s", bt_hex(&ecc_encrypt_data.remote_pk[0], 64));
	BT_DBG("secret\t%s", bt_hex(secret,32));
	BT_DBG("C1\t\t%s", bt_hex(C1,32));
	BT_DBG("C2\t\t%s", bt_hex(C2,64));
	return rc;
}

static uint8_t ecc_data_decrypt(uint8_t *M, uint8_t *C1, uint8_t *C2){
	BT_DBG("ecc_data_decrypt");
	uint8_t secret[32] = {0};
	// uint8_t private_key_le[32] = {0};
	int rc;
	// sys_memcpy_swap(&private_key_le[0], ecc.private_key_be, sizeof(ecc.private_key_be));	
	sys_mem_swap(C2, 64);	
	sys_mem_swap(C1, 32);	
	// caculate secret	
	// rc = uECC_shared_secret(C2, &private_key_le[0], secret, &curve_secp256r1); // prv C2
	rc = uECC_shared_secret(C2, ecc.private_key_be, secret, &curve_secp256r1); // prv C2
	if (rc == TC_CRYPTO_FAIL) { 
		BT_ERR("shared_secret() failed (1)\n");
		return rc;
	}
	// caculate M
	uECC_vli_xor(M, C1, secret, 32); 

	BT_DBG("ALG");
	BT_DBG("secret\t\t%s", bt_hex(secret, 32));
	BT_DBG("C1\t\t%s", bt_hex(C1, 32));
	BT_DBG("C2\t\t%s", bt_hex(C2, 64));
	BT_DBG("M\t\t%s", bt_hex(M, 32));
	return rc;
}

static void emulate_le_p256_public_key_cmd(void)
{
	struct bt_hci_evt_le_p256_public_key_complete *evt;
	struct bt_hci_evt_le_meta_event *meta;
	struct bt_hci_evt_hdr *hdr;
	struct net_buf *buf;
	uint8_t status;

	BT_DBG("emulate_le_p256_public_key_cmd");

	status = generate_keys();

	buf = bt_buf_get_rx(BT_BUF_EVT, K_FOREVER);

	hdr = net_buf_add(buf, sizeof(*hdr));
	hdr->evt = BT_HCI_EVT_LE_META_EVENT;
	hdr->len = sizeof(*meta) + sizeof(*evt);

	meta = net_buf_add(buf, sizeof(*meta));
	meta->subevent = BT_HCI_EVT_LE_P256_PUBLIC_KEY_COMPLETE;

	evt = net_buf_add(buf, sizeof(*evt));
	evt->status = status;

	if (status) {
		(void)memset(evt->key, 0, sizeof(evt->key));
	} else {
		/* Convert X and Y coordinates from big-endian (provided
		 * by crypto API) to little endian HCI.
		 */
		sys_memcpy_swap(evt->key, ecc.public_key_be, 32);
		sys_memcpy_swap(&evt->key[32], &ecc.public_key_be[32], 32);
	}

	atomic_clear_bit(flags, PENDING_PUB_KEY);

	bt_recv(buf);
}

static void emulate_le_generate_dhkey(void)
{
	BT_DBG("emulate_le_generate_dhkey");
	struct bt_hci_evt_le_generate_dhkey_complete *evt;
	struct bt_hci_evt_le_meta_event *meta;
	struct bt_hci_evt_hdr *hdr;
	struct net_buf *buf;
	int ret;

	ret = uECC_valid_public_key(ecc.public_key_be, &curve_secp256r1);
	if (ret < 0) {
		BT_ERR("public key is not valid (ret %d)", ret);
		ret = TC_CRYPTO_FAIL;
	} else {
		bool use_debug = atomic_test_bit(flags, USE_DEBUG_KEY);

		ret = uECC_shared_secret(ecc.public_key_be,
					 use_debug ? debug_private_key_be : ecc.private_key_be,
					 ecc.dhkey_be, &curve_secp256r1);
	}

	buf = bt_buf_get_rx(BT_BUF_EVT, K_FOREVER);

	hdr = net_buf_add(buf, sizeof(*hdr));
	hdr->evt = BT_HCI_EVT_LE_META_EVENT;
	hdr->len = sizeof(*meta) + sizeof(*evt);

	meta = net_buf_add(buf, sizeof(*meta));
	meta->subevent = BT_HCI_EVT_LE_GENERATE_DHKEY_COMPLETE;

	evt = net_buf_add(buf, sizeof(*evt));

	if (ret == TC_CRYPTO_FAIL) {
		evt->status = BT_HCI_ERR_UNSPECIFIED;
		(void)memset(evt->dhkey, 0xff, sizeof(evt->dhkey));
	} else {
		evt->status = 0U;
		/* Convert from big-endian (provided by crypto API) to
		 * little-endian HCI.
		 */
		sys_memcpy_swap(evt->dhkey, ecc.dhkey_be, sizeof(ecc.dhkey_be));
	}

	atomic_clear_bit(flags, PENDING_DHKEY);

	bt_recv(buf);
}

static void emulate_le_ecc_data_encrypt_cmd(void)
{
	BT_DBG("emulate_le_ecc_data_encrypt_cmd");
	struct bt_hci_evt_le_ecc_data_encrypt_complete *evt;
	struct bt_hci_evt_le_meta_event *meta;
	struct bt_hci_evt_hdr *hdr;
	struct net_buf *buf;
	int ret;
	uint8_t C2[64] = {0}, C1[32] = {0};
	BT_DBG("plaintext %s", bt_hex(&ecc_encrypt_data.plaintext[0], 32));

	ret = ecc_data_encrypt(&ecc_encrypt_data.plaintext[0], &C1[0], &C2[0]);
	buf = bt_buf_get_rx(BT_BUF_EVT, K_FOREVER);

	hdr = net_buf_add(buf, sizeof(*hdr));
	hdr->evt = BT_HCI_EVT_LE_META_EVENT;
	hdr->len = sizeof(*meta) + sizeof(*evt);

	meta = net_buf_add(buf, sizeof(*meta));
	meta->subevent = BT_HCI_EVT_LE_ECC_DATA_ENCRYPTION_COMPLETE;

	evt = net_buf_add(buf, sizeof(*evt));

	if (ret == TC_CRYPTO_FAIL) {
		evt->status = BT_HCI_ERR_UNSPECIFIED;
		(void)memset(evt->C1, 0xffffffff, sizeof(evt->C1));
		(void)memset(evt->C2, 0xffffffff, sizeof(evt->C2));
	} else {
		evt->status = 0U;
		sys_memcpy_swap(evt->C1, C1, sizeof(evt->C1));
		sys_memcpy_swap(evt->C2, C2, sizeof(evt->C2));
		BT_DBG("C1 %s", bt_hex(evt->C1, 32));
		BT_DBG("C2 %s", bt_hex(evt->C2, 64));
	}

	atomic_clear_bit(flags, PENDING_ECC_DATA_ENCRYPT);

	bt_recv(buf);
}

static void emulate_le_ecc_data_decrypt_cmd(void)
{
	BT_DBG("emulate_le_ecc_data_decrypt_cmd");
	struct bt_hci_evt_le_ecc_data_decrypt_complete *evt;
	struct bt_hci_evt_le_meta_event *meta;
	struct bt_hci_evt_hdr *hdr;
	struct net_buf *buf;
	int ret;
	uint8_t m[32] = {0};

	sys_mem_swap(&ecc_decrypt_data.C1[0], 32);
	sys_mem_swap(&ecc_decrypt_data.C2[0], 64);
	BT_DBG("C1 %s", bt_hex(&ecc_decrypt_data.C1[0], 32));
	BT_DBG("C2 %s", bt_hex(&ecc_decrypt_data.C2[0], 64));

	ret = ecc_data_decrypt(&m[0], &ecc_decrypt_data.C1[0], &ecc_decrypt_data.C2[0]);
	buf = bt_buf_get_rx(BT_BUF_EVT, K_FOREVER);

	hdr = net_buf_add(buf, sizeof(*hdr));
	hdr->evt = BT_HCI_EVT_LE_META_EVENT;
	hdr->len = sizeof(*meta) + sizeof(*evt);

	meta = net_buf_add(buf, sizeof(*meta));
	meta->subevent = BT_HCI_EVT_LE_ECC_DATA_DECRYPTION_COMPLETE;

	evt = net_buf_add(buf, sizeof(*evt));

	if (ret == TC_CRYPTO_FAIL) {
		evt->status = BT_HCI_ERR_UNSPECIFIED;
		(void)memset(evt->plaintext, 0xffffffff, sizeof(evt->plaintext));
	} else {
		evt->status = 0U;
		sys_memcpy_swap(evt->plaintext, m, sizeof(evt->plaintext));
		BT_DBG("plaintext %s", bt_hex(evt->plaintext, 32));
	}

	atomic_clear_bit(flags, PENDING_ECC_DATA_DECRYPT);

	bt_recv(buf);
}

static void ecc_thread(void *p1, void *p2, void *p3)
{
	while (true) {
		k_sem_take(&cmd_sem, K_FOREVER);

		if (atomic_test_bit(flags, PENDING_PUB_KEY)) {
			emulate_le_p256_public_key_cmd();
		} else if (atomic_test_bit(flags, PENDING_DHKEY)) {
			emulate_le_generate_dhkey();
		} else if (atomic_test_bit(flags, PENDING_ECC_DATA_ENCRYPT)) {
			emulate_le_ecc_data_encrypt_cmd();
		} else if (atomic_test_bit(flags, PENDING_ECC_DATA_DECRYPT)) {
			emulate_le_ecc_data_decrypt_cmd();
		} else {
			__ASSERT(0, "Unhandled ECC command");
		}
	}
}

static void clear_ecc_events(struct net_buf *buf)
{
	struct bt_hci_cp_le_set_event_mask *cmd;

	cmd = (void *)(buf->data + sizeof(struct bt_hci_cmd_hdr));

	/*
	 * don't enable controller ECC events as those will be generated from
	 * emulation code
	 */
	cmd->events[0] &= ~0x80; /* LE Read Local P-256 PKey Compl */
	cmd->events[1] &= ~0x01; /* LE Generate DHKey Compl Event */
}

static uint8_t le_gen_dhkey(uint8_t *key, uint8_t key_type)
{
	if (atomic_test_bit(flags, PENDING_PUB_KEY)) {
		return BT_HCI_ERR_CMD_DISALLOWED;
	}

	if (key_type > BT_HCI_LE_KEY_TYPE_DEBUG) {
		return BT_HCI_ERR_INVALID_PARAM;
	}

	if (atomic_test_and_set_bit(flags, PENDING_DHKEY)) {
		return BT_HCI_ERR_CMD_DISALLOWED;
	}

	/* Convert X and Y coordinates from little-endian HCI to
	 * big-endian (expected by the crypto API).
	 */
	sys_memcpy_swap(ecc.public_key_be, key, 32);
	sys_memcpy_swap(&ecc.public_key_be[32], &key[32], 32);

	atomic_set_bit_to(flags, USE_DEBUG_KEY,
			  key_type == BT_HCI_LE_KEY_TYPE_DEBUG);

	k_sem_give(&cmd_sem);

	return BT_HCI_ERR_SUCCESS;
}

static uint8_t le_ecc_set_encrypt_data(uint8_t *plaintext, uint8_t *remote_pk)
{
	if (atomic_test_bit(flags, PENDING_PUB_KEY)) {
		return BT_HCI_ERR_CMD_DISALLOWED;
	}
	if (atomic_test_and_set_bit(flags, PENDING_ECC_DATA_ENCRYPT)) {
		return BT_HCI_ERR_CMD_DISALLOWED;
	}

	sys_memcpy_swap(ecc_encrypt_data.plaintext, plaintext, 32);
	memcpy(ecc_encrypt_data.remote_pk, remote_pk, 64);
	
	k_sem_give(&cmd_sem);
	return BT_HCI_ERR_SUCCESS;
}

static uint8_t le_ecc_set_decrypt_data(uint8_t *C1, uint8_t *C2)
{
	if (atomic_test_bit(flags, PENDING_PUB_KEY)) {
		return BT_HCI_ERR_CMD_DISALLOWED;
	}
	if (atomic_test_and_set_bit(flags, PENDING_ECC_DATA_DECRYPT)) {
		return BT_HCI_ERR_CMD_DISALLOWED;
	}

	sys_memcpy_swap(ecc_decrypt_data.C1, C1, 32);
	sys_memcpy_swap(ecc_decrypt_data.C2, C2, 64);
	k_sem_give(&cmd_sem);
	return BT_HCI_ERR_SUCCESS;
}

static void le_gen_dhkey_v1(struct net_buf *buf)
{
	struct bt_hci_cp_le_generate_dhkey *cmd;
	uint8_t status;

	cmd = (void *)buf->data;
	status = le_gen_dhkey(cmd->key, BT_HCI_LE_KEY_TYPE_GENERATED);

	net_buf_unref(buf);
	send_cmd_status(BT_HCI_OP_LE_GENERATE_DHKEY, status);
}

static void le_gen_dhkey_v2(struct net_buf *buf)
{
	struct bt_hci_cp_le_generate_dhkey_v2 *cmd;
	uint8_t status;

	cmd = (void *)buf->data;
	status = le_gen_dhkey(cmd->key, cmd->key_type);

	net_buf_unref(buf);
	send_cmd_status(BT_HCI_OP_LE_GENERATE_DHKEY_V2, status);
}

static void le_p256_pub_key(struct net_buf *buf)
{
	uint8_t status;

	net_buf_unref(buf);

	if (atomic_test_bit(flags, PENDING_DHKEY)) {
		status = BT_HCI_ERR_CMD_DISALLOWED;
	} else if (atomic_test_and_set_bit(flags, PENDING_PUB_KEY)) {
		status = BT_HCI_ERR_CMD_DISALLOWED;
	} else {
		k_sem_give(&cmd_sem);
		status = BT_HCI_ERR_SUCCESS;
	}

	send_cmd_status(BT_HCI_OP_LE_P256_PUBLIC_KEY, status);
}

static void le_ecc_data_encrypt(struct net_buf *buf)
{
	struct bt_hci_cp_le_ecc_data_encrypt  *cmd;
	uint8_t status;

	cmd = (void *)buf->data;
	status = le_ecc_set_encrypt_data(cmd->plaintext, cmd->remote_pk);

	net_buf_unref(buf);
	send_cmd_status(BT_HCI_OP_LE_ECC_DATA_ENCRYPT, status);
}

static void le_ecc_data_decrypt(struct net_buf *buf)
{
	struct bt_hci_cp_le_ecc_data_decrypt  *cmd;
	uint8_t status;

	cmd = (void *)buf->data;
	status = le_ecc_set_decrypt_data(cmd->C1, cmd->C2);

	net_buf_unref(buf);
	send_cmd_status(BT_HCI_OP_LE_ECC_DATA_DECRYPT, status);
}

int bt_hci_ecc_send(struct net_buf *buf)
{
	// BT_INFO("bt_hci_ecc_send");
	if (bt_buf_get_type(buf) == BT_BUF_CMD) {
		struct bt_hci_cmd_hdr *chdr = (void *)buf->data;

		switch (sys_le16_to_cpu(chdr->opcode)) {
		case BT_HCI_OP_LE_P256_PUBLIC_KEY:
			net_buf_pull(buf, sizeof(*chdr));
			le_p256_pub_key(buf);
			return 0;
		case BT_HCI_OP_LE_GENERATE_DHKEY:
			net_buf_pull(buf, sizeof(*chdr));
			le_gen_dhkey_v1(buf);
			return 0;
		case BT_HCI_OP_LE_GENERATE_DHKEY_V2:
			net_buf_pull(buf, sizeof(*chdr));
			le_gen_dhkey_v2(buf);
			return 0;
		case BT_HCI_OP_LE_ECC_DATA_ENCRYPT:
			net_buf_pull(buf, sizeof(*chdr));
			le_ecc_data_encrypt(buf);
			return 0;
		case BT_HCI_OP_LE_ECC_DATA_DECRYPT:
			net_buf_pull(buf, sizeof(*chdr));
			le_ecc_data_decrypt(buf);
			return 0;
		case BT_HCI_OP_LE_SET_EVENT_MASK:
			clear_ecc_events(buf);
			break;
		default:
			break;
		}
	}

	return bt_dev.drv->send(buf);
}

void bt_hci_ecc_supported_commands(uint8_t *supported_commands)
{
	/* LE Read Local P-256 Public Key */
	supported_commands[34] |= BIT(1);
	/* LE Generate DH Key v1 */
	supported_commands[34] |= BIT(2);
	/* LE Generate DH Key v2 */
	supported_commands[41] |= BIT(2);
}

int default_CSPRNG(uint8_t *dst, unsigned int len)
{
	return !bt_rand(dst, len);
}

void bt_hci_ecc_init(void)
{
	k_thread_create(&ecc_thread_data, ecc_thread_stack,
			K_KERNEL_STACK_SIZEOF(ecc_thread_stack), ecc_thread,
			NULL, NULL, NULL, K_PRIO_PREEMPT(10), 0, K_NO_WAIT);
	k_thread_name_set(&ecc_thread_data, "BT ECC");
}
