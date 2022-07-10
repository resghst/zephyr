/* main.c - Application main entry point */

/*
 * Copyright (c) 2015-2016 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdio.h>
#include <stdbool.h>
#include <zephyr/types.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <sys/printk.h>
#include <sys/byteorder.h>
#include <zephyr.h>
#include <device.h>
#include <string.h>
#include "ecc.h"

#include <tinycrypt/constants.h>
#include <tinycrypt/aes.h>
#include <tinycrypt/utils.h>
#include <tinycrypt/cmac_mode.h>
#include <crypto/cipher.h>

#define LOG_LEVEL CONFIG_CRYPTO_LOG_LEVEL
#include <logging/log.h>
LOG_MODULE_REGISTER(main, LOG_LEVEL_DBG);

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_vs.h>
#include <bluetooth/conn.h>
#include <bluetooth/uuid.h>
#include <bluetooth/gatt.h>
#include <bluetooth/services/bas.h>
#include <bluetooth/ecc.h>

// #ifdef CONFIG_CRYPTO_TINYCRYPT_SHIM
// #define CRYPTO_DRV_NAME CONFIG_CRYPTO_TINYCRYPT_SHIM_DRV_NAME
// #elif CONFIG_CRYPTO_MBEDTLS_SHIM
// #define CRYPTO_DRV_NAME CONFIG_CRYPTO_MBEDTLS_SHIM_DRV_NAME
// #elif DT_HAS_COMPAT_STATUS_OKAY(st_stm32_cryp)
// #define CRYPTO_DRV_NAME DT_LABEL(DT_INST(0, st_stm32_cryp))
// #elif DT_HAS_COMPAT_STATUS_OKAY(st_stm32_aes)
// #define CRYPTO_DRV_NAME DT_LABEL(DT_INST(0, st_stm32_aes))
// #elif CONFIG_CRYPTO_NRF_ECB
// #define CRYPTO_DRV_NAME DT_LABEL(DT_INST(0, nordic_nrf_ecb))
// #else
// #error "You need to enable one crypto device"
// #endif

#define SENSOR_1_NAME "Sensor 1"

/* Sensor Internal Update Interval [seconds] */
#define SENSOR_1_UPDATE_IVAL 4

/* ESS error definitions */
#define ESS_ERR_WRITE_REJECT 0x80
#define ESS_ERR_COND_NOT_SUPP 0x81

const struct device *tmpdev;
static bool simulate_temp;
static struct bt_conn *default_conn;
static uint16_t default_conn_handle;
// static struct bt_uuid_16 uuid = BT_UUID_INIT_16(0);
// static struct bt_gatt_discover_params discover_params;
// static struct bt_gatt_subscribe_params subscribe_params, subscribe_params1;

/* security setting */
enum enc_mode
{
	ENC_AES_MODE,
	ENC_ECC_MODE
};
bool aes_finished = false, ecc_c1_finished = false, ecc_c2_finished = false;
bool pkt[4] = {0};

/* Environmental Sensing Service Declaration */
struct ecc_data{
	uint8_t c1[32];
	uint8_t c2[64];
} __packed;
struct app_key{
	uint8_t pub_256[64];
	uint8_t pri_256[32];
	uint8_t pub_192[48];
	uint8_t pri_192[24];
};
struct app_pkt1{
	uint8_t pub_256[64];
	uint8_t pub_192[48];
	uint8_t tk[8];
} __packed;
struct app_pkt2{
	uint8_t rk[64];
	uint8_t dh1[48];
	uint8_t mac[8];
} __packed;
struct app_pkt3{
	uint8_t verify_key[64];
	uint8_t dh2[48];
	uint8_t mac[8];
} __packed;
struct app_pkt4{
	uint8_t passenger_tk[76];
} __packed;
struct temperature_sensor {
	uint8_t aes_value;
	struct ecc_data ecc_value;
	struct app_pkt1 pkt1;
	struct app_pkt2 pkt2;
	struct app_pkt3 pkt3;
	struct app_pkt4 pkt4;
};

static struct app_key key_data;
static struct app_pkt3 pkt3;
static struct temperature_sensor sensor_1;
// static bool disconnect = 0;
static int mtu_changed = 0;

static void set_tx_power(uint8_t handle_type, uint16_t handle, int8_t tx_pwr_lvl)
{
	struct bt_hci_cp_vs_write_tx_power_level *cp;
	struct bt_hci_rp_vs_write_tx_power_level *rp;
	struct net_buf *buf, *rsp = NULL;
	int err;

	buf = bt_hci_cmd_create(BT_HCI_OP_VS_WRITE_TX_POWER_LEVEL,
				sizeof(*cp));
	if (!buf) {
		printk("Unable to allocate command buffer\n");
		return;
	}

	cp = net_buf_add(buf, sizeof(*cp));
	cp->handle = sys_cpu_to_le16(handle);
	cp->handle_type = handle_type;
	cp->tx_power_level = tx_pwr_lvl;

	err = bt_hci_cmd_send_sync(BT_HCI_OP_VS_WRITE_TX_POWER_LEVEL,
				   buf, &rsp);
	if (err) {
		uint8_t reason = rsp ?
			((struct bt_hci_rp_vs_write_tx_power_level *)
			  rsp->data)->status : 0;
		printk("Set Tx power err: %d reason 0x%02x\n", err, reason);
		return;
	}

	rp = (void *)rsp->data;
	printk("Actual Tx Power: %d\n", rp->selected_tx_power);

	net_buf_unref(rsp);
}

// static void get_tx_power(uint8_t handle_type, uint16_t handle, int8_t *tx_pwr_lvl)
// {
// 	struct bt_hci_cp_vs_read_tx_power_level *cp;
// 	struct bt_hci_rp_vs_read_tx_power_level *rp;
// 	struct net_buf *buf, *rsp = NULL;
// 	int err;

// 	*tx_pwr_lvl = 0xFF;
// 	buf = bt_hci_cmd_create(BT_HCI_OP_VS_READ_TX_POWER_LEVEL,
// 				sizeof(*cp));
// 	if (!buf) {
// 		printk("Unable to allocate command buffer\n");
// 		return;
// 	}

// 	cp = net_buf_add(buf, sizeof(*cp));
// 	cp->handle = sys_cpu_to_le16(handle);
// 	cp->handle_type = handle_type;

// 	err = bt_hci_cmd_send_sync(BT_HCI_OP_VS_READ_TX_POWER_LEVEL,
// 				   buf, &rsp);
// 	if (err) {
// 		uint8_t reason = rsp ?
// 			((struct bt_hci_rp_vs_read_tx_power_level *)
// 			  rsp->data)->status : 0;
// 		printk("Read Tx power err: %d reason 0x%02x\n", err, reason);
// 		return;
// 	}

// 	rp = (void *)rsp->data;
// 	*tx_pwr_lvl = rp->tx_power_level;

// 	printk("Read Tx Power: %d\n", rp->tx_power_level);
// 	net_buf_unref(rsp);
// }

static int aes_cmac(const uint8_t *key, const uint8_t *in, size_t len,
			   uint8_t *out)
{
	struct tc_aes_key_sched_struct sched;
	struct tc_cmac_struct state;
	if (tc_cmac_setup(&state, key, &sched) == TC_CRYPTO_FAIL) {
		return -EIO;
	}

	if (tc_cmac_update(&state, in, len) == TC_CRYPTO_FAIL) {
		return -EIO;
	}

	if (tc_cmac_final(out, &state) == TC_CRYPTO_FAIL) {
		return -EIO;
	}

	return 0;
}

static void temp_ccc_cfg_changed(const struct bt_gatt_attr *attr, uint16_t value)
{
	LOG_DBG("temp_ccc_cfg_changed");
	simulate_temp = value == BT_GATT_CCC_NOTIFY;
}

static ssize_t write_pkt2(struct bt_conn *conn, const struct bt_gatt_attr *attr, const void *buf, uint16_t len, uint16_t offset, uint8_t flags);
static ssize_t write_pkt4(struct bt_conn *conn, const struct bt_gatt_attr *attr, const void *buf, uint16_t len, uint16_t offset, uint8_t flags);

BT_GATT_SERVICE_DEFINE(ess_svc, 
	BT_GATT_PRIMARY_SERVICE(BT_UUID_ESS),

	BT_GATT_CHARACTERISTIC(BT_UUID_SENSOR_LOCATION, 
				BT_GATT_CHRC_NOTIFY, BT_GATT_PERM_WRITE, 
				NULL, NULL, &sensor_1.pkt1),
	BT_GATT_CHARACTERISTIC(BT_UUID_SC_CONTROL_POINT,
				BT_GATT_CHRC_WRITE, BT_GATT_PERM_WRITE, 
				NULL, write_pkt2, &sensor_1.pkt2),
	BT_GATT_CHARACTERISTIC(BT_UUID_ELEVATION,
				BT_GATT_CHRC_NOTIFY, BT_GATT_PERM_WRITE, 
				NULL, NULL, &sensor_1.pkt3),
	BT_GATT_CHARACTERISTIC(BT_UUID_PRESSURE,
				BT_GATT_CHRC_WRITE, BT_GATT_PERM_WRITE, 
				NULL, write_pkt4, &sensor_1.pkt4),
				
	BT_GATT_CHARACTERISTIC(BT_UUID_TEMPERATURE,
				BT_GATT_CHRC_NOTIFY, 0, 
				NULL, NULL, &sensor_1.aes_value),
	BT_GATT_CHARACTERISTIC(BT_UUID_HUMIDITY,
				BT_GATT_CHRC_NOTIFY, 0, 
				NULL, NULL, &sensor_1.ecc_value),

	BT_GATT_CUD(SENSOR_1_NAME, BT_GATT_PERM_READ),
	BT_GATT_CCC(temp_ccc_cfg_changed, BT_GATT_PERM_READ | BT_GATT_PERM_WRITE),
);

static ssize_t write_pkt2(struct bt_conn *conn, const struct bt_gatt_attr *attr, const void *buf, uint16_t len, uint16_t offset, uint8_t flags)
{
    LOG_DBG("write_pkt2");
	struct app_pkt2 pkt2;
    uint8_t ret = 0;
	if (offset + len > sizeof(pkt2)) { return BT_GATT_ERR(BT_ATT_ERR_INVALID_OFFSET); }
	memcpy(&pkt2, buf, len);
	
    uint8_t ct = secp256r1;
    uint8_t signature_256[ct * 2];
    uint8_t hash[ct];
    hash[0] = 0x2;
    LOG_DBG("P-256 ecdsa_sign");
    ret = set_CT(P256);
    if (ret == 0) { LOG_DBG("set_CT failure"); } 
    ret = ecdsa_sign(key_data.pri_256, hash, signature_256);
    if (ret == 0) { LOG_DBG("ecdsa_sign failure"); }
	
    ct = secp192r1;
    uint8_t local_secret[ct];
    LOG_DBG("################# P-192 local###################");
    ret = ecdh_shared_secret(&pkt2.rk[0], &key_data.pri_192[0], &local_secret[0]);
	
    uint8_t cmac_key[64] = {0}, cmac[16] = {0};
	memcpy(cmac_key, signature_256, 64);
	ret = aes_cmac(cmac_key, local_secret, ct, cmac);

	// struct app_pkt3 pkt3;
	memcpy(pkt3.verify_key, cmac_key, sizeof(pkt3.verify_key));
	memcpy(pkt3.dh2, local_secret, sizeof(pkt3.dh2));
	memcpy(pkt3.mac, cmac, sizeof(pkt3.mac));
	pkt[2]=1;
	// bt_gatt_notify(conn, &ess_svc.attrs[3], &pkt3, sizeof(struct app_pkt3));
    LOG_DBG("end");
	return len;
}

static ssize_t write_pkt4(struct bt_conn *conn, const struct bt_gatt_attr *attr, const void *buf, uint16_t len, uint16_t offset, uint8_t flags)
{
	struct app_pkt4 pkt4;
	LOG_DBG("write_pkt4");
	if (offset + len > sizeof(struct app_pkt4)) { return BT_GATT_ERR(BT_ATT_ERR_INVALID_OFFSET); }
	memcpy(&pkt4, buf, len);
	LOG_DBG("write_pkt4 Finished");
	return len;
}

static void send_pkt1_notify(const struct device *dev, struct bt_conn *conn, const struct bt_gatt_attr *chrc, const struct app_pkt1 *value, struct temperature_sensor *sensor)
{
	LOG_DBG("send_pkt1_notify");
	LOG_DBG("aes notify value: %s", bt_hex(value, sizeof(struct app_pkt1)));
	LOG_DBG("NOW MTU %d", bt_gatt_get_mtu(conn));
	bt_gatt_notify(conn, chrc, value, sizeof(struct app_pkt1));
	LOG_DBG("===================");
}

static void send_pkt3_notify(const struct device *dev, struct bt_conn *conn, const struct bt_gatt_attr *chrc, const struct app_pkt3 *value, struct temperature_sensor *sensor)
{
	LOG_DBG("send_pkt3_notify");
	LOG_DBG("aes notify value: %s", bt_hex(value, sizeof(struct app_pkt3)));
	LOG_DBG("NOW MTU %d", bt_gatt_get_mtu(conn));
	int ret = bt_gatt_notify(conn, chrc, value, sizeof(struct app_pkt3));
	LOG_DBG("err: %u",ret);
}

// static uint8_t ecc_notify_func(struct bt_conn *conn, struct bt_gatt_subscribe_params *params,
// 			   const void *data, uint16_t length)
// {
// 	// struct ecc_data ecc_decrypt;
// 	if (!data) {
// 		LOG_DBG("[UNSUBSCRIBED]");
// 		params->value_handle = 0U;
// 		return BT_GATT_ITER_STOP;
// 	}
// 	// LOG_DBG("[NOTIFICATION] ECC handle %u length %u", params->value_handle, length);
// 	// memcpy(&ecc_decrypt, data, sizeof(ecc_decrypt));
// 	// LOG_DBG("\t\tECC C1 %s", bt_hex(ecc_decrypt.c1, 32));
// 	// LOG_DBG("\t\tECC C2 %s", bt_hex(ecc_decrypt.c2, 64));
// 	// bt_ecc_data_decrypt(ecc_decrypt.c1, ecc_decrypt.c2, ecc_data_decrypt_cb.func);
// 	return BT_GATT_ITER_CONTINUE;
// }

// static uint8_t aes_notify_func(struct bt_conn *conn, struct bt_gatt_subscribe_params *params, const void *data, uint16_t length)
// {
// 	if (!data) {
// 		LOG_DBG("[UNSUBSCRIBED]");
// 		params->value_handle = 0U;
// 		return BT_GATT_ITER_STOP;
// 	}
	
// 	// uint8_t plaintext[16], enc_data[16];
// 	// memcpy(&enc_data[0], data, sizeof(uint8_t)*length);
// 	// LOG_DBG("[NOTIFICATION] AES handle %u length %d recived %s", params->value_handle, length, bt_hex(&enc_data[0], sizeof(uint8_t)*length));
// 	// bt_proposed_decrypt_le(aes_key, &plaintext[0], &enc_data[0], shift_key);
// 	// LOG_DBG("\t\tDecrypted: %s", bt_hex(&plaintext[0], 16));
// 	return BT_GATT_ITER_CONTINUE;
// }

int flagccc=0;
// static void send_aes_notify(const struct device *dev, struct bt_conn *conn, const struct bt_gatt_attr *chrc, uint8_t *value, struct temperature_sensor *sensor)
// {
// 	LOG_DBG("send_aes_notify");
// 	LOG_DBG("aes notify value: %s", bt_hex(value, 16));
// 	bt_gatt_notify(conn, chrc, value, 16);
// }

// static void send_ecc_notify(const struct device *dev, struct bt_conn *conn, const struct bt_gatt_attr *chrc, const struct ecc_data *value,  struct temperature_sensor *sensor)
// {
// 	LOG_DBG("send_ecc_notify");
// 	bt_gatt_notify(conn, chrc, value, 128);
// }

// int ecc_free=1;
// static void bt_ecc_data_encrypt_finished(const uint8_t *C1, const uint8_t *C2)
// {	
// 	//to do c1 c1 wapper
// 	LOG_DBG("bt_ecc_data_encrypt_finished");
// 	struct ecc_data c;
// 	memcpy(c.c1, C1, sizeof(c.c1));
// 	memcpy(c.c2, C2, sizeof(c.c2));
// 	LOG_DBG("C1 %s", bt_hex(C1, 32)); 
// 	LOG_DBG("C2 %s", bt_hex(C2, 64));
// 	//to do uuid at chr (finished)
// 	send_ecc_notify(tmpdev, NULL, &ess_svc.attrs[3], &c, &sensor_1); // BT_UUID_HUMIDITY
// 	// LOG_DBG("=============================");
// 	k_sleep(K_SECONDS(1));
// 	ecc_free=1;
// }

// static struct bt_ecc_data_encrypt_cb ecc_encrypt_cb = {
// 	.func = bt_ecc_data_encrypt_finished,
// };

// uint8_t *shift_key, *pub_key, *aes_key;
// static void ess_simulate(struct bt_conn *conn, const struct device *dev, const uint8_t mode)
// {
// 	// to do key use conn object data
// 	switch (mode)
// 	{
// 		case ENC_AES_MODE:
// 		{
// 			uint8_t ecb_plaintext[16] = {
// 				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
// 				0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00
// 			};
// 			uint8_t enc_data[16];
// 			bt_proposed_encrypt_le(aes_key, &ecb_plaintext[0],&enc_data[0], shift_key);
// 			//to do uuid at chr (finished)
// 			LOG_DBG("aes plaintext: %s", bt_hex(&ecb_plaintext[0], 16));
// 			LOG_DBG("aes encryptd: %s", bt_hex(&enc_data[0], 16));
// 			send_aes_notify(tmpdev, NULL, &ess_svc.attrs[2], &enc_data[0], &sensor_1); // BT_UUID_TEMPERATURE
// 			break;
// 		}
// 		case ENC_ECC_MODE:
// 		{
// 			LOG_DBG("ECC MTU size is: %d\n", bt_gatt_get_mtu(conn));
// 			uint8_t text_val[32] = {
// 				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
// 				0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00,
// 				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
// 				0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00
// 			};
// 			ecc_free=0;
// 			LOG_DBG("ECC plaintext: %s", bt_hex(&text_val[0], 32));
// 			bt_ecc_data_encrypt(&text_val[0], pub_key, ecc_encrypt_cb.func);
// 			break;
// 		}
// 	default:
// 		LOG_ERR("Encryption mode is not defined.");
// 		break;
// 	}

// }

int mtu_working=0;
void mtu_updated(struct bt_conn *conn, uint16_t tx, uint16_t rx){
	LOG_DBG("mtu_updated, %u", ++mtu_changed);
	LOG_DBG("Updated MTU: TX: %d RX: %d bytes", tx, rx);
	default_conn = conn;
}

static struct bt_gatt_cb gatt_callbacks = {
	.att_mtu_updated = mtu_updated
};

static const struct bt_data ad[] = {
	BT_DATA_BYTES(BT_DATA_FLAGS, (BT_LE_AD_GENERAL | BT_LE_AD_NO_BREDR)),
	BT_DATA_BYTES(BT_DATA_GAP_APPEARANCE, 0x00, 0x03),
	BT_DATA_BYTES(BT_DATA_UUID16_ALL,  BT_UUID_16_ENCODE(BT_UUID_ESS_VAL),
	),
};

static void connected(struct bt_conn *conn, uint8_t err)
{
	char addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));

	if (err) {
		LOG_DBG("Faiㄠled to connect to %s (%u)", addr, err);
		return;
	}

	LOG_DBG("Connected %s", addr);
	// LOG_DBG("SET security: bt_conn_set_security");
	// if (bt_conn_set_security(conn, BT_SECURITY_L1)) {
	// 	LOG_DBG("Failed to set security");
	// }
	int8_t tx_power = 8;
	set_tx_power(BT_HCI_VS_LL_HANDLE_TYPE_CONN, default_conn_handle, tx_power);
	default_conn = conn;
}

static void disconnected(struct bt_conn *conn, uint8_t reason)
{
	char addr[BT_ADDR_LE_STR_LEN];
	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));
	LOG_DBG("Disconnected from %s (reason 0x%02x)", addr, reason);
	LOG_DBG("++++++++++++++++++++++++++++++++++++++++++++++++++++");
}

static struct bt_conn_cb conn_callbacks = {
	.connected = connected,
	.disconnected = disconnected, 
};

static void auth_passkey_display(struct bt_conn *conn, unsigned int passkey)
{
	char addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));
	LOG_DBG("Passkey for %s: %06u", addr, passkey);
}

static void auth_cancel(struct bt_conn *conn)
{
	char addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));
	LOG_DBG("Pairing cancelled: %s", addr);
}

static void pairing_complete(struct bt_conn *conn, bool bonded)
{
	char addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));

	LOG_DBG("Pairing Complete to addr: %s", addr);
	LOG_DBG("enc_key: %d", bt_conn_enc_key_size(conn));
	LOG_DBG("security_level: %d", bt_conn_get_security(conn));
}

static void pairing_failed(struct bt_conn *conn, enum bt_security_err reason)
{
	LOG_DBG("Pairing Failed (%d). Disconnecting.", reason);
	bt_conn_disconnect(conn, BT_HCI_ERR_AUTH_FAIL);
}

static struct bt_conn_auth_cb auth_cb_display = {
	.passkey_display = auth_passkey_display,
	.passkey_entry = NULL,
	.cancel = auth_cancel,
	.pairing_complete = pairing_complete,
	.pairing_failed = pairing_failed,
	.pairing_confirm = NULL,
};

static int start_auth_data_send(const struct device* dev)
{
	LOG_DBG("start_auth_data_send\n");

    uint8_t ct = secp256r1, ret = 0;
    uint8_t public_key_256[ct + 1], private_key_256[ct];
    ret = set_CT(P256);
    if (ret == 0) {
        LOG_DBG("set_CT failure");
        return 0;
    }
    ret = ecc_make_key(public_key_256, private_key_256);
    if (ret == 0) { 
		LOG_DBG("ecc_make_key failure\n"); 
        return 0;
	}    
	LOG_DBG("=== P256 Info ===");
	LOG_DBG("Pub: %s",bt_hex(&public_key_256[0], ct + 1));
	LOG_DBG("Pri: %s",bt_hex(&private_key_256[0], ct));

    ct = secp192r1;
    uint8_t public_key_192[ct + 1];
    uint8_t private_key_192[ct];
    ret = set_CT(P192);
    if (ret == 0) { LOG_DBG("set_CT failure\n"); } 
    
    ret = ecc_make_key(public_key_192, private_key_192);
    if (ret == 0) {
        LOG_DBG("ecc_make_key failure\n");
        return 0;
    }
	LOG_DBG("=== P192 Info ===");
	LOG_DBG("Pub: %s",bt_hex(&public_key_192[0], ct + 1));
	LOG_DBG("Pri: %s",bt_hex(&private_key_192[0], ct));

	memcpy(key_data.pub_256, &public_key_256[0], secp256r1+1);
	memcpy(key_data.pri_256, &private_key_256[0], secp256r1);
	memcpy(key_data.pub_192, &public_key_192[0], secp192r1+1);
	memcpy(key_data.pri_192, &private_key_192[0], secp192r1);
	pkt[0]=1;

	while (1) {
		k_sleep(K_SECONDS(5));
		// LOG_DBG("SUCCESS!!!!");
		if(pkt[0]){
			struct app_pkt1 pkt1;
			memcpy(pkt1.pub_192, &key_data.pub_192[0], sizeof(pkt1.pub_192));
			memcpy(pkt1.pub_256, &key_data.pub_256[0], sizeof(pkt1.pub_256));
			send_pkt1_notify(tmpdev, default_conn, &ess_svc.attrs[1], &pkt1, &sensor_1);
			pkt[0]=0;
			// break;
		}
		if(pkt[2]){
			send_pkt3_notify(tmpdev, default_conn, &ess_svc.attrs[5], &pkt3, &sensor_1);
			pkt[2]=0;
		}

		
	}
	return -1;
}

static int start_data_send(const struct device* dev)
{
	while (1){
		k_sleep(K_SECONDS(3));
		if (simulate_temp && mtu_changed==2) {
		// if (simulate_temp ) {
			start_auth_data_send(dev);
			break;
		}
	}
	return -1;
}

void main(void)
{	
	LOG_INF("DEV: Slave");

	int err;
	const struct device *dev = NULL;
	// const struct device *dev = device_get_binding(CRYPTO_DRV_NAME);
	// if (!dev) {
	// 	LOG_ERR("%s pseudo device not found", CRYPTO_DRV_NAME);
	// 	return;
	// }

	err = bt_enable(NULL);
	if (err) {
		LOG_DBG("Bluetooth init failed (err %d)", err);
		return;
	}

	LOG_DBG("Bluetooth initialized");
	// bt_passkey_set(0);
	bt_conn_auth_cb_register(&auth_cb_display);
	bt_conn_cb_register(&conn_callbacks);
	bt_gatt_cb_register(&gatt_callbacks);

	err = bt_le_adv_start(BT_LE_ADV_CONN_NAME, ad, ARRAY_SIZE(ad), NULL, 0);
	if (err) {
		LOG_DBG("Advertising failed to start (err %d)", err);
		return;
	}

	LOG_DBG("Advertising successfully started");
	tmpdev = dev;
	err = start_data_send(dev);
	if (err) {
		LOG_DBG("Disconnect failed (err %d)", err);
		return;
	}

}