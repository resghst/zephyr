/* main.c - Application main entry point */

/*
 * Copyright (c) 2015-2016 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stddef.h>
#include <errno.h>

#include <stdbool.h>
#include <zephyr/types.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>

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

#ifdef CONFIG_CRYPTO_TINYCRYPT_SHIM
#define CRYPTO_DRV_NAME CONFIG_CRYPTO_TINYCRYPT_SHIM_DRV_NAME
#elif CONFIG_CRYPTO_MBEDTLS_SHIM
#define CRYPTO_DRV_NAME CONFIG_CRYPTO_MBEDTLS_SHIM_DRV_NAME
#elif DT_HAS_COMPAT_STATUS_OKAY(st_stm32_cryp)
#define CRYPTO_DRV_NAME DT_LABEL(DT_INST(0, st_stm32_cryp))
#elif DT_HAS_COMPAT_STATUS_OKAY(st_stm32_aes)
#define CRYPTO_DRV_NAME DT_LABEL(DT_INST(0, st_stm32_aes))
#elif CONFIG_CRYPTO_NRF_ECB
#define CRYPTO_DRV_NAME DT_LABEL(DT_INST(0, nordic_nrf_ecb))
#else
#error "You need to enable one crypto device"
#endif


#define CUSTOM_CONN_INT_MIN 50
#define CUSTOM_CONN_INT_MAX 50

#define BT_LE_CONN_PARAM_CUSTOM BT_LE_CONN_PARAM(CUSTOM_CONN_INT_MIN, \
						  CUSTOM_CONN_INT_MAX, 0, 400)

static void start_scan(void);
static struct bt_conn *default_conn;
static uint16_t default_conn_handle;
static struct bt_uuid_16 uuid = BT_UUID_INIT_16(0);
static struct bt_gatt_discover_params discover_params;
static struct bt_gatt_subscribe_params subscribe_params, subscribe_params1;

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

static void get_tx_power(uint8_t handle_type, uint16_t handle, int8_t *tx_pwr_lvl)
{
	struct bt_hci_cp_vs_read_tx_power_level *cp;
	struct bt_hci_rp_vs_read_tx_power_level *rp;
	struct net_buf *buf, *rsp = NULL;
	int err;

	*tx_pwr_lvl = 0xFF;
	buf = bt_hci_cmd_create(BT_HCI_OP_VS_READ_TX_POWER_LEVEL,
				sizeof(*cp));
	if (!buf) {
		printk("Unable to allocate command buffer\n");
		return;
	}

	cp = net_buf_add(buf, sizeof(*cp));
	cp->handle = sys_cpu_to_le16(handle);
	cp->handle_type = handle_type;

	err = bt_hci_cmd_send_sync(BT_HCI_OP_VS_READ_TX_POWER_LEVEL,
				   buf, &rsp);
	if (err) {
		uint8_t reason = rsp ?
			((struct bt_hci_rp_vs_read_tx_power_level *)
			  rsp->data)->status : 0;
		printk("Read Tx power err: %d reason 0x%02x\n", err, reason);
		return;
	}

	rp = (void *)rsp->data;
	*tx_pwr_lvl = rp->tx_power_level;

	net_buf_unref(rsp);
}

/* Environmental Sensing Service Declaration */
struct ecc_data{
	uint8_t c1[32];
	uint8_t c2[64];
};

/* security setting */
bool aes_finished = false, ecc_c1_finished = false, ecc_c2_finished = false;
uint8_t *shift_key, *pub_key, *aes_key;

static uint8_t aes_notify_func(struct bt_conn *conn, struct bt_gatt_subscribe_params *params, const void *data, uint16_t length)
{
	if (!data) {
		LOG_DBG("[UNSUBSCRIBED]");
		params->value_handle = 0U;
		return BT_GATT_ITER_STOP;
	}
	
	uint8_t plaintext[16], enc_data[16];
	memcpy(&enc_data[0], data, sizeof(uint8_t)*length);
	LOG_DBG("[NOTIFICATION] AES handle %u length %d recived %s", params->value_handle, length, bt_hex(&enc_data[0], sizeof(uint8_t)*length));
	bt_proposed_decrypt_le(aes_key, &plaintext[0], &enc_data[0], shift_key);
	LOG_DBG("\t\tDecrypted: %s", bt_hex(&plaintext[0], 16));
	return BT_GATT_ITER_CONTINUE;
}

static void bt_ecc_data_decrypt_finished(const uint8_t *M)
{
	LOG_DBG("bt_ecc_data_decrypt_finished");
	LOG_DBG("M %s", bt_hex(M, 32));
	LOG_DBG("=============================");
}

static struct bt_ecc_data_decrypt_cb ecc_data_decrypt_cb = {
	.func = bt_ecc_data_decrypt_finished,
};

static uint8_t ecc_notify_func(struct bt_conn *conn, struct bt_gatt_subscribe_params *params,
			   const void *data, uint16_t length)
{
	struct ecc_data ecc_decrypt;
	if (!data) {
		LOG_DBG("[UNSUBSCRIBED]");
		params->value_handle = 0U;
		return BT_GATT_ITER_STOP;
	}
	LOG_DBG("[NOTIFICATION] ECC handle %u length %u", params->value_handle, length);
	memcpy(&ecc_decrypt, data, sizeof(ecc_decrypt));
	LOG_DBG("\t\tECC C1 %s", bt_hex(ecc_decrypt.c1, 32));
	LOG_DBG("\t\tECC C2 %s", bt_hex(ecc_decrypt.c2, 64));
	bt_ecc_data_decrypt(ecc_decrypt.c1, ecc_decrypt.c2, ecc_data_decrypt_cb.func);
	return BT_GATT_ITER_CONTINUE;
}

int flagccc=0;
static uint8_t discover_func(struct bt_conn *conn, const struct bt_gatt_attr *attr,
			     struct bt_gatt_discover_params *params)
{
	int err;
	if (!attr) { return BT_GATT_ITER_STOP; }

	LOG_DBG("[ATTRIBUTE] handle %u", attr->handle);

	if (!bt_uuid_cmp(discover_params.uuid, BT_UUID_ESS)) { 
		LOG_DBG("Process uuid BT_UUID_TEMPERATURE");
		memcpy(&uuid, BT_UUID_TEMPERATURE, sizeof(uuid));
		discover_params.uuid = &uuid.uuid;
		discover_params.start_handle = attr->handle + 1;
		discover_params.type = BT_GATT_DISCOVER_CHARACTERISTIC;
		err = bt_gatt_discover(conn, &discover_params);
		if (err) { LOG_DBG("Discover failed (err %d)", err); }
	} 
	else if (!bt_uuid_cmp(discover_params.uuid, BT_UUID_TEMPERATURE)) { 
		LOG_DBG("Process uuid BT_UUID_HUMIDITY");
		memcpy(&uuid, BT_UUID_HUMIDITY, sizeof(uuid));
		discover_params.uuid = &uuid.uuid;
		discover_params.start_handle = attr->handle + 2;
		discover_params.type = BT_GATT_DISCOVER_DESCRIPTOR;
		subscribe_params.value_handle = bt_gatt_attr_value_handle(attr);
		err = bt_gatt_discover(conn, &discover_params);
		if (err) { LOG_DBG("Discover failed (err %d)", err); }
	} 
	else if (!bt_uuid_cmp(discover_params.uuid, BT_UUID_HUMIDITY)) { 
		LOG_DBG("Process uuid BT_UUID_GATT_CCC");
		memcpy(&uuid, BT_UUID_GATT_CCC, sizeof(uuid));
		discover_params.uuid = &uuid.uuid;
		discover_params.start_handle = attr->handle + 3;
		discover_params.type = BT_GATT_DISCOVER_DESCRIPTOR;
		subscribe_params1.value_handle = bt_gatt_attr_value_handle(attr);
		err = bt_gatt_discover(conn, &discover_params);
		if (err) { LOG_DBG("Discover failed (err %d)", err); }
	} 
	else if(!bt_uuid_cmp(discover_params.uuid, BT_UUID_GATT_CCC) && !flagccc){
		LOG_DBG("Process subscribed UUID");
		flagccc = 1;
		subscribe_params.notify = aes_notify_func;
		subscribe_params.value = BT_GATT_CCC_NOTIFY;
		subscribe_params.ccc_handle = attr->handle;
		err = bt_gatt_subscribe(conn, &subscribe_params);
		if (err && err != -EALREADY) { LOG_DBG("Subscribe failed (err %d)", err); } 
		else { LOG_DBG("[SUBSCRIBED]"); }

		subscribe_params1.notify = ecc_notify_func;
		subscribe_params1.value = BT_GATT_CCC_NOTIFY;
		subscribe_params1.ccc_handle = attr->handle;
		err = bt_gatt_subscribe(conn, &subscribe_params1);
		if (err && err != -EALREADY) { LOG_DBG("Subscribe failed (err %d)", err); } 
		else { LOG_DBG("[SUBSCRIBED]"); }
		return BT_GATT_ITER_STOP;
	}
	return BT_GATT_ITER_CONTINUE;
}

static bool eir_found(struct bt_data *data, void *user_data)
{
	bt_addr_le_t *addr = user_data;
	int i;
	// LOG_DBG("[AD]: %u data_len %u", data->type, data->data_len);
	
	switch (data->type) {
	case BT_DATA_UUID16_SOME:
	case BT_DATA_UUID16_ALL:
		if (data->data_len % sizeof(uint16_t) != 0U) {
			LOG_DBG("AD malformed");
			return true;
		}
		
		for (i = 0; i < data->data_len; i += sizeof(uint16_t)) {
			LOG_DBG("i: %d, step: %d",i, sizeof(uint16_t));
			struct bt_le_conn_param *param;
			struct bt_uuid *uuid;
			uint16_t u16;
			int err;
			memcpy(&u16, &data->data[i], sizeof(u16));
			uuid = BT_UUID_DECLARE_16(sys_le16_to_cpu(u16));
			
			// BT_UUID_ESS is the application Type
			if (bt_uuid_cmp(uuid, BT_UUID_ESS)) { continue; }

			LOG_DBG("is BT_UUID_ESS");
			err = bt_le_scan_stop();
			if (err) {
				LOG_DBG("Stop LE scan failed (err %d)", err);
				continue;
			}

			LOG_DBG("connnect");
			// param = BT_LE_CONN_PARAM_DEFAULT;
			param = BT_LE_CONN_PARAM_CUSTOM;
			err = bt_conn_le_create(addr, BT_CONN_LE_CREATE_CONN,
						param, &default_conn);
			if (err) {
				LOG_DBG("Create conn failed (err %d)", err);
				start_scan();
			}
			LOG_DBG("connnected");

			return false;
		}
	}

	return true;
}

static void device_found(const bt_addr_le_t *addr, int8_t rssi, uint8_t type,
			 struct net_buf_simple *ad)
{
	char dev[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(addr, dev, sizeof(dev));
	// LOG_DBG("[DEVICE]: %s, AD evt type %u, AD data len %u, RSSI %i",
	//        dev, type, ad->len, rssi);

	/* We're only interested in connectable events */
	if (type == BT_GAP_ADV_TYPE_ADV_IND ||
	    type == BT_GAP_ADV_TYPE_ADV_DIRECT_IND) {
		bt_data_parse(ad, eir_found, (void *)addr);
	}
}

static void start_scan(void)
{
	int err;
	/* Use active scanning and disable duplicate filtering to handle any
	 * devices that might update their advertising data at runtime. */
	struct bt_le_scan_param scan_param = {
		.type       = BT_LE_SCAN_TYPE_ACTIVE,
		.options    = BT_LE_SCAN_OPT_NONE,
		.interval   = BT_GAP_SCAN_FAST_INTERVAL,
		.window     = BT_GAP_SCAN_FAST_WINDOW,
	};

	err = bt_le_scan_start(&scan_param, device_found);
	// bt_scan_cb_register
	if (err) {
		LOG_DBG("Scanning failed to start (err %d)", err);
		return;
	}

	LOG_DBG("Scanning successfully started");
}

static void connected(struct bt_conn *conn, uint8_t err)
{
	char addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));

	if (err) {
		LOG_DBG("Failed to connect to %s (%u)", addr, err);

		bt_conn_unref(default_conn);
		default_conn = NULL;
		start_scan();
		return;
	}

	if (bt_conn_set_security(conn, BT_SECURITY_L4)) {
		LOG_DBG("Failed to set security");
	}
	int8_t tx_power = 8;
	LOG_DBG("Connected: %s", addr);
	set_tx_power(BT_HCI_VS_LL_HANDLE_TYPE_CONN, default_conn_handle, tx_power);
}

static void disconnected(struct bt_conn *conn, uint8_t reason)
{
	char addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));

	LOG_DBG("Disconnected from %s (reason 0x%02x)", addr, reason);
}

static void identity_resolved(struct bt_conn *conn, const bt_addr_le_t *rpa,
			      const bt_addr_le_t *identity)
{
	char addr_identity[BT_ADDR_LE_STR_LEN];
	char addr_rpa[BT_ADDR_LE_STR_LEN];
	bt_addr_le_to_str(identity, addr_identity, sizeof(addr_identity));
	bt_addr_le_to_str(rpa, addr_rpa, sizeof(addr_rpa));
	LOG_DBG("Identity resolved %s -> %s", addr_rpa, addr_identity);

	if (conn == default_conn) {
		LOG_DBG("gatt_discover BT_UUID_ESS");
		memcpy(&uuid, BT_UUID_ESS, sizeof(uuid));
		discover_params.uuid = &uuid.uuid;
		discover_params.func = discover_func;
		discover_params.start_handle = BT_ATT_FIRST_ATTTRIBUTE_HANDLE;
		discover_params.end_handle = BT_ATT_LAST_ATTTRIBUTE_HANDLE;
		discover_params.type = BT_GATT_DISCOVER_PRIMARY;
		int err = bt_gatt_discover(default_conn, &discover_params);

		LOG_DBG("gatt_discovered");
		if (err) {
			LOG_DBG("Discover failed(err %d)", err);
			return;
		}
	}
}

static void security_changed(struct bt_conn *conn, bt_security_t level, enum bt_security_err err)
{
	char addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));

	if (!err) {
		LOG_DBG("Security changed: %s level %u", addr, level);
		LOG_DBG(" -enc_key: %d", bt_conn_enc_key_size(conn));
		LOG_DBG(" -security_level: %d", bt_conn_get_security(conn));
	} else { LOG_DBG("Security failed: %s level %u err %d", addr, level, err); }

	shift_key = bt_conn_get_shift_key(conn);
	aes_key = bt_conn_get_aes_key(conn);
	pub_key = bt_conn_get_public_key(conn);
	default_conn = conn;
}

static struct bt_conn_cb conn_callbacks = {
	.connected = connected,
	.disconnected = disconnected,
	.identity_resolved = identity_resolved,
	.security_changed = security_changed,
};

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

static void passkey_entry(struct bt_conn *conn)
{
	LOG_DBG("Peripheral passkey confirm finished");
	int err = 0;
	err = bt_conn_auth_passkey_entry(conn, 0);
	if (err) { 
		LOG_DBG("Auth passkey failed (err %d)", err); 
	}

	// LOG_DBG("pairing");
	// err = bt_conn_auth_pairing_confirm(conn);
	// if (err) { 
	// 	LOG_DBG("pairing failed (err %d)", err); 
	// }
}

static struct bt_conn_auth_cb auth_cb = {
	.passkey_display = NULL,
	.passkey_entry = passkey_entry,
	.cancel = auth_cancel,
	.pairing_complete = pairing_complete,
	.pairing_failed = pairing_failed,
	.pairing_confirm = NULL,
};

void main(void)
{
	LOG_INF("DEV: Master");
	int err;
	err = bt_enable(NULL);
	if (err) {
		LOG_DBG("Bluetooth init failed (err %d)", err);
		return;
	}

	LOG_DBG("Bluetooth initialized");
	

	bt_conn_auth_cb_register(&auth_cb);
	bt_conn_cb_register(&conn_callbacks);

	start_scan();
}
