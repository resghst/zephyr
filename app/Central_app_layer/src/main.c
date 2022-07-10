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
// #include <crypto.h>
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


#define CUSTOM_CONN_INT_MIN 50
#define CUSTOM_CONN_INT_MAX 50

#define BT_LE_CONN_PARAM_CUSTOM BT_LE_CONN_PARAM(CUSTOM_CONN_INT_MIN, \
						  CUSTOM_CONN_INT_MAX, 0, 400)

static void start_scan(void);
static struct bt_conn *default_conn;
static uint16_t default_conn_handle;
static struct bt_uuid_16 uuid = BT_UUID_INIT_16(0);
static struct bt_gatt_discover_params discover_params;
static struct bt_gatt_subscribe_params subscribe_params, subscribe_params1, subscribe_params2, subscribe_params3, subscribe_params4, subscribe_params5;
static struct bt_gatt_write_params write_params1,  write_params3;
bool pkt[4] = {0};
uint8_t mtu_changed = 0;

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
	uint8_t remote_pub_256[64];
	uint8_t remote_pub_192[48];
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
	uint8_t dh1[48];
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

/* security setting */
bool aes_finished = false, ecc_c1_finished = false, ecc_c2_finished = false;
uint8_t *shift_key, *pub_key, *aes_key;
static struct app_pkt1 pkt1;
static struct app_pkt2 pkt2;
static struct app_pkt3 pkt3;
static struct app_pkt4 pkt4;

static uint8_t pkt1_notify_func(struct bt_conn *conn, struct bt_gatt_subscribe_params *params, const void *data, uint16_t length)
{
	LOG_DBG("pkt1_notify_func");
	if (!data) {
		LOG_DBG("[UNSUBSCRIBED]");
		params->value_handle = 0U;
		return BT_GATT_ITER_STOP;
	}
	LOG_DBG("receive pkt1\n");	
	// sys_memcpy_swap(&pkt1, data, sizeof(struct app_pkt1));
	memcpy(&pkt1, data, sizeof(struct app_pkt1));
	LOG_DBG("%s",bt_hex(data, sizeof(struct app_pkt1)));
	LOG_DBG("%s",bt_hex(&pkt1, sizeof(struct app_pkt1)));

    uint8_t ct = secp256r1;
    uint8_t public_key_256[ct + 1], private_key_256[ct], ret = 0;
    ret = set_CT(P256);
    if (ret == 0) {
        LOG_DBG("set_CT failure");
        return 0;
    }
    ret = ecc_make_key(public_key_256, private_key_256);
    if (ret == 0) {  LOG_DBG("ecc_make_key failure\n"); }    
	LOG_DBG("=== P256 Info ===");
	LOG_DBG("Pub: %s",bt_hex(&public_key_256[0], ct + 1));
	LOG_DBG("Pri: %s",bt_hex(&private_key_256[0], ct));

        
    ct = secp192r1;
    uint8_t public_key_192[ct + 1];
    uint8_t private_key_192[ct];
    ret = set_CT(P192);
    if (ret == 0) { 
		LOG_DBG("set_CT failure");
        return 0; 
	} 
    ret = ecc_make_key(public_key_192, private_key_192);
    if (ret == 0) {
        LOG_DBG("ecc_make_key failure");
        return 0;
    }
	LOG_DBG("=== P192 Info ===");
	LOG_DBG("Pub: %s",bt_hex(&public_key_192[0], ct + 1));
	LOG_DBG("Pri: %s",bt_hex(&private_key_192[0], ct));

	memcpy(key_data.pub_256, public_key_256, secp256r1+1);
	memcpy(key_data.pri_256, private_key_256, secp256r1);
	memcpy(key_data.pub_192, public_key_192, secp192r1+1);
	memcpy(key_data.pri_192, private_key_192, secp192r1);
	memcpy(key_data.remote_pub_256, pkt1.pub_256, secp256r1+1);
	memcpy(key_data.remote_pub_192, pkt1.pub_192, secp192r1+1);
	LOG_DBG("=== remote P256 Info ===");
	LOG_DBG("Pub: %s",bt_hex(&key_data.remote_pub_256, secp256r1 + 1));
	LOG_DBG("=== remote P192 Info ===");
	LOG_DBG("Pub: %s",bt_hex(&key_data.remote_pub_192, secp192r1 + 1));
	LOG_DBG("=========================");
	pkt[0]=1;

    ct = secp192r1;
    uint8_t local_secret[ct*2];
    LOG_DBG("P-192 local");
    ret = ecdh_shared_secret(pkt1.pub_192, 
			private_key_192, local_secret);
	LOG_DBG("secret: %s",bt_hex(&local_secret[0], ct*2));
	
    uint8_t *cmac_key=NULL, *cmac=NULL;
	aes_cmac(cmac_key, local_secret, ct, cmac);
	memcpy(pkt2.rk, key_data.pub_256, sizeof(pkt2.rk));
	memcpy(pkt2.dh1, local_secret, sizeof(pkt2.dh1));
	memcpy(&pkt2.mac[0], cmac, sizeof(pkt2.mac));

    LOG_DBG("bt_gatt_write");
	ret = bt_gatt_write(conn, &write_params1);
    LOG_DBG("end");
	return BT_GATT_ITER_CONTINUE;
}

static uint8_t pkt3_notify_func(struct bt_conn *conn, struct bt_gatt_subscribe_params *params, const void *data, uint16_t length)
{
	LOG_DBG("pkt3_notify_func");
	if (!data) {
		LOG_DBG("[UNSUBSCRIBED]");
		params->value_handle = 0U;
		return BT_GATT_ITER_STOP;
	}
	// struct app_pkt3 *pkt3=NULL;
	memcpy(&pkt3, data, sizeof(struct app_pkt3));

    uint8_t ct = secp256r1;
    uint8_t signature_256[ct * 2];
    uint8_t hash[ct], ret;
    hash[0] = 0x2;
    LOG_DBG("P-256 ecdsa_sign");
    ret = set_CT(P256);
	memcpy(signature_256, pkt3.verify_key, 64);
    ret = ecdsa_verify(key_data.remote_pub_256, hash, signature_256);

    uint8_t local_secret[ct], cmac_key[16] = {0}, cmac[16] = {0};
	memcpy(cmac_key, signature_256, 16);
	aes_cmac(cmac_key, local_secret, ct, cmac);
	uint8_t passenger_tk[76] = {0};
	memcpy(pkt4.passenger_tk, passenger_tk, sizeof(pkt4.passenger_tk));
	LOG_DBG("bt_gatt_write");
	ret = bt_gatt_write(conn, &write_params3);
	return BT_GATT_ITER_CONTINUE;
}

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


static void pkt2_cb(struct bt_conn *conn, uint8_t err, struct bt_gatt_write_params *params)
{
	LOG_DBG("[pkt2_cb]");
	LOG_DBG("err: %04x", err);
}
static void pkt4_cb(struct bt_conn *conn, uint8_t err, struct bt_gatt_write_params *params)
{
	LOG_DBG("[pkt4_cb]");
	LOG_DBG("err: %04x", err);
}

int flagccc=0;
static uint8_t discover_func(struct bt_conn *conn, const struct bt_gatt_attr *attr,
			     struct bt_gatt_discover_params *params)
{
	int err;
	if (!attr) { 
		LOG_DBG("ITER STOP");
		return BT_GATT_ITER_STOP; 
	}
	LOG_DBG("[ATTRIBUTE] handle %u", attr->handle);

	if (!bt_uuid_cmp(discover_params.uuid, BT_UUID_ESS)) { 
		LOG_DBG("Process uuid BT_UUID_SENSOR_LOCATION");
		memcpy(&uuid, BT_UUID_SENSOR_LOCATION, sizeof(uuid));
		discover_params.uuid = &uuid.uuid;
		discover_params.start_handle = attr->handle + 1;
		discover_params.type = BT_GATT_DISCOVER_CHARACTERISTIC;
		err = bt_gatt_discover(conn, &discover_params);
		if (err) { LOG_DBG("Discover failed (err %d)", err); }
	} 
	else if (!bt_uuid_cmp(discover_params.uuid, BT_UUID_SENSOR_LOCATION)) { 
		LOG_DBG("Process uuid BT_UUID_SC_CONTROL_POINT");
		memcpy(&uuid, BT_UUID_SC_CONTROL_POINT, sizeof(uuid));

		discover_params.uuid = &uuid.uuid;
		discover_params.start_handle = attr->handle + 2;
		discover_params.type = BT_GATT_DISCOVER_DESCRIPTOR;
		subscribe_params.value_handle = bt_gatt_attr_value_handle(attr);
		err = bt_gatt_discover(conn, &discover_params);
		if (err) { LOG_DBG("Discover failed (err %d)", err); }
	} 
	else if (!bt_uuid_cmp(discover_params.uuid, BT_UUID_SC_CONTROL_POINT)) { 
		LOG_DBG("Process uuid BT_UUID_ELEVATION");
		memcpy(&uuid, BT_UUID_ELEVATION, sizeof(uuid));
		discover_params.uuid = &uuid.uuid;
		discover_params.start_handle = attr->handle + 3;
		discover_params.type = BT_GATT_DISCOVER_DESCRIPTOR;
		// subscribe_params1.value_handle = bt_gatt_attr_value_handle(attr);
		err = bt_gatt_discover(conn, &discover_params);
		if (err) { LOG_DBG("Discover failed (err %d)", err); }
		write_params1.handle = bt_gatt_attr_value_handle(attr);
		write_params1.offset = 0;
		write_params1.func = pkt2_cb;
		write_params1.data = &pkt2;
		write_params1.length = sizeof(struct app_pkt2);
		LOG_DBG("[WRITED]");
	} 
	else if (!bt_uuid_cmp(discover_params.uuid, BT_UUID_ELEVATION)) { 
		LOG_DBG("Process uuid BT_UUID_PRESSURE");
		memcpy(&uuid, BT_UUID_PRESSURE, sizeof(uuid));

		discover_params.uuid = &uuid.uuid;
		discover_params.start_handle = attr->handle + 4;
		discover_params.type = BT_GATT_DISCOVER_DESCRIPTOR;
		subscribe_params2.value_handle = bt_gatt_attr_value_handle(attr);
		err = bt_gatt_discover(conn, &discover_params);
		if (err) { LOG_DBG("Discover failed (err %d)", err); }

	} 
	else if (!bt_uuid_cmp(discover_params.uuid, BT_UUID_PRESSURE)) { 
		LOG_DBG("Process uuid BT_UUID_TEMPERATURE");
		memcpy(&uuid, BT_UUID_TEMPERATURE, sizeof(uuid));
		discover_params.uuid = &uuid.uuid;
		discover_params.start_handle = attr->handle + 5;
		discover_params.type = BT_GATT_DISCOVER_DESCRIPTOR;
		// subscribe_params3.value_handle = bt_gatt_attr_value_handle(attr);
		write_params3.handle = bt_gatt_attr_value_handle(attr);
		write_params3.offset = 0;
		write_params3.func = pkt4_cb;
		write_params3.data = &pkt4;
		write_params3.length = sizeof(struct app_pkt4);
		LOG_DBG("[WRITED]");
		err = bt_gatt_discover(conn, &discover_params);
		if (err) { LOG_DBG("Discover failed (err %d)", err); }
	} 
	else if (!bt_uuid_cmp(discover_params.uuid, BT_UUID_TEMPERATURE)) { 
		LOG_DBG("Process uuid BT_UUID_HUMIDITY");
		memcpy(&uuid, BT_UUID_HUMIDITY, sizeof(uuid));
		discover_params.uuid = &uuid.uuid;
		discover_params.start_handle = attr->handle + 6;
		discover_params.type = BT_GATT_DISCOVER_DESCRIPTOR;
		subscribe_params4.value_handle = bt_gatt_attr_value_handle(attr);
		err = bt_gatt_discover(conn, &discover_params);
		if (err) { LOG_DBG("Discover failed (err %d)", err); }
	} 
	else if (!bt_uuid_cmp(discover_params.uuid, BT_UUID_HUMIDITY)) { 
		LOG_DBG("Process uuid BT_UUID_GATT_CCC");
		memcpy(&uuid, BT_UUID_GATT_CCC, sizeof(uuid));
		discover_params.uuid = &uuid.uuid;
		discover_params.start_handle = attr->handle + 7;
		discover_params.type = BT_GATT_DISCOVER_DESCRIPTOR;
		subscribe_params5.value_handle = bt_gatt_attr_value_handle(attr);
		err = bt_gatt_discover(conn, &discover_params);
		if (err) { LOG_DBG("Discover failed (err %d)", err); }
	} 
	else if(!bt_uuid_cmp(discover_params.uuid, BT_UUID_GATT_CCC) && !flagccc){
		LOG_DBG("Process subscribed UUID");
		subscribe_params.notify = pkt1_notify_func;
		subscribe_params.value = BT_GATT_CCC_NOTIFY;
		subscribe_params.ccc_handle = attr->handle;
		err = bt_gatt_subscribe(conn, &subscribe_params);
		if (err && err != -EALREADY) { LOG_DBG("Subscribe failed (err %d)", err); } 
		else { LOG_DBG("[SUBSCRIBED]"); }

		// subscribe_params1.write = pkt2_cb;
		// subscribe_params1.value = BT_GATT_CCC_NOTIFY;
		// subscribe_params1.ccc_handle = attr->handle;
		// err = bt_gatt_subscribe(conn, &subscribe_params1);
		// if (err && err != -EALREADY) { LOG_DBG("Subscribe failed (err %d)", err); } 
		// else { LOG_DBG("[SUBSCRIBED]"); }

		subscribe_params2.notify = pkt3_notify_func;
		subscribe_params2.value = BT_GATT_CCC_NOTIFY;
		subscribe_params2.ccc_handle = attr->handle;
		err = bt_gatt_subscribe(conn, &subscribe_params2);
		if (err && err != -EALREADY) { LOG_DBG("Subscribe failed (err %d)", err); } 
		else { LOG_DBG("[SUBSCRIBED]"); }

		// subscribe_params3.write = pkt4_cb;
		// subscribe_params3.value = BT_GATT_CCC_NOTIFY;
		// subscribe_params3.ccc_handle = attr->handle;
		// err = bt_gatt_subscribe(conn, &subscribe_params3);
		// if (err && err != -EALREADY) { LOG_DBG("Subscribe failed (err %d)", err); } 
		// else { LOG_DBG("[SUBSCRIBED]"); }


		subscribe_params4.notify = aes_notify_func;
		subscribe_params4.value = BT_GATT_CCC_NOTIFY;
		subscribe_params4.ccc_handle = attr->handle;
		err = bt_gatt_subscribe(conn, &subscribe_params4);
		if (err && err != -EALREADY) { LOG_DBG("Subscribe failed (err %d)", err); } 
		else { LOG_DBG("[SUBSCRIBED]"); }

		subscribe_params5.notify = ecc_notify_func;
		subscribe_params5.value = BT_GATT_CCC_NOTIFY;
		subscribe_params5.ccc_handle = attr->handle;
		err = bt_gatt_subscribe(conn, &subscribe_params5);
		if (err && err != -EALREADY) { LOG_DBG("Subscribe failed (err %d)", err); } 
		else { LOG_DBG("[SUBSCRIBED]"); }

		flagccc = 1;
		default_conn = conn;
		LOG_DBG("[END]");
		return BT_GATT_ITER_STOP;
	}

	return BT_GATT_ITER_CONTINUE;
}

static bool eir_found(struct bt_data *data, void *user_data)
{
	bt_addr_le_t *addr = user_data;
	// int i;
	// LOG_DBG("[AD]: %u data_len %u", data->type, data->data_len);
	switch (data->type) {
	case BT_DATA_UUID16_SOME:
	case BT_DATA_UUID16_ALL:
		if (data->data_len % sizeof(uint16_t) != 0U) {
			LOG_DBG("AD malformed");
			return true;
		}
		LOG_DBG("[AD]: %u data_len %u", data->type, data->data_len);
		for (int i = 0; i < data->data_len; i += sizeof(uint16_t)) {
			// LOG_DBG("i: %d, step: %d",i, sizeof(uint16_t));
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

			LOG_DBG("connnecting");
			// param = BT_LE_CONN_PARAM_DEFAULT;
			param = BT_LE_CONN_PARAM_CUSTOM;
			err = bt_conn_le_create(addr, BT_CONN_LE_CREATE_CONN,
						param, &default_conn);
			if (err) {
				LOG_DBG("Create conn failed (err %d)", err);
				start_scan();
			}
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
	if (type == BT_GAP_ADV_TYPE_ADV_IND || type == BT_GAP_ADV_TYPE_ADV_DIRECT_IND) {
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

static void set_mtu_updated_cb(struct bt_conn *conn, uint8_t err, struct bt_gatt_exchange_params *params)
{
	LOG_DBG("set_mtu_updated callcacked");
	LOG_DBG("err %02x, MTU %d", err, bt_gatt_get_mtu(conn));
	LOG_DBG("gatt_discover BT_UUID_ESS");
	memcpy(&uuid, BT_UUID_ESS, sizeof(uuid));
	discover_params.uuid = &uuid.uuid;
	discover_params.func = discover_func;
	discover_params.start_handle = BT_ATT_FIRST_ATTTRIBUTE_HANDLE;
	discover_params.end_handle = BT_ATT_LAST_ATTTRIBUTE_HANDLE;
	discover_params.type = BT_GATT_DISCOVER_PRIMARY;
	err = bt_gatt_discover(conn, &discover_params);
	mtu_changed++;
	LOG_DBG("gatt_discovered");
	if (err) { 	LOG_DBG("Discover failed(err %d)", err); }
}

static struct bt_gatt_exchange_params exchange_params={
	.func = set_mtu_updated_cb,
};

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

	// if (bt_conn_set_security(conn, BT_SECURITY_L1)) {
	// 	LOG_DBG("Failed to set security");
	// }
	int8_t tx_power = 8;
	set_tx_power(BT_HCI_VS_LL_HANDLE_TYPE_CONN, default_conn_handle, tx_power);
	LOG_DBG("Connected: %s", addr);
}

static void disconnected(struct bt_conn *conn, uint8_t reason)
{
	char addr[BT_ADDR_LE_STR_LEN];
	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));
	LOG_DBG("Disconnected from %s (reason 0x%02x)", addr, reason);
}

static struct bt_conn_cb conn_callbacks = {
	.connected = connected,
	.disconnected = disconnected,
};

int mtu_count=0;
void att_mtu_updated(struct bt_conn *conn, uint16_t tx, uint16_t rx){
	LOG_DBG("mtu_updated");
	LOG_DBG("Updated MTU: TX: %d RX: %d bytes", tx, rx);
	if(mtu_count==0){
		int err = bt_gatt_exchange_mtu(conn, &exchange_params);
		if (err) { LOG_DBG("MTU exchange failed (err %d)", err); } 
		else { LOG_DBG("MTU exchange pending");}
	}
	mtu_count=1;
}

struct bt_gatt_cb gatt_callbacks = {
	.att_mtu_updated = att_mtu_updated
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

	// bt_conn_auth_cb_register(&auth_cb);
	bt_conn_cb_register(&conn_callbacks);
	bt_gatt_cb_register(&gatt_callbacks);

	start_scan();
	while(1) {
		k_sleep(K_SECONDS(30));
		LOG_DBG("ED");
	}
}
