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
#include <bluetooth/conn.h>
#include <bluetooth/uuid.h>
#include <bluetooth/gatt.h>
#include <bluetooth/services/bas.h>

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

#define SENSOR_1_NAME "Temperature Sensor 1"

/* Sensor Internal Update Interval [seconds] */
#define SENSOR_1_UPDATE_IVAL 5

/* ESS error definitions */
#define ESS_ERR_WRITE_REJECT 0x80
#define ESS_ERR_COND_NOT_SUPP 0x81

/* ESS Trigger Setting conditions */
#define ESS_TRIGGER_INACTIVE 0x00
#define ESS_FIXED_TIME_INTERVAL 0x01
#define ESS_NO_LESS_THAN_SPECIFIED_TIME 0x02
#define ESS_VALUE_CHANGED 0x03
#define ESS_LESS_THAN_REF_VALUE 0x04
#define ESS_LESS_OR_EQUAL_TO_REF_VALUE 0x05
#define ESS_GREATER_THAN_REF_VALUE 0x06
#define ESS_GREATER_OR_EQUAL_TO_REF_VALUE 0x07
#define ESS_EQUAL_TO_REF_VALUE 0x08
#define ESS_NOT_EQUAL_TO_REF_VALUE 0x09

uint32_t cap_flags;

static void start_scan(void);
static struct bt_conn *default_conn;
static struct bt_uuid_16 uuid = BT_UUID_INIT_16(0);
static struct bt_gatt_discover_params discover_params;
static struct bt_gatt_subscribe_params subscribe_params;

int validate_hw_compatibility(const struct device *dev)
{
	uint32_t flags = 0U;

	flags = cipher_query_hwcaps(dev);
	if ((flags & CAP_RAW_KEY) == 0U) {
		LOG_INF("Please provision the key separately "
			"as the module doesnt support a raw key");
		return -1;
	}

	if ((flags & CAP_SYNC_OPS) == 0U) {
		LOG_ERR("The app assumes sync semantics. "
		  "Please rewrite the app accordingly before proceeding");
		return -1;
	}

	if ((flags & CAP_SEPARATE_IO_BUFS) == 0U) {
		LOG_ERR("The app assumes distinct IO buffers. "
		"Please rewrite the app accordingly before proceeding");
		return -1;
	}

	cap_flags = CAP_RAW_KEY | CAP_SYNC_OPS | CAP_SEPARATE_IO_BUFS;

	return 0;

}

/* Environmental Sensing Service Declaration */

struct es_measurement {
	uint16_t flags; /* Reserved for Future Use */
	uint8_t sampling_func;
	uint32_t meas_period;
	uint32_t update_interval;
	uint8_t application;
	uint8_t meas_uncertainty;
};

struct temperature_sensor {
	int16_t temp_value;

	/* Valid Range */
	int16_t lower_limit;
	int16_t upper_limit;

	/* ES trigger setting - Value Notification condition */
	uint8_t condition;
	union {
		uint32_t seconds;
		int16_t ref_val; /* Reference temperature */
	};

	struct es_measurement meas;
};

struct humidity_sensor {
	int16_t humid_value;

	struct es_measurement meas;
};

struct read_es_measurement_rp {
	uint16_t flags; /* Reserved for Future Use */
	uint8_t sampling_function;
	uint8_t measurement_period[3];
	uint8_t update_interval[3];
	uint8_t application;
	uint8_t measurement_uncertainty;
} __packed;

struct es_trigger_setting_seconds {
	uint8_t condition;
	uint8_t sec[3];
} __packed;

struct es_trigger_setting_reference {
	uint8_t condition;
	int16_t ref_val;
} __packed;

static uint8_t notify_func(struct bt_conn *conn,
			   struct bt_gatt_subscribe_params *params,
			   const void *data, uint16_t length)
{
	if (!data) {
		LOG_DBG("[UNSUBSCRIBED]");
		params->value_handle = 0U;
		return BT_GATT_ITER_STOP;
	}
	LOG_DBG("[NOTIFICATION] data %p length %u Temperature %d C", \
		data, length, ((uint16_t *)data)[0]);
	return BT_GATT_ITER_CONTINUE;
}

int flagccc=0;
static uint8_t discover_func(struct bt_conn *conn,
			     const struct bt_gatt_attr *attr,
			     struct bt_gatt_discover_params *params)
{
	int err;
	if (!attr) {
		LOG_DBG("Discover complete");
		// (void)memset(params, 0, sizeof(*params));
		return BT_GATT_ITER_STOP;
	}

	LOG_DBG("[ATTRIBUTE] handle %u", attr->handle);

	if (!bt_uuid_cmp(discover_params.uuid, BT_UUID_ESS)) { 
		memcpy(&uuid, BT_UUID_TEMPERATURE, sizeof(uuid));
		discover_params.uuid = &uuid.uuid;
		discover_params.start_handle = attr->handle + 1;
		discover_params.type = BT_GATT_DISCOVER_CHARACTERISTIC;
		LOG_DBG("gatt_discover tmp");
		err = bt_gatt_discover(conn, &discover_params);
		if (err) {
			LOG_DBG("Discover failed (err %d)", err);
		}
	} else if (!bt_uuid_cmp(discover_params.uuid, BT_UUID_TEMPERATURE)) { 
		memcpy(&uuid, BT_UUID_GATT_CCC, sizeof(uuid));
		discover_params.uuid = &uuid.uuid;
		discover_params.start_handle = attr->handle + 2;
		discover_params.type = BT_GATT_DISCOVER_DESCRIPTOR;
		subscribe_params.value_handle = bt_gatt_attr_value_handle(attr);
		LOG_DBG("gatt_discover ccc");
		err = bt_gatt_discover(conn, &discover_params);
		if (err) {
			LOG_DBG("Discover failed (err %d)", err);
		}
	} else if(!bt_uuid_cmp(discover_params.uuid, BT_UUID_GATT_CCC) && !flagccc){
		LOG_DBG("GATT_CCC");
		flagccc=1;
		subscribe_params.notify = notify_func;
		subscribe_params.value = BT_GATT_CCC_NOTIFY;
		subscribe_params.ccc_handle = attr->handle;

		err = bt_gatt_subscribe(conn, &subscribe_params);
		if (err && err != -EALREADY) {
			LOG_DBG("Subscribe failed (err %d)", err);
		} else {
			LOG_DBG("[SUBSCRIBED]");
		}

		return BT_GATT_ITER_STOP;
	}
	
	return BT_GATT_ITER_CONTINUE;
}

static bool eir_found(struct bt_data *data, void *user_data)
{
	bt_addr_le_t *addr = user_data;
	int i;

	LOG_DBG("[AD]: %u data_len %u", data->type, data->data_len);
	

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
			if (bt_uuid_cmp(uuid, BT_UUID_ESS)) {
				continue;
			}

			LOG_DBG("is BT_UUID_ESS");
			err = bt_le_scan_stop();
			if (err) {
				LOG_DBG("Stop LE scan failed (err %d)", err);
				continue;
			}

			LOG_DBG("connnect");
			param = BT_LE_CONN_PARAM_DEFAULT;
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

	LOG_DBG("Connected: %s", addr);
}

static void disconnected(struct bt_conn *conn, uint8_t reason)
{
	char addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));

	LOG_DBG("Disconnected from %s (reason 0x%02x)", addr, reason);
}

static void security_changed(struct bt_conn *conn, bt_security_t level, enum bt_security_err err)
{
	char addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));

	if (!err) {
		LOG_DBG("Security changed: %s level %u", addr, level);
		LOG_DBG(" -enc_key: %d", bt_conn_enc_key_size(conn));
		LOG_DBG(" -security_level: %d", bt_conn_get_security(conn));
		bt_conn_enc_key_info(conn);
	} else {
		LOG_DBG("Security failed: %s level %u err %d", addr, level, err);
	}

	if (conn == default_conn) {
		memcpy(&uuid, BT_UUID_ESS, sizeof(uuid));
		discover_params.uuid = &uuid.uuid;
		discover_params.func = discover_func;
		discover_params.start_handle = BT_ATT_FIRST_ATTTRIBUTE_HANDLE;
		discover_params.end_handle = BT_ATT_LAST_ATTTRIBUTE_HANDLE;
		discover_params.type = BT_GATT_DISCOVER_PRIMARY;

		LOG_DBG("gatt_discover BT_UUID_ESS");
		err = bt_gatt_discover(default_conn, &discover_params);
		LOG_DBG("gatt_discovered");
		if (err) {
			LOG_DBG("Discover failed(err %d)", err);
			return;
		}
	}
}

static struct bt_conn_cb conn_callbacks = {
	.connected = connected,
	.disconnected = disconnected,
	.identity_resolved = NULL,
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
