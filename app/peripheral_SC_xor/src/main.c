/* main.c - Application main entry point */

/*
 * Copyright (c) 2015-2016 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

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

static ssize_t read_u16(struct bt_conn *conn, const struct bt_gatt_attr *attr, void *buf,
			uint16_t len, uint16_t offset)
{
	const uint16_t *u16 = attr->user_data;
	uint16_t value = sys_cpu_to_le16(*u16);
	return bt_gatt_attr_read(conn, attr, buf, len, offset, &value, sizeof(value));
}

static ssize_t read_ecc(struct bt_conn *conn, const struct bt_gatt_attr *attr, void *buf,
			uint16_t len, uint16_t offset)
{
	const uint16_t *u16 = attr->user_data;
	uint16_t value = sys_cpu_to_le16(*u16);
	return bt_gatt_attr_read(conn, attr, buf, len, offset, &value, sizeof(value));
}

/* security setting */
enum enc_mode
{
	ENC_AES_MODE,
	ENC_ECC_MODE
};
bool aes_finished = false, ecc_c1_finished = false, ecc_c2_finished = false;

/* Environmental Sensing Service Declaration */
struct ecc_data{
	uint8_t c1[32];
	uint8_t c2[64];
};

struct temperature_sensor {
	uint8_t aes_value;
	struct ecc_data ecc_value;
};

static struct temperature_sensor sensor_1;
static bool disconnect = 0;

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

	printk("Read Tx Power: %d\n", rp->tx_power_level);
	net_buf_unref(rsp);
}

static void temp_ccc_cfg_changed(const struct bt_gatt_attr *attr, uint16_t value)
{
	LOG_DBG("temp_ccc_cfg_changed");
	simulate_temp = value == BT_GATT_CCC_NOTIFY;
}

BT_GATT_SERVICE_DEFINE(ess_svc, 
	BT_GATT_PRIMARY_SERVICE(BT_UUID_ESS),
	BT_GATT_CHARACTERISTIC(BT_UUID_TEMPERATURE,
				BT_GATT_CHRC_READ | BT_GATT_CHRC_NOTIFY,
				BT_GATT_PERM_READ, read_u16, NULL,
				&sensor_1.aes_value),
	BT_GATT_CHARACTERISTIC(BT_UUID_HUMIDITY,
				BT_GATT_CHRC_READ | BT_GATT_CHRC_NOTIFY,
				BT_GATT_PERM_READ, read_ecc, NULL,
				&sensor_1.ecc_value),
	BT_GATT_CUD(SENSOR_1_NAME, BT_GATT_PERM_READ),
	BT_GATT_CCC(temp_ccc_cfg_changed, BT_GATT_PERM_READ | BT_GATT_PERM_WRITE), 
);

static void send_aes_notify(const struct device *dev, struct bt_conn *conn, const struct bt_gatt_attr *chrc, uint8_t *value, struct temperature_sensor *sensor)
{
	LOG_DBG("send_aes_notify");
	LOG_DBG("aes notify value: %s", bt_hex(value, 16));
	bt_gatt_notify(conn, chrc, value, 16);
}

static void send_ecc_notify(const struct device *dev, struct bt_conn *conn, const struct bt_gatt_attr *chrc, const struct ecc_data *value,  struct temperature_sensor *sensor)
{
	LOG_DBG("send_ecc_notify");
	bt_gatt_notify(conn, chrc, value, 128);
}

int ecc_free=1;
static void bt_ecc_data_encrypt_finished(const uint8_t *C1, const uint8_t *C2)
{	
	//to do c1 c1 wapper
	LOG_DBG("bt_ecc_data_encrypt_finished");
	struct ecc_data c;
	memcpy(c.c1, C1, sizeof(c.c1));
	memcpy(c.c2, C2, sizeof(c.c2));
	LOG_DBG("C1 %s", bt_hex(C1, 32)); 
	LOG_DBG("C2 %s", bt_hex(C2, 64));
	//to do uuid at chr (finished)
	send_ecc_notify(tmpdev, NULL, &ess_svc.attrs[3], &c, &sensor_1); // BT_UUID_HUMIDITY
	// LOG_DBG("=============================");
	k_sleep(K_SECONDS(1));
	ecc_free=1;
}

static struct bt_ecc_data_encrypt_cb ecc_encrypt_cb = {
	.func = bt_ecc_data_encrypt_finished,
};

uint8_t *shift_key, *pub_key, *aes_key;
static void ess_simulate(struct bt_conn *conn, const struct device *dev, const uint8_t mode)
{
	// to do key use conn object data
	switch (mode)
	{
		case ENC_AES_MODE:
		{
			uint8_t ecb_plaintext[16] = {
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00
			};
			uint8_t enc_data[16];
			bt_proposed_encrypt_le(aes_key, &ecb_plaintext[0],&enc_data[0], shift_key);
			//to do uuid at chr (finished)
			LOG_DBG("aes plaintext: %s", bt_hex(&ecb_plaintext[0], 16));
			LOG_DBG("aes encryptd: %s", bt_hex(&enc_data[0], 16));
			send_aes_notify(tmpdev, NULL, &ess_svc.attrs[2], &enc_data[0], &sensor_1); // BT_UUID_TEMPERATURE
			break;
		}
		case ENC_ECC_MODE:
		{
			LOG_DBG("ECC MTU size is: %d\n", bt_gatt_get_mtu(conn));
			uint8_t text_val[32] = {
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00,
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00
			};
			ecc_free=0;
			LOG_DBG("ECC plaintext: %s", bt_hex(&text_val[0], 32));
			bt_ecc_data_encrypt(&text_val[0], pub_key, ecc_encrypt_cb.func);
			break;
		}
	default:
		LOG_ERR("Encryption mode is not defined.");
		break;
	}

}

static const struct bt_data ad[] = {
	BT_DATA_BYTES(BT_DATA_FLAGS, (BT_LE_AD_GENERAL | BT_LE_AD_NO_BREDR)),
	BT_DATA_BYTES(BT_DATA_GAP_APPEARANCE, 0x00, 0x03),
	BT_DATA_BYTES(BT_DATA_UUID16_ALL, 
	BT_UUID_16_ENCODE(BT_UUID_ESS_VAL),
	),
};

static void connected(struct bt_conn *conn, uint8_t err)
{
	char addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));

	if (err) {
		LOG_DBG("Failed to connect to %s (%u)", addr, err);
		return;
	}

	LOG_DBG("Connected %s", addr);
	LOG_DBG("MTU %d", bt_gatt_get_mtu(conn));
	LOG_DBG("SET security: bt_conn_set_security");
	if (bt_conn_set_security(conn, BT_SECURITY_L4)) {
		LOG_DBG("Failed to set security");
	}
	
	int8_t tx_power = 8;
	set_tx_power(BT_HCI_VS_LL_HANDLE_TYPE_CONN, default_conn_handle, tx_power);
	
}

static void disconnected(struct bt_conn *conn, uint8_t reason)
{
	char addr[BT_ADDR_LE_STR_LEN];
	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));
	LOG_DBG("Disconnected from %s (reason 0x%02x)", addr, reason);
	LOG_DBG("++++++++++++++++++++++++++++++++++++++++++++++++++++");
}

static void identity_resolved(struct bt_conn *conn, const bt_addr_le_t *rpa,
			      const bt_addr_le_t *identity)
{
	char addr_identity[BT_ADDR_LE_STR_LEN];
	char addr_rpa[BT_ADDR_LE_STR_LEN];
	bt_addr_le_to_str(identity, addr_identity, sizeof(addr_identity));
	bt_addr_le_to_str(rpa, addr_rpa, sizeof(addr_rpa));
	LOG_DBG("Identity resolved %s -> %s", addr_rpa, addr_identity);


	// struct bt_gatt_exchange_params exchange_params;
	// exchange_params.func = NULL;
	// default_conn = conn;
	// uint8_t err = bt_gatt_exchange_mtu(default_conn, &exchange_params);
	// if (err) {
	// 	LOG_DBG("MTU exchange failed (err %d)", err);
	// } else {
	// 	LOG_DBG("MTU exchange pending");
	// }
}

static void security_changed(struct bt_conn *conn, bt_security_t level, enum bt_security_err err)
{
	char addr[BT_ADDR_LE_STR_LEN];
	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));

	LOG_DBG("security_changed");
	if (!err) {
		LOG_DBG("Security changed: %s level %u", addr, level);
		LOG_DBG(" -enc_key: %d", bt_conn_enc_key_size(conn));
		LOG_DBG(" -security_level: %d", bt_conn_get_security(conn));
	} else {
		LOG_DBG("Security failed: %s level %u err %d", addr, level, err);
	}

	shift_key = bt_conn_get_shift_key(conn);
	aes_key = bt_conn_get_aes_key(conn);
	pub_key = bt_conn_get_public_key(conn);

}

static struct bt_conn_cb conn_callbacks = {
	.connected = connected,
	.disconnected = disconnected,
	.identity_resolved = identity_resolved,
	.security_changed = security_changed,
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

static int start_data_send(const struct device* dev){

	static uint8_t i;
	// bool aes_active = true, ecc_active = false;
	int16_t aes_counter = 0, ecc_counter = 0;
	int16_t aes_limited = 1, ecc_limited = 1;
	k_sleep(K_SECONDS(5));

	while (1) {
		k_sleep(K_SECONDS(1));
		if (simulate_temp) { 
			if (!(i % SENSOR_1_UPDATE_IVAL)) {
				LOG_DBG("UPDATE SENSOR_1_UPDATE_IVAL");
				if(aes_counter < aes_limited){
					LOG_DBG("UPDATE AES: %d", aes_counter);
					aes_counter++;
					ess_simulate(default_conn, dev, ENC_AES_MODE);
				}
				else if(ecc_counter < ecc_limited && ecc_free){
					LOG_DBG("UPDATE ECC: %d", ecc_counter);
					ecc_counter++;
					ess_simulate(default_conn, dev, ENC_ECC_MODE);
				}
				else{
					LOG_DBG("All action finished....");
					return bt_conn_disconnect(default_conn, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
				}
			}
			if (!(i % INT8_MAX)) { i = 0U; }
			i++; 
		}
	}
	return -1;
}

void main(void)
{	
	LOG_INF("DEV: Slave");
	int err;
	const struct device *dev = device_get_binding(CRYPTO_DRV_NAME);
	if (!dev) {
		LOG_ERR("%s pseudo device not found", CRYPTO_DRV_NAME);
		return;
	}

	err = bt_enable(NULL);
	if (err) {
		LOG_DBG("Bluetooth init failed (err %d)", err);
		return;
	}

	LOG_DBG("Bluetooth initialized");
	bt_passkey_set(0);
	bt_conn_auth_cb_register(&auth_cb_display);
	bt_conn_cb_register(&conn_callbacks);

	err = bt_le_adv_start(BT_LE_ADV_CONN_NAME, ad, ARRAY_SIZE(ad), NULL, 0);
	if (err) {
		LOG_DBG("Advertising failed to start (err %d)", err);
		return;
	}

	LOG_DBG("Advertising successfully started");
	err = start_data_send(dev);
	if (err) {
		LOG_DBG("Disconnect failed (err %d)", err);
		return;
	}

}