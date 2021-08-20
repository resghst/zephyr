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

static void print_buffer_comparison(const uint8_t *wanted_result,
				    uint8_t *result, size_t length)
{
	int i, j;

	LOG_DBG("Was waiting for: ");

	for (i = 0, j = 1; i < length; i++, j++) {
		LOG_DBG("0x%02x ", wanted_result[i]);

		if (j == 10) {
			LOG_DBG("");
			j = 0;
		}
	}

	LOG_DBG(" But got:");

	for (i = 0, j = 1; i < length; i++, j++) {
		LOG_DBG("0x%02x ", result[i]);

		if (j == 10) {
			LOG_DBG("");
			j = 0;
		}
	}

	LOG_DBG("");
}

static void print_buffer_uint8(uint8_t *result, size_t length)
{
	int i, j;
	for (i = 0, j = 1; i < length; i++, j++) {
		LOG_DBG("0x%02x ", result[i]);
		if (j == 10) {
			LOG_DBG("");
			j = 0;
		}
	}
	LOG_DBG("");
}

static void print_buffer_uint16(uint16_t *result, size_t length)
{
	int i, j;
	for (i = 0, j = 1; i < length; i++, j++) {
		LOG_DBG("0x%02x ", result[i]);
		if (j == 10) {
			LOG_DBG("");
			j = 0;
		}
	}
	LOG_DBG("");
}

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

/* RFC 3610 test vector #1 */
static uint8_t ccm_key[16] = {
	0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb,
	0xcc, 0xcd, 0xce, 0xcf
};
static uint8_t ccm_nonce[13] = {
	0x00, 0x00, 0x00, 0x03, 0x02, 0x01, 0x00, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4,
	0xa5
};
static uint8_t ccm_hdr[8] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
};
static uint8_t ccm_data[23] = {
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
	0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e
};
static const uint8_t ccm_expected[31] = {
	0x58, 0x8c, 0x97, 0x9a, 0x61, 0xc6, 0x63, 0xd2, 0xf0, 0x66, 0xd0, 0xc2,
	0xc0, 0xf9, 0x89, 0x80, 0x6d, 0x5f, 0x6b, 0x61, 0xda, 0xc3, 0x84, 0x17,
	0xe8, 0xd1, 0x2c, 0xfd, 0xf9, 0x26, 0xe0
};

void ccm_mode(const struct device *dev)
{
	uint8_t encrypted[50]={0};
	uint8_t decrypted[25]={0};
	struct cipher_ctx ini = {
		.keylen = sizeof(ccm_key),
		.key.bit_stream = ccm_key,
		.mode_params.ccm_info = {
			.nonce_len = sizeof(ccm_nonce),
			.tag_len = 8,
		},
		.flags = cap_flags,
	};
	struct cipher_pkt encrypt = {
		.in_buf = ccm_data,
		.in_len = sizeof(ccm_data),
		.out_buf_max = sizeof(encrypted),
		.out_buf = encrypted,
	};
	struct cipher_aead_pkt ccm_op = {
		.ad = ccm_hdr,
		.ad_len = sizeof(ccm_hdr),
		.pkt = &encrypt,
		/* TinyCrypt always puts the tag at the end of the ciphered
		 * text, but other library such as mbedtls might be more
		 * flexible and can take a different buffer for it.  So to
		 * make sure test passes on all backends: enforcing the tag
		 * buffer to be after the ciphered text.
		 */
		.tag = encrypted + sizeof(ccm_data),
	};
	struct cipher_pkt decrypt = {
		.in_buf = encrypted,
		.in_len = sizeof(ccm_data),
		.out_buf = decrypted,
		.out_buf_max = sizeof(decrypted),
	};

	if (cipher_begin_session(dev, &ini, CRYPTO_CIPHER_ALGO_AES,
				 CRYPTO_CIPHER_MODE_CCM,
				 CRYPTO_CIPHER_OP_ENCRYPT)) {
		return;
	}

	ccm_op.pkt = &encrypt;
	if (cipher_ccm_op(&ini, &ccm_op, ccm_nonce)) {
		LOG_ERR("CCM mode ENCRYPT - Failed");
		goto out;
	}


	LOG_INF("Output length (encryption): %d", encrypt.out_len);

	if (memcmp(encrypt.out_buf, ccm_expected, sizeof(ccm_expected))) {
		LOG_ERR("CCM mode ENCRYPT - Mismatch between expected "
			    "and returned cipher text");
		print_buffer_comparison(ccm_expected,
					encrypt.out_buf, sizeof(ccm_expected));
		goto out;
	}

	LOG_INF("Output length (encryption): %d", encrypt.out_len);
	LOG_INF("CCM mode ENCRYPT - Match");
	int i=0;
	LOG_DBG("plain text: 0x");
	for(i=0;i<sizeof(encrypt.in_len);i++) LOG_DBG("%02x",encrypt.in_buf[i]);
	LOG_DBG("");
	LOG_DBG("enc: 0x");
	for(i=0;i<sizeof(encrypt.in_len);i++) LOG_DBG("%02x",encrypt.out_buf[i]);
	LOG_DBG("");

	cipher_free_session(dev, &ini);

	if (cipher_begin_session(dev, &ini, CRYPTO_CIPHER_ALGO_AES,
				 CRYPTO_CIPHER_MODE_CCM,
				 CRYPTO_CIPHER_OP_DECRYPT)) {
		return;
	}

	ccm_op.pkt = &decrypt;
	if (cipher_ccm_op(&ini, &ccm_op, ccm_nonce)) {
		LOG_ERR("CCM mode DECRYPT - Failed");
		goto out;
	}

	LOG_INF("Output length (decryption): %d", decrypt.out_len);

	if (memcmp(decrypt.out_buf, ccm_data, sizeof(ccm_data))) {
		LOG_ERR("CCM mode DECRYPT - Mismatch between plaintext "
			"and decrypted cipher text");
		print_buffer_comparison(ccm_data,
					decrypt.out_buf, sizeof(ccm_data));
		goto out;
	}

	LOG_DBG("enc text: 0x");
	for(i=0;i<sizeof(decrypt.in_len);i++) LOG_DBG("%02x",decrypt.in_buf[i]);
	LOG_DBG("");
	LOG_DBG("plain: 0x");
	for(i=0;i<sizeof(decrypt.in_len);i++) LOG_DBG("%02x",decrypt.out_buf[i]);
	LOG_DBG("");

	LOG_INF("CCM mode DECRYPT - Match");
out:
	cipher_free_session(dev, &ini);
}

void d2h(int16_t dec_data, uint8_t *hex_data, uint8_t* len){
    int16_t quotient= dec_data;
    uint8_t hexadecimalnum[100], j = 0;
	len = &j;
 	hex_data = &hexadecimalnum[0];
	LOG_INF("dec value: %d", dec_data);
	LOG_INF("hex value:");
    while (quotient != 0)
    {	
		hexadecimalnum[j++] = quotient % 256;
        quotient = quotient/256;
    }
	int i=0;
	for(i=0;i<j;i++) LOG_DBG("%02x", hex_data[i]);
	LOG_DBG("");
}

void enc(const struct device *dev, uint8_t *data, uint8_t *enc_data, uint8_t data_len){
	
	uint8_t encrypted[50]={0};
	enc_data = &encrypted[0];
	struct cipher_ctx ini = {
		.keylen = sizeof(ccm_key),
		.key.bit_stream = ccm_key,
		.mode_params.ccm_info = {
			.nonce_len = sizeof(ccm_nonce),
			.tag_len = 8,
		},
		.flags = cap_flags,
	};
	struct cipher_pkt encrypt = {
		.in_buf = data,
		.in_len = data_len,
		.out_buf_max = sizeof(encrypted),
		.out_buf = encrypted,
	};
	struct cipher_aead_pkt ccm_op = {
		.ad = ccm_hdr,
		.ad_len = sizeof(ccm_hdr),
		.pkt = &encrypt,
		/* TinyCrypt always puts the tag at the end of the ciphered
		 * text, but other library such as mbedtls might be more
		 * flexible and can take a different buffer for it.  So to
		 * make sure test passes on all backends: enforcing the tag
		 * buffer to be after the ciphered text.
		 */
		.tag = encrypted + sizeof(ccm_data),
	};

	if (cipher_begin_session(dev, &ini, CRYPTO_CIPHER_ALGO_AES,
				 CRYPTO_CIPHER_MODE_CCM,
				 CRYPTO_CIPHER_OP_ENCRYPT)) {
		return;
	}

	ccm_op.pkt = &encrypt;
	if (cipher_ccm_op(&ini, &ccm_op, ccm_nonce)) {
		LOG_ERR("CCM mode ENCRYPT - Failed");
		goto out;
	}


	LOG_INF("Output length (encryption): %d", encrypt.out_len);
	LOG_INF("CCM mode ENCRYPT - Match");
	int i=0;
	LOG_DBG("plain text: 0x");
	for(i=0;i<sizeof(encrypt.in_len);i++) LOG_DBG("%02x",encrypt.in_buf[i]);
	LOG_DBG("");
	LOG_DBG("enc: 0x");
	for(i=0;i<sizeof(encrypt.in_len);i++) LOG_DBG("%02x",encrypt.out_buf[i]);
	LOG_DBG("");

	cipher_free_session(dev, &ini);
out:
	cipher_free_session(dev, &ini);
}

static ssize_t read_u16(struct bt_conn *conn, const struct bt_gatt_attr *attr, void *buf,
			uint16_t len, uint16_t offset)
{
	const uint16_t *u16 = attr->user_data;
	uint16_t value = sys_cpu_to_le16(*u16);

	return bt_gatt_attr_read(conn, attr, buf, len, offset, &value, sizeof(value));
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

static bool simulate_temp;
static struct temperature_sensor sensor_1 = {
	.temp_value = 1200,
	.lower_limit = -10000,
	.upper_limit = 10000,
	.condition = ESS_VALUE_CHANGED,
	.meas.sampling_func = 0x00,
	.meas.meas_period = 0x01,
	.meas.update_interval = SENSOR_1_UPDATE_IVAL,
	.meas.application = 0x1c,
	.meas.meas_uncertainty = 0x04,
};

static void temp_ccc_cfg_changed(const struct bt_gatt_attr *attr, uint16_t value)
{
	LOG_DBG("temp_ccc_cfg_changed");
	simulate_temp = value == BT_GATT_CCC_NOTIFY;
}

struct read_es_measurement_rp {
	uint16_t flags; /* Reserved for Future Use */
	uint8_t sampling_function;
	uint8_t measurement_period[3];
	uint8_t update_interval[3];
	uint8_t application;
	uint8_t measurement_uncertainty;
} __packed;

static ssize_t read_es_measurement(struct bt_conn *conn, const struct bt_gatt_attr *attr, void *buf,
				   uint16_t len, uint16_t offset)
{
	const struct es_measurement *value = attr->user_data;
	struct read_es_measurement_rp rsp;
	LOG_DBG("read measurement");
	rsp.flags = sys_cpu_to_le16(value->flags);
	rsp.sampling_function = value->sampling_func;
	sys_put_le24(value->meas_period, rsp.measurement_period);
	sys_put_le24(value->update_interval, rsp.update_interval);
	rsp.application = value->application;
	rsp.measurement_uncertainty = value->meas_uncertainty;

	return bt_gatt_attr_read(conn, attr, buf, len, offset, &rsp, sizeof(rsp));
}

static ssize_t read_temp_valid_range(struct bt_conn *conn, const struct bt_gatt_attr *attr,
				     void *buf, uint16_t len, uint16_t offset)
{
	const struct temperature_sensor *sensor = attr->user_data;
	uint16_t tmp[] = { sys_cpu_to_le16(sensor->lower_limit),
			   sys_cpu_to_le16(sensor->upper_limit) };

	return bt_gatt_attr_read(conn, attr, buf, len, offset, tmp, sizeof(tmp));
}

struct es_trigger_setting_seconds {
	uint8_t condition;
	uint8_t sec[3];
} __packed;

struct es_trigger_setting_reference {
	uint8_t condition;
	int16_t ref_val;
} __packed;

static ssize_t read_temp_trigger_setting(struct bt_conn *conn, const struct bt_gatt_attr *attr,
					 void *buf, uint16_t len, uint16_t offset)
{
	const struct temperature_sensor *sensor = attr->user_data;

	switch (sensor->condition) {
	/* Operand N/A */
	case ESS_TRIGGER_INACTIVE:
		__fallthrough;
	case ESS_VALUE_CHANGED:
		return bt_gatt_attr_read(conn, attr, buf, len, offset, &sensor->condition,
					 sizeof(sensor->condition));
	/* Seconds */
	case ESS_FIXED_TIME_INTERVAL:
		__fallthrough;
	case ESS_NO_LESS_THAN_SPECIFIED_TIME: {
		struct es_trigger_setting_seconds rp;

		rp.condition = sensor->condition;
		sys_put_le24(sensor->seconds, rp.sec);

		return bt_gatt_attr_read(conn, attr, buf, len, offset, &rp, sizeof(rp));
	}
	/* Reference temperature */
	default: {
		struct es_trigger_setting_reference rp;

		rp.condition = sensor->condition;
		rp.ref_val = sys_cpu_to_le16(sensor->ref_val);

		return bt_gatt_attr_read(conn, attr, buf, len, offset, &rp, sizeof(rp));
	}
	}
}

static bool check_condition(uint8_t condition, int16_t old_val, int16_t new_val, int16_t ref_val)
{
	switch (condition) {
	case ESS_TRIGGER_INACTIVE:
		return false;
	case ESS_FIXED_TIME_INTERVAL:
	case ESS_NO_LESS_THAN_SPECIFIED_TIME:
		/* TODO: Check time requirements */
		return false;
	case ESS_VALUE_CHANGED:
		return new_val != old_val;
	case ESS_LESS_THAN_REF_VALUE:
		return new_val < ref_val;
	case ESS_LESS_OR_EQUAL_TO_REF_VALUE:
		return new_val <= ref_val;
	case ESS_GREATER_THAN_REF_VALUE:
		return new_val > ref_val;
	case ESS_GREATER_OR_EQUAL_TO_REF_VALUE:
		return new_val >= ref_val;
	case ESS_EQUAL_TO_REF_VALUE:
		return new_val == ref_val;
	case ESS_NOT_EQUAL_TO_REF_VALUE:
		return new_val != ref_val;
	default:
		return false;
	}
}

static void update_temperature(const struct device *dev, struct bt_conn *conn, const struct bt_gatt_attr *chrc, int16_t value,
			       struct temperature_sensor *sensor)
{
	bool notify =
		check_condition(sensor->condition, sensor->temp_value, value, sensor->ref_val);

	/* Update temperature value */
	sensor->temp_value = value;

	/* Trigger notification if conditions are met */
	if (notify) {
		value = sensor->temp_value;

		LOG_DBG("TEM: %d", value);

		// uint8_t *enc_value;
		// uint8_t *hex_value={0};
		// uint8_t enc_len=0;
		// d2h(value, enc_value, &enc_len);
		// enc(dev, hex_value, enc_value, sizeof(uint8_t));
		// value = sys_cpu_to_le16(sensor->temp_value);
		// LOG_DBG("notify:  ");
		// print_buffer_uint16(&value, enc_len);
		// LOG_DBG("enc_notify: ");
		// print_buffer_uint8(enc_value, enc_len);
		// bt_gatt_notify(conn, chrc, &enc_value, sizeof(value));

		bt_gatt_notify(conn, chrc, &value, sizeof(value));
	}
}

BT_GATT_SERVICE_DEFINE(ess_svc, 
	BT_GATT_PRIMARY_SERVICE(BT_UUID_ESS),
	/* Temperature Sensor 1 */
	BT_GATT_CHARACTERISTIC(BT_UUID_TEMPERATURE,
				BT_GATT_CHRC_READ | BT_GATT_CHRC_NOTIFY,
				BT_GATT_PERM_READ, read_u16, NULL,
				&sensor_1.temp_value),
	// BT_GATT_DESCRIPTOR(BT_UUID_ES_MEASUREMENT, BT_GATT_PERM_READ,
	// 		read_es_measurement, NULL, &sensor_1.meas),
	BT_GATT_CUD(SENSOR_1_NAME, BT_GATT_PERM_READ),
	// BT_GATT_DESCRIPTOR(BT_UUID_VALID_RANGE, BT_GATT_PERM_READ,
	// 		read_temp_valid_range, NULL, &sensor_1),
	// BT_GATT_DESCRIPTOR(BT_UUID_ES_TRIGGER_SETTING, BT_GATT_PERM_READ,
	// 		read_temp_trigger_setting, NULL, &sensor_1),
	BT_GATT_CCC(temp_ccc_cfg_changed, BT_GATT_PERM_READ | BT_GATT_PERM_WRITE), 
);

static void ess_simulate(const struct device *dev)
{
	static uint8_t i;
	uint16_t val;

	if (!(i % SENSOR_1_UPDATE_IVAL)) {
		val = 1200 + i;
		update_temperature(dev, NULL, &ess_svc.attrs[2], val, &sensor_1);
	}

	if (!(i % INT8_MAX)) {
		i = 0U;
	}

	i++;
}

static const struct bt_data ad[] = {
	BT_DATA_BYTES(BT_DATA_FLAGS, (BT_LE_AD_GENERAL | BT_LE_AD_NO_BREDR)),
	// BT_DATA_BYTES(BT_DATA_GAP_APPEARANCE, 0x00, 0x03),
	BT_DATA_BYTES(BT_DATA_UUID16_ALL, 
	BT_UUID_16_ENCODE(BT_UUID_ESS_VAL),
	BT_UUID_16_ENCODE(BT_UUID_TEMPERATURE_VAL),
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
	if (bt_conn_set_security(conn, BT_SECURITY_L4)) {
		LOG_DBG("Failed to set security");
	}
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
}

static void security_changed(struct bt_conn *conn, bt_security_t level, enum bt_security_err err)
{
	char addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));

	if (!err) {
		LOG_DBG("Security changed: %s level %u", addr, level);
		LOG_DBG(" -enc_key: %d", bt_conn_enc_key_size(conn));
		LOG_DBG(" -security_level: %d", bt_conn_get_security(conn));
		// bt_conn_enc_key_info(conn);
	} else {
		LOG_DBG("Security failed: %s level %u err %d", addr, level, err);
	}
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
	LOG_DBG("enc_key: %d", bt_conn_enc_key_size(conn));
	LOG_DBG("security_level: %d", bt_conn_get_security(conn));
	LOG_DBG("Pairing Complete");
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

void main(void)
{
	int err;
	const struct device *dev = device_get_binding(CRYPTO_DRV_NAME);
	if (!dev) {
		LOG_ERR("%s pseudo device not found", CRYPTO_DRV_NAME);
		return;
	}

	if (validate_hw_compatibility(dev)) {
		LOG_ERR("Incompatible h/w");
		return;
	}
	ccm_mode(dev);
	LOG_DBG("..............");

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

	while (1) {
		k_sleep(K_SECONDS(1));

		
		/* Temperature simulation */
		if (simulate_temp) {
			// LOG_DBG("start porting %d .....",simulate_temp);
			ess_simulate(dev);
		}

		// /* Battery level simulation */
		// bas_notify();
	}
}
