/* main.c - Application main entry point */

/*
 * Copyright (c) 2015-2016 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <zephyr/types.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <sys/printk.h>
#include <sys/util.h>
#include <sys/byteorder.h>
#include <zephyr.h>
#include <device.h>
#include <drivers/gpio.h>
#include <inttypes.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/conn.h>
#include <bluetooth/uuid.h>
#include <bluetooth/gatt.h>

#define SLEEP_TIME_MS 1
#define NUMBER_OF_SLOTS 3
#define EDS_VERSION 0x00
#define EDS_URL_READ_OFFSET 2
#define EDS_URL_WRITE_OFFSET 4
#define EDS_IDLE_TIMEOUT K_SECONDS(30)
#define IBEACON_RSSI 0xc8
#define BTN_COUNT 3

#define SW0_NODE	DT_ALIAS(sw0)
#define SW1_NODE	DT_ALIAS(sw1)
#define SW2_NODE	DT_ALIAS(sw2)

#if !DT_NODE_HAS_STATUS(SW0_NODE, okay)
#error "Unsupported board: sw0 devicetree alias is not defined"
#endif
#if !DT_NODE_HAS_STATUS(SW1_NODE, okay)
#error "Unsupported board: sw1 devicetree alias is not defined"
#endif
#if !DT_NODE_HAS_STATUS(SW2_NODE, okay)
#error "Unsupported board: sw2 devicetree alias is not defined"
#endif
// #if !DT_NODE_HAS_STATUS(SW3_NODE, okay)
// #error "Unsupported board: sw3 devicetree alias is not defined"
// #endif

static const struct gpio_dt_spec button[BTN_COUNT] = {
	GPIO_DT_SPEC_GET_OR(SW0_NODE, gpios, {0}),
	GPIO_DT_SPEC_GET_OR(SW1_NODE, gpios, {1}),
	GPIO_DT_SPEC_GET_OR(SW2_NODE, gpios, {2}),
};
static struct gpio_callback button_cb_data[BTN_COUNT];

/* Idle timer */
struct k_work_delayable btn_work[BTN_COUNT], eddy_TLM;

/* Eddystone Service Variables */
/* Service UUID a3c87500-8ed3-4bdf-8a39-a01bebede295 */
static struct bt_uuid_128 eds_uuid = BT_UUID_INIT_128(
	BT_UUID_128_ENCODE(0xa3c87500, 0x8ed3, 0x4bdf, 0x8a39, 0xa01bebede295));

/* Characteristic UUID a3c87501-8ed3-4bdf-8a39-a01bebede295 */
static struct bt_uuid_128 eds_caps_uuid = BT_UUID_INIT_128(
	BT_UUID_128_ENCODE(0xa3c87501, 0x8ed3, 0x4bdf, 0x8a39, 0xa01bebede295));

/* Characteristic UUID a3c87502-8ed3-4bdf-8a39-a01bebede295 */
static struct bt_uuid_128 eds_slot_uuid = BT_UUID_INIT_128(
	BT_UUID_128_ENCODE(0xa3c87502, 0x8ed3, 0x4bdf, 0x8a39, 0xa01bebede295));

/* Characteristic UUID a3c87503-8ed3-4bdf-8a39-a01bebede295 */
static struct bt_uuid_128 eds_intv_uuid = BT_UUID_INIT_128(
	BT_UUID_128_ENCODE(0xa3c87503, 0x8ed3, 0x4bdf, 0x8a39, 0xa01bebede295));

/* Characteristic UUID a3c87504-8ed3-4bdf-8a39-a01bebede295 */
static struct bt_uuid_128 eds_tx_uuid = BT_UUID_INIT_128(
	BT_UUID_128_ENCODE(0xa3c87504, 0x8ed3, 0x4bdf, 0x8a39, 0xa01bebede295));

/* Characteristic UUID a3c87505-8ed3-4bdf-8a39-a01bebede295 */
static struct bt_uuid_128 eds_adv_tx_uuid = BT_UUID_INIT_128(
	BT_UUID_128_ENCODE(0xa3c87505, 0x8ed3, 0x4bdf, 0x8a39, 0xa01bebede295));

/* Characteristic UUID a3c87506-8ed3-4bdf-8a39-a01bebede295 */
static struct bt_uuid_128 eds_lock_uuid = BT_UUID_INIT_128(
	BT_UUID_128_ENCODE(0xa3c87506, 0x8ed3, 0x4bdf, 0x8a39, 0xa01bebede295));

/* Characteristic UUID a3c87507-8ed3-4bdf-8a39-a01bebede295 */
static struct bt_uuid_128 eds_unlock_uuid = BT_UUID_INIT_128(
	BT_UUID_128_ENCODE(0xa3c87507, 0x8ed3, 0x4bdf, 0x8a39, 0xa01bebede295));

/* Characteristic UUID a3c87508-8ed3-4bdf-8a39-a01bebede295 */
static struct bt_uuid_128 eds_ecdh_uuid = BT_UUID_INIT_128(
	BT_UUID_128_ENCODE(0xa3c87508, 0x8ed3, 0x4bdf, 0x8a39, 0xa01bebede295));

/* Characteristic UUID a3c87509-8ed3-4bdf-8a39-a01bebede295 */
static struct bt_uuid_128 eds_eid_uuid = BT_UUID_INIT_128(
	BT_UUID_128_ENCODE(0xa3c87509, 0x8ed3, 0x4bdf, 0x8a39, 0xa01bebede295));

/* Characteristic UUID a3c8750a-8ed3-4bdf-8a39-a01bebede295 */
static struct bt_uuid_128 eds_data_uuid = BT_UUID_INIT_128(
	BT_UUID_128_ENCODE(0xa3c8750a, 0x8ed3, 0x4bdf, 0x8a39, 0xa01bebede295));

/* Characteristic UUID a3c8750b-8ed3-4bdf-8a39-a01bebede295 */
static struct bt_uuid_128 eds_reset_uuid = BT_UUID_INIT_128(
	BT_UUID_128_ENCODE(0xa3c8750b, 0x8ed3, 0x4bdf, 0x8a39, 0xa01bebede295));

/* Characteristic UUID a3c8750c-8ed3-4bdf-8a39-a01bebede295 */
static struct bt_uuid_128 eds_connectable_uuid = BT_UUID_INIT_128(
	BT_UUID_128_ENCODE(0xa3c8750c, 0x8ed3, 0x4bdf, 0x8a39, 0xa01bebede295));

enum {
	EDS_TYPE_UID = 0x00,
	EDS_TYPE_URL = 0x10,
	EDS_TYPE_TLM = 0x20,
	EDS_TYPE_EID = 0x30,
	EDS_TYPE_NONE = 0xff,
};

enum {
	EDS_HTTP_WWW = 0x00,
	EDS_HTTPS_WWW = 0x10,
	EDS_HTTP = 0x20,
	EDS_HTTPS = 0x30,
};

enum {
	EDS_SLOT_UID = sys_cpu_to_be16(BIT(0)),
	EDS_SLOT_URL = sys_cpu_to_be16(BIT(1)),
	EDS_SLOT_TLM = sys_cpu_to_be16(BIT(2)),
	EDS_SLOT_EID = sys_cpu_to_be16(BIT(3)),
};

struct eds_capabilities {
	uint8_t version;
	uint8_t slots;
	uint8_t uids;
	uint8_t adv_types;
	uint16_t slot_types;
	uint8_t tx_power;
} __packed;

static struct eds_capabilities eds_caps = {
	.version = EDS_VERSION,
	.slots = NUMBER_OF_SLOTS,
	.slot_types = EDS_SLOT_URL, /* TODO: Add support for other slot types */
};

uint8_t eds_active_slot, TLM_active;

enum {
	EDS_LOCKED = 0x00,
	EDS_UNLOCKED = 0x01,
	EDS_UNLOCKED_NO_RELOCKING = 0x02,
};

struct eds_slot {
	uint8_t type;
	uint8_t state;
	uint8_t connectable;
	uint16_t interval;
	uint8_t tx_power;
	uint8_t adv_tx_power;
	uint8_t lock[16];
	uint8_t challenge[16];
	struct bt_data ad[3];
};

static const struct bt_data ad[] = {
	BT_DATA_BYTES(BT_DATA_FLAGS, (BT_LE_AD_GENERAL | BT_LE_AD_NO_BREDR)),
	BT_DATA_BYTES(BT_DATA_UUID16_ALL, 0xaa, 0xfe),
	BT_DATA_BYTES(BT_DATA_SVC_DATA16,
		      0xaa, 0xfe, /* Eddystone UUID */
		      EDS_TYPE_URL, /* Eddystone-URL frame type */
		      0x00, /* Calibrated Tx power at 0m */
		      EDS_HTTP_WWW, /* URL Scheme Prefix http://www. */
		      'z', 'e', 'p', 'h', 'y', 'r',
		      'p', 'r', 'o', 'j', 'e', 'c', 't',
		      0x08), 
};

static const struct bt_data ibeacon[] = {
	BT_DATA_BYTES(BT_DATA_FLAGS, BT_LE_AD_NO_BREDR),
	BT_DATA_BYTES(BT_DATA_MANUFACTURER_DATA,
		      0x4c, 0x00, /* Apple */
		      0x02, 0x15, /* iBeacon */
		      0x18, 0xee, 0x15, 0x16, /* UUID[15..12] */
		      0x01, 0x6b, /* UUID[11..10] */
		      0x4b, 0xec, /* UUID[9..8] */
		      0xad, 0x96, /* UUID[7..6] */
		      0xbc, 0xb9, 0x6d, 0x16, 0x6e, 0x97, /* UUID[5..0] */
		      0x00, 0x00, /* Major */
		      0x00, 0x00, /* Minor */
		      IBEACON_RSSI) /* Calibrated RSSI @ 1m */
};

enum {
	EDS_SLOT_URL_TYPE = 0,
	EDS_SLOT_UID_TYPE = 1,
	EDS_SLOT_TLM_TYPE = 2,
};

static struct eds_slot eds_slots[NUMBER_OF_SLOTS] = {
	{
		.type = EDS_TYPE_NONE,  /* Start as disabled */
		.state = EDS_UNLOCKED, /* Start unlocked */
		.interval = sys_cpu_to_be16(BT_GAP_ADV_FAST_INT_MIN_2),
		.lock = { 'N', 'C', 'H',  'U', 'W', 'C', 'C', 'C', '-', 'W',
			  'e', 'b', 'L', 'i', 'n', 'k' },
		.challenge = {},
		.ad = {
			BT_DATA_BYTES(BT_DATA_FLAGS, BT_LE_AD_NO_BREDR),
			BT_DATA_BYTES(BT_DATA_UUID16_ALL, 0xaa, 0xfe),
			BT_DATA_BYTES(BT_DATA_SVC_DATA16,
				0xaa, 0xfe, /* Eddystone UUID */
				EDS_TYPE_URL, /* Eddystone-URL frame type */
				0x00, /* Calibrated Tx power at 0m */
				EDS_HTTPS, /* URL Scheme Prefix https://. */
				'r','e','u','r','l','.','c','c','/','9','5','j','Y','y','Y'),
		},
	},
	{
		.type = EDS_TYPE_NONE,  /* Start as disabled */
		.state = EDS_UNLOCKED, /* Start unlocked */
		.interval = sys_cpu_to_be16(BT_GAP_ADV_FAST_INT_MIN_2),
		.lock = { 'N', 'C', 'H',  'U', 'W', 'C', 'C', 'C', '-', 'W',
			  'e', 'b', 'L', 'i', 'n', 'k' },
		.challenge = {},
		.ad = {
			BT_DATA_BYTES(BT_DATA_FLAGS, BT_LE_AD_NO_BREDR),
			BT_DATA_BYTES(BT_DATA_UUID16_ALL, 0xaa, 0xfe),
			BT_DATA_BYTES(BT_DATA_SVC_DATA16,
				0xaa, 0xfe, /* Eddystone UUID */
				EDS_TYPE_UID, /* Eddystone-UID frame type */
				0x00, /* Calibrated Tx power at 0m */
				0x00, 0x00, 'N', 'C', 'H', 'U', 'W', 'C', 'C', 'C', 
				0x00, 0x00, 'H', 'A', 'N', 'K',
				0x00, 0x00
			) 
		},
	},
	{
		.type = EDS_TYPE_NONE,  /* Start as disabled */
		.state = EDS_UNLOCKED, /* Start unlocked */
		.interval = sys_cpu_to_be16(BT_GAP_ADV_FAST_INT_MIN_2),
		.lock = { 'N', 'C', 'H',  'U', 'W', 'C', 'C', 'C', '-', 'W',
			  'e', 'b', 'L', 'i', 'n', 'k' },
		.challenge = {},
		.ad = {
			BT_DATA_BYTES(BT_DATA_FLAGS, BT_LE_AD_NO_BREDR),
			BT_DATA_BYTES(BT_DATA_UUID16_ALL, 0xaa, 0xfe),
			BT_DATA_BYTES(BT_DATA_SVC_DATA16,
				0xaa, 0xfe, /* Eddystone UUID */
				EDS_TYPE_TLM, 0x00, /* Eddystone-UID frame type */
				0x64, 0x00, // Battery voltage
				0x20, 0x00, // temperature
				0x01, 0x00, 0x00, 0x00, // PDU count
				0x00, 0x00, 0x00, 0x00, // TIMESTAMP 
			) 
		},
	},
};

			  
static ssize_t read_caps(struct bt_conn *conn, const struct bt_gatt_attr *attr,
			 void *buf, uint16_t len, uint16_t offset)
{
	const struct eds_capabilities *caps = attr->user_data;

	return bt_gatt_attr_read(conn, attr, buf, len, offset, caps,
				 sizeof(*caps));
}

static ssize_t read_slot(struct bt_conn *conn, const struct bt_gatt_attr *attr,
			 void *buf, uint16_t len, uint16_t offset)
{
	return bt_gatt_attr_read(conn, attr, buf, len, offset,
				 &eds_active_slot, sizeof(eds_active_slot));
}

static ssize_t write_slot(struct bt_conn *conn,
			  const struct bt_gatt_attr *attr, const void *buf,
			  uint16_t len, uint16_t offset, uint8_t flags)
{
	uint8_t value;

	if (offset + len > sizeof(value)) {
		return BT_GATT_ERR(BT_ATT_ERR_INVALID_OFFSET);
	}

	memcpy(&value, buf, len);

	if (value + 1 > NUMBER_OF_SLOTS) {
		return BT_GATT_ERR(BT_ATT_ERR_WRITE_NOT_PERMITTED);
	}

	eds_active_slot = value;

	return len;
}

static ssize_t read_tx_power(struct bt_conn *conn,
			     const struct bt_gatt_attr *attr,
			     void *buf, uint16_t len, uint16_t offset)
{
	struct eds_slot *slot = &eds_slots[eds_active_slot];

	if (slot->state == EDS_LOCKED) {
		return BT_GATT_ERR(BT_ATT_ERR_READ_NOT_PERMITTED);
	}

	return bt_gatt_attr_read(conn, attr, buf, len, offset, &slot->tx_power,
				 sizeof(slot->tx_power));
}

static ssize_t write_tx_power(struct bt_conn *conn,
			      const struct bt_gatt_attr *attr,
			      const void *buf, uint16_t len, uint16_t offset,
			      uint8_t flags)
{
	struct eds_slot *slot = &eds_slots[eds_active_slot];

	if (slot->state == EDS_LOCKED) {
		return BT_GATT_ERR(BT_ATT_ERR_WRITE_NOT_PERMITTED);
	}

	if (offset + len > sizeof(slot->tx_power)) {
		return BT_GATT_ERR(BT_ATT_ERR_INVALID_OFFSET);
	}

	memcpy(&slot->tx_power, buf, len);

	return len;
}

static ssize_t read_adv_tx_power(struct bt_conn *conn,
				 const struct bt_gatt_attr *attr,
				 void *buf, uint16_t len, uint16_t offset)
{
	struct eds_slot *slot = &eds_slots[eds_active_slot];

	if (slot->state == EDS_LOCKED) {
		return BT_GATT_ERR(BT_ATT_ERR_READ_NOT_PERMITTED);
	}

	return bt_gatt_attr_read(conn, attr, buf, len, offset, &slot->tx_power,
				 sizeof(slot->tx_power));
}

static ssize_t write_adv_tx_power(struct bt_conn *conn,
				  const struct bt_gatt_attr *attr,
				  const void *buf, uint16_t len,
				  uint16_t offset,
				  uint8_t flags)
{
	struct eds_slot *slot = &eds_slots[eds_active_slot];

	if (slot->state == EDS_LOCKED) {
		return BT_GATT_ERR(BT_ATT_ERR_WRITE_NOT_PERMITTED);
	}

	if (offset + len > sizeof(slot->adv_tx_power)) {
		return BT_GATT_ERR(BT_ATT_ERR_INVALID_OFFSET);
	}

	memcpy(&slot->adv_tx_power, buf, len);

	return len;
}

static ssize_t read_interval(struct bt_conn *conn,
			     const struct bt_gatt_attr *attr,
			     void *buf, uint16_t len, uint16_t offset)
{
	struct eds_slot *slot = &eds_slots[eds_active_slot];

	if (slot->state == EDS_LOCKED) {
		return BT_GATT_ERR(BT_ATT_ERR_WRITE_NOT_PERMITTED);
	}

	return bt_gatt_attr_read(conn, attr, buf, len, offset, &slot->interval,
				 sizeof(slot->interval));
}

static ssize_t read_lock(struct bt_conn *conn, const struct bt_gatt_attr *attr,
			 void *buf, uint16_t len, uint16_t offset)
{
	struct eds_slot *slot = &eds_slots[eds_active_slot];

	return bt_gatt_attr_read(conn, attr, buf, len, offset, &slot->state,
				 sizeof(slot->state));
}

static ssize_t write_lock(struct bt_conn *conn,
			  const struct bt_gatt_attr *attr, const void *buf,
			  uint16_t len, uint16_t offset, uint8_t flags)
{
	struct eds_slot *slot = &eds_slots[eds_active_slot];
	uint8_t value;

	if (slot->state == EDS_LOCKED) {
		return BT_GATT_ERR(BT_ATT_ERR_WRITE_NOT_PERMITTED);
	}

	if (offset) {
		return BT_GATT_ERR(BT_ATT_ERR_INVALID_OFFSET);
	}

	/* Write 1 byte to lock or 17 bytes to transition to a new lock state */
	if (len != 1U) {
		/* TODO: Allow setting new lock code, using AES-128-ECB to
		 * decrypt with the existing lock code and set the unencrypted
		 * value as the new code.
		 */
		return BT_GATT_ERR(BT_ATT_ERR_INVALID_ATTRIBUTE_LEN);
	}

	memcpy(&value, buf, sizeof(value));

	if (value > EDS_UNLOCKED_NO_RELOCKING) {
		return BT_GATT_ERR(BT_ATT_ERR_WRITE_NOT_PERMITTED);
	}

	slot->state = value;

	return len;
}

static ssize_t read_unlock(struct bt_conn *conn,
			   const struct bt_gatt_attr *attr,
			   void *buf, uint16_t len, uint16_t offset)
{
	struct eds_slot *slot = &eds_slots[eds_active_slot];

	if (slot->state != EDS_LOCKED) { return BT_GATT_ERR(BT_ATT_ERR_READ_NOT_PERMITTED); }

	/* returns a 128-bit challenge token. This token is for one-time use
	 * and cannot be replayed.
	 */
	if (bt_rand(slot->challenge, sizeof(slot->challenge))) { return BT_GATT_ERR(BT_ATT_ERR_UNLIKELY); }

	return bt_gatt_attr_read(conn, attr, buf, len, offset, slot->challenge,
				 sizeof(slot->challenge));
}

static ssize_t write_unlock(struct bt_conn *conn,
			    const struct bt_gatt_attr *attr, const void *buf,
			    uint16_t len, uint16_t offset, uint8_t flags)
{
	struct eds_slot *slot = &eds_slots[eds_active_slot];

	if (slot->state != EDS_LOCKED) { return BT_GATT_ERR(BT_ATT_ERR_READ_NOT_PERMITTED); }

	/* TODO: accepts a 128-bit encrypted value that verifies the client
	 * knows the beacon's lock code.
	 */

	return BT_GATT_ERR(BT_ATT_ERR_NOT_SUPPORTED);
}

static uint8_t eds_ecdh[32] = {}; /* TODO: Add ECDH key */

static ssize_t read_ecdh(struct bt_conn *conn, const struct bt_gatt_attr *attr,
			 void *buf, uint16_t len, uint16_t offset)
{
	uint8_t *value = attr->user_data;

	return bt_gatt_attr_read(conn, attr, buf, len, offset, value,
				 sizeof(eds_ecdh));
}

static uint8_t eds_eid[16] = {}; /* TODO: Add EID key */

static ssize_t read_eid(struct bt_conn *conn, const struct bt_gatt_attr *attr,
			void *buf, uint16_t len, uint16_t offset)
{
	uint8_t *value = attr->user_data;

	return bt_gatt_attr_read(conn, attr, buf, len, offset, value,
				 sizeof(eds_eid));
}

static ssize_t read_adv_data(struct bt_conn *conn,
			     const struct bt_gatt_attr *attr, void *buf,
			     uint16_t len, uint16_t offset)
{
	struct eds_slot *slot = &eds_slots[eds_active_slot];

	if (slot->state == EDS_LOCKED) { return BT_GATT_ERR(BT_ATT_ERR_READ_NOT_PERMITTED); }

	/* If the slot is currently not broadcasting, reading the slot data
	 * shall return either an empty array or a single byte of 0x00.
	 */
	if (slot->type == EDS_TYPE_NONE) { return 0; }

	return bt_gatt_attr_read(conn, attr, buf, len, offset,
				 slot->ad[2].data + EDS_URL_READ_OFFSET,
				 slot->ad[2].data_len - EDS_URL_READ_OFFSET);
}

static void eddy_TLM_ADV_update()
{
	int32_t reftime = k_uptime_get_32();
	uint8_t hex[4];
	printk("update\n");
	sprintf(hex, "%x", reftime);
	const struct bt_data TLM_ad[] = {
		BT_DATA_BYTES(BT_DATA_FLAGS, BT_LE_AD_NO_BREDR),
		BT_DATA_BYTES(BT_DATA_UUID16_ALL, 0xaa, 0xfe),
		BT_DATA_BYTES(BT_DATA_SVC_DATA16,
			0xaa, 0xfe, /* Eddystone UUID */
			EDS_TYPE_TLM, 0x00, /* Eddystone-UID frame type */
			0x05, 0xDC, // Battery voltage
			0x20, 0x00, // temperature
			0x01, 0x00, 0x00, 0x00, // PDU count
			hex[0], hex[1], hex[2], hex[3], // TIMESTAMP 
		), 
	};
	int err = bt_le_adv_update_data(TLM_ad, ARRAY_SIZE(TLM_ad),
									NULL, 0);
	if (err) {
		printk("TLM update failed to start (err %d)\n", err);
		return;
	}
}


static int eds_slot_restart(struct eds_slot *slot, uint8_t type)
{
	int err = 0;
	char addr_s[BT_ADDR_LE_STR_LEN];
	bt_addr_le_t addr = {0};
	struct bt_le_oob oob;
	// size_t count = 1;

	bt_le_adv_stop();
	switch (type)
	{
		case EDS_TYPE_NONE:
			if (bt_le_oob_get_local(BT_ID_DEFAULT, &oob) == 0) { addr = oob.addr; }
			err = bt_le_adv_start(BT_LE_ADV_CONN_NAME, ad, ARRAY_SIZE(ad), NULL, 0);
			break;
		case EDS_TYPE_UID:
		case EDS_TYPE_URL:
			err = bt_le_adv_start(BT_LE_ADV_NCONN_NAME, slot->ad,
									ARRAY_SIZE(slot->ad), NULL, 0);
			break;
		case EDS_TYPE_TLM:
			TLM_active=1;
			err = bt_le_adv_start(BT_LE_ADV_NCONN_NAME, slot->ad, 
									ARRAY_SIZE(slot->ad), NULL, 0);
			while (1)
			{ 
				if(TLM_active){ eddy_TLM_ADV_update(); }
				else{ break; } 
				k_sleep(K_SECONDS(5));
			}
			break;
	}
	if (err) {
		printk("Advertising failed to start (err %d)\n", err);
		return err;
	}

	bt_addr_le_to_str(&addr, addr_s, sizeof(addr_s));
	printk("Advertising as %s\n", addr_s);

	slot->type = type;
	return 0;
}

static ssize_t write_reset(struct bt_conn *conn,
			   const struct bt_gatt_attr *attr,
			   const void *buf, uint16_t len, uint16_t offset,
			   uint8_t flags)
{
	/* TODO: Power cycle or reload for storage the values */
	return BT_GATT_ERR(BT_ATT_ERR_WRITE_NOT_PERMITTED);
}

static ssize_t read_connectable(struct bt_conn *conn,
			     const struct bt_gatt_attr *attr, void *buf,
			     uint16_t len, uint16_t offset)
{
	uint8_t connectable = 0x01;

	/* Returning a non-zero value indicates that the beacon is capable
	 * of becoming non-connectable
	 */
	return bt_gatt_attr_read(conn, attr, buf, len, offset,
				 &connectable, sizeof(connectable));
}

/* Eddystone Configuration Service Declaration */
BT_GATT_SERVICE_DEFINE(eds_svc,
	BT_GATT_PRIMARY_SERVICE(&eds_uuid),
	/* Capabilities: Readable only when unlocked. Never writable. */
	BT_GATT_CHARACTERISTIC(&eds_caps_uuid.uuid, BT_GATT_CHRC_READ,
			       BT_GATT_PERM_READ, read_caps, NULL, &eds_caps),
	/* Active slot: Must be unlocked for both read and write. */
	BT_GATT_CHARACTERISTIC(&eds_slot_uuid.uuid,
			       BT_GATT_CHRC_READ | BT_GATT_CHRC_WRITE,
			       BT_GATT_PERM_READ | BT_GATT_PERM_WRITE,
			       read_slot, write_slot, NULL),
	/* Advertising Interval: Must be unlocked for both read and write. */
	BT_GATT_CHARACTERISTIC(&eds_intv_uuid.uuid, BT_GATT_CHRC_READ,
			       BT_GATT_PERM_READ, read_interval, NULL, NULL),
	/* Radio TX Power: Must be unlocked for both read and write. */
	BT_GATT_CHARACTERISTIC(&eds_tx_uuid.uuid,
			       BT_GATT_CHRC_READ | BT_GATT_CHRC_WRITE,
			       BT_GATT_PERM_READ | BT_GATT_PERM_WRITE,
			       read_tx_power, write_tx_power, NULL),
	/* Advertised TX Power: Must be unlocked for both read and write. */
	BT_GATT_CHARACTERISTIC(&eds_adv_tx_uuid.uuid,
			       BT_GATT_CHRC_READ | BT_GATT_CHRC_WRITE,
			       BT_GATT_PERM_READ | BT_GATT_PERM_WRITE,
			       read_adv_tx_power, write_adv_tx_power, NULL),
	/* Lock State:
	 * Readable in locked or unlocked state.
	 * Writeable only in unlocked state.
	 */
	BT_GATT_CHARACTERISTIC(&eds_lock_uuid.uuid,
			       BT_GATT_CHRC_READ | BT_GATT_CHRC_WRITE,
			       BT_GATT_PERM_READ | BT_GATT_PERM_WRITE,
			       read_lock, write_lock, NULL),
	/* Unlock:
	 * Readable only in locked state.
	 * Writeable only in locked state.
	 */
	BT_GATT_CHARACTERISTIC(&eds_unlock_uuid.uuid,
			       BT_GATT_CHRC_READ | BT_GATT_CHRC_WRITE,
			       BT_GATT_PERM_READ | BT_GATT_PERM_WRITE,
			       read_unlock, write_unlock, NULL),
	/* Public ECDH Key: Readable only in unlocked state. Never writable. */
	BT_GATT_CHARACTERISTIC(&eds_ecdh_uuid.uuid, BT_GATT_CHRC_READ,
			       BT_GATT_PERM_READ, read_ecdh, NULL, &eds_ecdh),
	/* EID Identity Key:Readable only in unlocked state. Never writable. */
	BT_GATT_CHARACTERISTIC(&eds_eid_uuid.uuid, BT_GATT_CHRC_READ,
			       BT_GATT_PERM_READ, read_eid, NULL, eds_eid),
	/* ADV Slot Data: Must be unlocked for both read and write. */
	BT_GATT_CHARACTERISTIC(&eds_data_uuid.uuid,
			       BT_GATT_CHRC_READ , BT_GATT_PERM_READ ,
			       read_adv_data, NULL, NULL),
	/* ADV Factory Reset: Must be unlocked for write. */
	BT_GATT_CHARACTERISTIC(&eds_reset_uuid.uuid,  BT_GATT_CHRC_WRITE,
			       BT_GATT_PERM_WRITE, NULL, write_reset, NULL),
	/* ADV Remain Connectable: Must be unlocked for write. */
	BT_GATT_CHARACTERISTIC(&eds_connectable_uuid.uuid,
			       BT_GATT_CHRC_READ, BT_GATT_PERM_READ,
			       read_connectable, NULL, NULL),
);

static void bt_ready(int err)
{
	char addr_s[BT_ADDR_LE_STR_LEN];
	struct bt_le_oob oob;

	printk("Bluetooth initialized\n");
	/* Start advertising */
	err = bt_le_adv_start(BT_LE_ADV_NCONN, ad, ARRAY_SIZE(ad), NULL, 0);
	if (err) {
		printk("Advertising failed to start (err %d)\n", err);
		return;
	}

	/* Restore connectable if slot */
	bt_le_oob_get_local(BT_ID_DEFAULT, &oob);
	bt_addr_le_to_str(&oob.addr, addr_s, sizeof(addr_s));
	printk("Initial advertising as %s\n", addr_s);
}

static void nonconnectable_eddy_work(struct k_work *work)
{
	uint8_t esd_type=0;
	switch (eds_active_slot)
	{
	case EDS_SLOT_URL_TYPE:
		esd_type = EDS_TYPE_URL;
		break;
	case EDS_SLOT_UID_TYPE:
		esd_type = EDS_TYPE_UID;
		break;
	case EDS_SLOT_TLM_TYPE:
		esd_type = EDS_TYPE_TLM;
		break;
	}
	printk("Switching to Beacon mode %u.\n", eds_active_slot);
	eds_slot_restart(&eds_slots[eds_active_slot], esd_type);
}

static void connected(struct bt_conn *conn, uint8_t err)
{
	if (err) { printk("Connection failed (err 0x%02x)\n", err); } 
	else { printk("Connected\n"); }
}

static void disconnected(struct bt_conn *conn, uint8_t reason)
{
	struct eds_slot *slot = &eds_slots[eds_active_slot];

	printk("Disconnected (reason 0x%02x)\n", reason);
	if (!slot->connectable) { k_work_reschedule(&btn_work[2], K_NO_WAIT); }
}

static struct bt_conn_cb conn_callbacks = {
	.connected = connected,
	.disconnected = disconnected,
};

static void connectable_eddy_work(struct k_work *work)
{
	char addr_s[BT_ADDR_LE_STR_LEN];
	struct bt_le_oob oob;

	bt_le_adv_stop();
	int err = bt_le_adv_start(BT_LE_ADV_CONN_NAME, ad,
							ARRAY_SIZE(ad), NULL, 0);
	if (err) {
		printk("Advertising failed to start (err %d)\n", err);
		return;
	}
	bt_le_oob_get_local(BT_ID_DEFAULT, &oob);
	bt_addr_le_to_str(&oob.addr, addr_s, sizeof(addr_s));

	printk("Eddystone Beacon\n");
	printk("Initial advertising as %s\n", addr_s);
	printk("Configuration mode: waiting connections...\n");
}

static void ibeacon_work(struct k_work *work)
{
	int err;
	char addr_s[BT_ADDR_LE_STR_LEN];
	bt_addr_le_t addr = {0};
	struct bt_le_oob oob;

	bt_le_adv_stop();
	if (bt_le_oob_get_local(BT_ID_DEFAULT, &oob) == 0)
	{  addr = oob.addr; }
	err = bt_le_adv_start(BT_LE_ADV_NCONN_NAME, ibeacon,\
						 ARRAY_SIZE(ibeacon), NULL, 0);
	bt_addr_le_to_str(&addr, addr_s, sizeof(addr_s));
	printk("The iBeacon advertising address is %s\n", addr_s);
}

void button_pressed(const struct device *dev, struct gpio_callback *cb, gpio_port_pins_t pins)
{
	TLM_active=0;
	switch(pins){
		case 2048:
			printk("Button pressed at 0: connectable eddystone\n");
			k_work_schedule(&btn_work[0], K_SECONDS(1));
			break;
		case 4096:
			printk("Button pressed at 1: iBeacon\n");
			k_work_schedule(&btn_work[1], K_SECONDS(1));
			break;
		case 16777216:
			printk("Button pressed at 2: non-connectable eddystone\n");
			eds_active_slot = EDS_SLOT_URL_TYPE;
			k_work_schedule(&btn_work[2], K_SECONDS(1));
			break;
	}

}

static int setup_btn()
{
	int err=0;
	for(int i=0; i<BTN_COUNT; i++){
		err = device_is_ready(button[i].port);
		if (!err) {
			printk("Error: button device %s is not ready\n", button[i].port->name);
			break;
		}

		err = gpio_pin_configure_dt(&button[i], GPIO_INPUT);
		if (err) {
			printk("Error %d: failed to configure %s pin %d\n", err, button[i].port->name, button[i].pin);
			break;
		}

		err = gpio_pin_interrupt_configure_dt(&button[i], GPIO_INT_EDGE_TO_ACTIVE);
		if (err) {
			printk("Error %d: failed to configure interrupt on %s pin %d\n", err, button[i].port->name, button[i].pin);
			break;
		}
		gpio_init_callback(&button_cb_data[i], button_pressed, BIT(button[i].pin));
		gpio_add_callback(button[i].port, &button_cb_data[i]);
	}
	return err;
}

void main(void)
{
	int err;
	//Setup button
	err = setup_btn();
	if (err) { printk("Setup button failed (err %d)\n", err); }
	else { printk("Setup button finished\n"); }
	k_work_init_delayable(&btn_work[0], connectable_eddy_work);
	k_work_init_delayable(&btn_work[1], ibeacon_work);
	k_work_init_delayable(&btn_work[2], nonconnectable_eddy_work);

	//Setup BLE
	bt_conn_cb_register(&conn_callbacks);
	err = bt_enable(bt_ready);
	if (err) { printk("Bluetooth init failed (err %d)\n", err); }
	else { printk("Press the button\n"); }

}
