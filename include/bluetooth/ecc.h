/* ecc.h - ECDH helpers */

/*
 * Copyright (c) 2016 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*  @brief Container for public key callback */
struct bt_pub_key_cb {
	/** @brief Callback type for Public Key generation.
	 *
	 *  Used to notify of the local public key or that the local key is not
	 *  available (either because of a failure to read it or because it is
	 *  being regenerated).
	 *
	 *  @param key The local public key, or NULL in case of no key.
	 */
	void (*func)(const uint8_t key[64]);

	/* Internal */
	sys_snode_t node;
};

/*  @brief Container for ecc data encryption callback */
struct bt_ecc_data_encrypt_cb {
	/** @brief Callback type for ecc data encryption.
	 *
	 *  @param C1 
	 *  @param C2 
	 */
	void (*func)(const uint8_t C1[32], const uint8_t C2[64]);
	/* Internal */
	sys_snode_t node;
};

struct bt_ecc_data_decrypt_cb {
	/** @brief Callback type for ecc data decryption.
	 *
	 *  @param M 
	 */
	void (*func)(const uint8_t M[32]);
	/* Internal */
	sys_snode_t node;
};

/*  @brief Check if public key is equal to the debug public key.
 *
 *  Compare the Public key to the Bluetooth specification defined debug public
 *  key.
 *
 *  @param pub_key The public key to compare.
 *
 *  @return True if the public key is the debug public key.
 */
bool bt_pub_key_is_debug(uint8_t *pub_key);

/*  @brief Generate a new Public Key.
 *
 *  Generate a new ECC Public Key. Provided cb must persists until callback
 *  is called. Callee adds the callback structure to a linked list. Registering
 *  multiple callbacks requires multiple calls to bt_pub_key_gen() and separate
 *  callback structures. This method cannot be called directly from result
 *  callback. After calling all the registered callbacks the linked list
 *  is cleared.
 *
 *  @param cb Callback to notify the new key.
 *
 *  @return Zero on success or negative error code otherwise
 */
int bt_pub_key_gen(struct bt_pub_key_cb *cb);

/*  @brief Get the current Public Key.
 *
 *  Get the current ECC Public Key.
 *
 *  @return Current key, or NULL if not available.
 */
const uint8_t *bt_pub_key_get(void);

/*  @typedef bt_dh_key_cb_t
 *  @brief Callback type for DH Key calculation.
 *
 *  Used to notify of the calculated DH Key.
 *
 *  @param key The DH Key, or NULL in case of failure.
 */
typedef void (*bt_dh_key_cb_t)(const uint8_t key[32]);

/*  @brief Calculate a DH Key from a remote Public Key.
 *
 *  Calculate a DH Key from the remote Public Key.
 *
 *  @param remote_pk Remote Public Key.
 *  @param cb Callback to notify the calculated key.
 *
 *  @return Zero on success or negative error code otherwise
 */
int bt_dh_key_gen(const uint8_t remote_pk[64], bt_dh_key_cb_t cb);

typedef void (*bt_ecc_encrypt_cb_t)(const uint8_t C1[32], const uint8_t C2[64]);
typedef void (*bt_ecc_decrypt_cb_t)(const uint8_t M[32]);

int bt_ecc_data_encrypt(const uint8_t *plaintext, const uint8_t *remote_pk, bt_ecc_encrypt_cb_t cb);
int bt_ecc_data_decrypt(const uint8_t *C1, const uint8_t *C2, bt_ecc_decrypt_cb_t cb);
