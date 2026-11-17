/*
 * eg_key_interface_custom.c - CryptoLib's "custom" key interface for the
 * EagleGate SDLS sidecar (decision D12 in EagleGate/DECISIONS.md).
 *
 * CryptoLib's own extension point: built into libcryptolib with
 *   cmake -DKEY_CUSTOM=ON -DKEY_CUSTOM_PATH=<this folder>
 * and chosen at run time with Crypto_Config_CryptoLib(KEY_TYPE_CUSTOM, ...).
 *
 * This file performs NO cryptography and decides nothing about keys. It is a
 * key ring (the same crypto_key_t array CryptoLib's internal interface uses)
 * that starts EMPTY instead of holding CryptoLib's published test keys. The
 * sidecar fills it from its Docker secret through eg_custom_key_set() (via the
 * shim, eg_cryptolib.c); CryptoLib reads it through get_key() and itself
 * refuses keys that are not KEY_ACTIVE or have the wrong length.
 *
 * Not thread safe, like the rest of CryptoLib: the sidecar serializes every
 * call (CryptoLibEngine.lock), including a reload while frames are processed.
 */
#define _DEFAULT_SOURCE /* explicit_bzero */
#include <string.h>

#include "key_interface.h"

static crypto_key_t       key_ring[NUM_KEYS];
static KeyInterfaceStruct key_if_struct;

static crypto_key_t *get_key(uint32_t key_id)
{
    return key_id < NUM_KEYS ? &key_ring[key_id] : NULL;
}

/* Crypto_Init calls this. The ring is filled by the sidecar (before or after
 * Crypto_Init), so there is nothing to do here: in particular no built-in keys */
static int32_t key_init(void)
{
    return CRYPTO_LIB_SUCCESS;
}

/* Crypto_Shutdown: wipe every key (explicit_bzero is never optimised away) */
static int32_t key_shutdown(void)
{
    explicit_bzero(key_ring, sizeof(key_ring));
    return CRYPTO_LIB_SUCCESS;
}

KeyInterface get_key_interface_custom(void)
{
    key_if_struct.get_key      = get_key;
    key_if_struct.key_init     = key_init;
    key_if_struct.key_shutdown = key_shutdown;
    return &key_if_struct;
}

/* ---- for the sidecar (through eg_cryptolib.c) ---------------------------- */

/* Wipe the whole ring: every key id becomes empty (length 0, PREACTIVE) */
int32_t eg_custom_key_clear(void)
{
    explicit_bzero(key_ring, sizeof(key_ring));
    return CRYPTO_LIB_SUCCESS;
}

/* Put one key in the ring. state is CryptoLib's KEY_PREACTIVE .. KEY_CORRUPTED.
 * Returns CRYPTO_LIB_ERR_KEY_ID_ERROR for a bad id, CRYPTO_LIB_ERR_KEY_LENGTH_ERROR
 * for a bad length, CRYPTO_LIB_ERR_KEY_STATE_INVALID for a bad state (the ring
 * entry is left wiped then). */
int32_t eg_custom_key_set(uint32_t key_id, const uint8_t *value, uint32_t key_len, uint8_t key_state)
{
    if (key_id >= NUM_KEYS)
        return CRYPTO_LIB_ERR_KEY_ID_ERROR;
    crypto_key_t *key = &key_ring[key_id];
    explicit_bzero(key, sizeof(*key));
    if (value == NULL || key_len == 0 || key_len > KEY_SIZE)
        return CRYPTO_LIB_ERR_KEY_LENGTH_ERROR;
    if (key_state > KEY_CORRUPTED)
        return CRYPTO_LIB_ERR_KEY_STATE_INVALID;
    memcpy(key->value, value, key_len);
    key->key_len   = key_len;
    key->key_state = key_state & 0x0F;
    return CRYPTO_LIB_SUCCESS;
}
