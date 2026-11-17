/*
 * eg_cryptolib.c - a flat C interface over NASA CryptoLib for the EagleGate
 * SDLS sidecar (Python ctypes).
 *
 * This file performs NO cryptography. Every check, decryption and key lookup
 * is CryptoLib's own (Crypto_TM_ProcessSecurity, key_if->get_key). It exists
 * because CryptoLib's structs (SecurityAssociation_t, TM_t, the managed
 * parameters) are packed bitfields whose layout ctypes cannot mirror safely:
 * here the C compiler lays them out from CryptoLib's own headers.
 *
 * Not thread safe (CryptoLib keeps global state): the caller serializes calls.
 *
 * Built against CryptoLib with -DKEY_INTERNAL=ON -DKEY_CUSTOM=ON
 * (KEY_CUSTOM_PATH=key_custom/) -DSA_INTERNAL=ON -DMC_DISABLED=ON
 * -DCRYPTO_LIBGCRYPT=ON (see ../Dockerfile).
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "crypto.h"

/* key_custom/eg_key_interface_custom.c, built into libcryptolib */
int32_t eg_custom_key_clear(void);
int32_t eg_custom_key_set(uint32_t key_id, const uint8_t *value, uint32_t key_len, uint8_t key_state);

#define EG_ERR_ARG   (-9001) /* a bad argument from the caller */
#define EG_ERR_SPACE (-9002) /* an output buffer is too small */

/* CryptoLib's version, e.g. 10501 for 1.5.1 */
int eg_cryptolib_version(void)
{
    return CRYPTO_LIB_MAJOR_VERSION * 10000 + CRYPTO_LIB_MINOR_VERSION * 100 + CRYPTO_LIB_REVISION;
}

int eg_num_sa(void) { return NUM_SA; }
int eg_num_keys(void) { return NUM_KEYS; }
int eg_abm_size(void) { return ABM_SIZE; }

/* Step 1: global and TM configuration. Anti-replay is OFF on purpose: CryptoLib
 * would save the SA (ARSN/IV) after every frame; EagleGate does anti-replay
 * itself, so each call here stays a pure check. custom_keys: CryptoLib's
 * custom key interface (keys from the sidecar's secret) instead of its
 * internal ring of published test keys. */
int eg_configure(int check_fecf, int custom_keys)
{
    int32_t status = Crypto_Config_CryptoLib(custom_keys ? KEY_TYPE_CUSTOM : KEY_TYPE_INTERNAL, MC_TYPE_DISABLED,
                                             SA_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT, IV_INTERNAL);
    if (status != CRYPTO_LIB_SUCCESS)
        return status;
    return Crypto_Config_TM(CRYPTO_TM_CREATE_FECF_FALSE, TM_IGNORE_ANTI_REPLAY_TRUE,
                            check_fecf ? TM_CHECK_FECF_TRUE : TM_CHECK_FECF_FALSE, 0x3F,
                            SA_INCREMENT_NONTRANSMITTED_IV_FALSE);
}

/* Step 2 (once per virtual channel): the TM managed parameters */
int eg_add_tm_channel(int tfvn, int scid, int vcid, int has_fecf, int max_frame_size, int has_ocf)
{
    if (tfvn < 0 || tfvn > 3 || scid < 0 || scid > 0x3FF || vcid < 0 || vcid > 7 || max_frame_size < 1 ||
        max_frame_size > 0xFFFF)
        return EG_ERR_ARG;
    TMGvcidManagedParameters_t mp;
    memset(&mp, 0, sizeof(mp));
    mp.tfvn           = (uint8_t)tfvn;
    mp.scid           = (uint16_t)scid;
    mp.vcid           = (uint8_t)vcid;
    mp.has_fecf       = has_fecf ? TM_HAS_FECF : TM_NO_FECF;
    mp.max_frame_size = (uint16_t)max_frame_size;
    mp.has_ocf        = has_ocf ? TM_HAS_OCF : TM_NO_OCF;
    mp.set_flag       = 1;
    return Crypto_Config_Add_TM_Gvcid_Managed_Parameters(mp);
}

/* Step 3 */
int eg_init(void) { return Crypto_Init(); }

int eg_shutdown(void) { return Crypto_Shutdown(); }

static SecurityAssociation_t *sa_at(int spi)
{
    SecurityAssociation_t *sa = NULL;
    if (spi < 0 || spi >= NUM_SA || sa_if == NULL)
        return NULL;
    /* The in-memory SA store hands out a pointer into its table even when it
     * also reports a problem with the SA (e.g. no ABM yet), so use the pointer */
    sa_if->sa_get_from_spi((uint16_t)spi, &sa);
    return sa;
}

/* Step 4: switch off every SA CryptoLib's built-in table starts with, so only
 * the SAs the sidecar's configuration sets up can be used */
int eg_disable_all_sas(void)
{
    for (int spi = 0; spi < NUM_SA; spi++)
    {
        SecurityAssociation_t *sa = sa_at(spi);
        if (sa == NULL)
            return EG_ERR_ARG;
        sa->sa_state = SA_NONE;
    }
    return CRYPTO_LIB_SUCCESS;
}

/* Step 5 (once per SA): its settings, as the spacecraft has them. Lengths in
 * bytes. abm: abm_len bytes of authentication bit mask. */
int eg_set_sa(int spi, int tfvn, int scid, int vcid, int est, int ast, int ecs, int acs, int ekid, int akid,
              int shivf_len, int iv_len, int shsnf_len, int arsn_len, int shplf_len, int stmacf_len,
              const uint8_t *abm, int abm_len)
{
    SecurityAssociation_t *sa = sa_at(spi);
    if (sa == NULL)
        return EG_ERR_ARG;
    if (shivf_len < 0 || shivf_len > iv_len || iv_len > IV_SIZE || shsnf_len < 0 || shsnf_len > arsn_len ||
        arsn_len > ARSN_SIZE || shplf_len < 0 || shplf_len > 2 || stmacf_len < 0 || stmacf_len > MAC_SIZE ||
        abm_len < 0 || abm_len > ABM_SIZE || (abm_len > 0 && abm == NULL) || ekid < 0 || ekid >= NUM_KEYS ||
        akid < 0 || akid >= NUM_KEYS)
        return EG_ERR_ARG;
    sa->spi             = (uint16_t)spi;
    sa->sa_state        = SA_OPERATIONAL;
    sa->gvcid_blk.tfvn  = (uint8_t)tfvn;
    sa->gvcid_blk.scid  = (uint16_t)scid;
    sa->gvcid_blk.vcid  = (uint8_t)vcid;
    sa->gvcid_blk.mapid = 0;
    sa->est             = est ? 1 : 0;
    sa->ast             = ast ? 1 : 0;
    sa->ecs             = (uint8_t)ecs;
    sa->ecs_len         = ecs ? 1 : 0;
    sa->acs             = (uint8_t)acs;
    sa->acs_len         = acs ? 1 : 0;
    sa->ekid            = (uint16_t)ekid;
    sa->akid            = (uint16_t)akid;
    sa->shivf_len       = (uint8_t)shivf_len;
    sa->iv_len          = (uint8_t)iv_len;
    sa->shsnf_len       = (uint8_t)shsnf_len;
    sa->arsn_len        = (uint8_t)arsn_len;
    sa->shplf_len       = (uint8_t)shplf_len;
    sa->stmacf_len      = (uint8_t)stmacf_len;
    memset(sa->iv, 0, sizeof(sa->iv));
    memset(sa->arsn, 0, sizeof(sa->arsn));
    memset(sa->abm, 0, sizeof(sa->abm));
    if (abm_len > 0)
        memcpy(sa->abm, abm, (size_t)abm_len);
    sa->abm_len = (uint16_t)abm_len;
    return CRYPTO_LIB_SUCCESS;
}

/* Read back what CryptoLib holds for an SA (to report it, never to use it):
 * out[0..15] = state, tfvn, scid, vcid, est, ast, ecs, acs, ekid, akid,
 *              shivf_len, iv_len, shsnf_len, arsn_len, shplf_len, stmacf_len
 * abm_out receives up to abm_cap bytes of the mask; *abm_len its length. */
int eg_get_sa(int spi, int32_t *out, uint8_t *abm_out, int abm_cap, int *abm_len)
{
    SecurityAssociation_t *sa = sa_at(spi);
    if (sa == NULL || out == NULL || abm_len == NULL)
        return EG_ERR_ARG;
    out[0]  = sa->sa_state;
    out[1]  = sa->gvcid_blk.tfvn;
    out[2]  = sa->gvcid_blk.scid;
    out[3]  = sa->gvcid_blk.vcid;
    out[4]  = sa->est;
    out[5]  = sa->ast;
    out[6]  = sa->ecs;
    out[7]  = sa->acs;
    out[8]  = sa->ekid;
    out[9]  = sa->akid;
    out[10] = sa->shivf_len;
    out[11] = sa->iv_len;
    out[12] = sa->shsnf_len;
    out[13] = sa->arsn_len;
    out[14] = sa->shplf_len;
    out[15] = sa->stmacf_len;
    *abm_len = sa->abm_len;
    if (abm_out != NULL)
    {
        if (abm_cap < sa->abm_len)
            return EG_ERR_SPACE;
        memcpy(abm_out, sa->abm, sa->abm_len);
    }
    return CRYPTO_LIB_SUCCESS;
}

/* A key's bytes and state, from CryptoLib's key interface, so the sidecar can
 * fingerprint it. The caller wipes the buffer right after. */
int eg_get_key(int key_id, uint8_t *out, int cap, int *key_len, int *key_state)
{
    if (key_if == NULL || out == NULL || key_len == NULL || key_state == NULL || key_id < 0 || key_id >= NUM_KEYS)
        return EG_ERR_ARG;
    crypto_key_t *key = key_if->get_key((uint32_t)key_id);
    if (key == NULL)
        return CRYPTO_LIB_ERR_KEY_ID_ERROR;
    if ((int)key->key_len > cap || key->key_len > KEY_SIZE)
        return EG_ERR_SPACE;
    memcpy(out, key->value, key->key_len);
    *key_len   = (int)key->key_len;
    *key_state = key->key_state;
    return CRYPTO_LIB_SUCCESS;
}

/* Verify/decrypt one TM frame with CryptoLib. On success the data field
 * (plaintext, padding removed by CryptoLib) is copied to pdu_out. *spi gets the
 * frame's SPI whenever CryptoLib read it (-1 otherwise). */
int eg_tm_process(const uint8_t *frame, int frame_len, uint8_t *pdu_out, int pdu_cap, int *pdu_len, int *spi)
{
    if (frame == NULL || pdu_out == NULL || pdu_len == NULL || spi == NULL || frame_len <= 0 || frame_len > 0xFFFF)
        return EG_ERR_ARG;
    *pdu_len = 0;
    *spi     = -1;
    /* CryptoLib takes a non-const buffer: give it a copy */
    uint8_t *copy = (uint8_t *)malloc((size_t)frame_len);
    TM_t    *tm   = (TM_t *)calloc(1, sizeof(TM_t));
    if (copy == NULL || tm == NULL)
    {
        free(copy);
        free(tm);
        return CRYPTO_LIB_ERROR;
    }
    memcpy(copy, frame, (size_t)frame_len);
    tm->tm_sec_header.spi = 0xFFFF;
    uint16_t length       = 0;
    int32_t  status       = Crypto_TM_ProcessSecurity(copy, (uint16_t)frame_len, tm, &length);
    if (tm->tm_sec_header.spi != 0xFFFF)
        *spi = tm->tm_sec_header.spi;
    if (status == CRYPTO_LIB_SUCCESS)
    {
        if (tm->tm_pdu_len > sizeof(tm->tm_pdu) || (int)tm->tm_pdu_len > pdu_cap)
            status = EG_ERR_SPACE;
        else
        {
            memcpy(pdu_out, tm->tm_pdu, tm->tm_pdu_len);
            *pdu_len = tm->tm_pdu_len;
        }
    }
    memset(tm, 0, sizeof(TM_t)); /* plaintext */
    free(tm);
    free(copy);
    return status;
}

/* The custom key ring (custom_keys only). The caller wipes its own copy. */
int eg_key_clear(void) { return eg_custom_key_clear(); }

int eg_key_set(int key_id, const uint8_t *value, int key_len, int key_state)
{
    if (key_id < 0 || key_len < 0 || key_state < 0 || key_state > 0xFF)
        return EG_ERR_ARG;
    return eg_custom_key_set((uint32_t)key_id, value, (uint32_t)key_len, (uint8_t)key_state);
}

/* The key length CryptoLib expects for a cipher / MAC suite (CryptoLib's own
 * table), or a negative value when it does not know the suite */
int eg_ecs_keylen(int ecs) { return Crypto_Get_ECS_Algo_Keylen((uint8_t)ecs); }
int eg_acs_keylen(int acs) { return Crypto_Get_ACS_Algo_Keylen((uint8_t)acs); }

const char *eg_status_name(int status)
{
    if (status == EG_ERR_ARG)
        return "EG_ERR_ARG";
    if (status == EG_ERR_SPACE)
        return "EG_ERR_SPACE";
    return Crypto_Get_Error_Code_Enum_String(status);
}
