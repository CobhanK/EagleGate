/*
 * eg_test_apply.c - TEST IMAGE ONLY. Lets the sidecar's tests build protected
 * frames with CryptoLib's own Crypto_TM_ApplySecurity (what the spacecraft
 * does), so the tests check CryptoLib against itself, never against crypto
 * written for the tests. Not built into the runtime image: applying security
 * changes the SA's IV/ARSN, which the sidecar must never do.
 */
#include <stdint.h>

#include "crypto.h"

int eg_test_tm_apply(uint8_t *frame, int frame_len)
{
    if (frame == NULL || frame_len <= 0 || frame_len > 0xFFFF)
        return -9001;
    return Crypto_TM_ApplySecurity(frame, (uint16_t)frame_len);
}
