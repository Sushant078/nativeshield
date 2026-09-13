#include "shieldcrypto.h"
#include "shield_secret.h"   /* generated per-build: SHIELD_SHARES, SHIELD_CERT_SHA256, SHIELD_INFO, SHIELD_SHARE_COUNT */
#include <string.h>
#ifndef SHIELD_HOST_TEST
#include "rasp.h"
#endif

/*
 * Reassemble the per-build rootSecret from N XOR shares (no single array holds it),
 * gate on the live signing-cert hash, then derive the content key with HKDF using the
 * live cert hash as salt. The raw rootSecret never leaves this function; only the
 * derived key is returned, and the reconstruction buffer is wiped before return.
 *
 * Returns 0 on success (out_key filled). Returns -1 and leaves out_key zeroed if the
 * live certificate hash does not match the signer this build was packed for.
 */
int shield_derive_key(const uint8_t *live_cert_sha256, uint8_t out_key[32]) {
    memset(out_key, 0, 32);

#ifndef SHIELD_HOST_TEST
    /* Refuse content-key material when an enforced runtime signal is active. */
    if (rasp_block_key()) {
        return -1;
    }
#endif

    /* Gate: refuse unless the running APK is signed by the expected certificate. */
    if (!shield_ct_eq(live_cert_sha256, SHIELD_CERT_SHA256, 32)) {
        return -1;
    }

    uint8_t root[32];
    for (int i = 0; i < 32; i++) {
        uint8_t v = 0;
        for (int s = 0; s < SHIELD_SHARE_COUNT; s++) v ^= SHIELD_SHARES[s][i];
        root[i] = v;
    }

    int rc = shield_hkdf_sha256(root, 32,
                                live_cert_sha256, 32,
                                (const uint8_t *)SHIELD_INFO, sizeof(SHIELD_INFO) - 1,
                                out_key, 32);
    memset(root, 0, sizeof(root));      /* wipe reconstructed secret */
    if (rc != 0) { memset(out_key, 0, 32); return -1; }
    return 0;
}

#ifdef SHIELD_HOST_TEST
#include <stdio.h>
static void hex(const uint8_t *b, int n){ for(int i=0;i<n;i++) printf("%02x", b[i]); printf("\n"); }
int main(void) {
    uint8_t key[32];

    /* Case A: genuine signer (live hash == the one baked in). */
    if (shield_derive_key(SHIELD_CERT_SHA256, key) != 0) { printf("FAIL-GENUINE\n"); return 2; }
    printf("NATIVE_KEY="); hex(key, 32);

    /* Case B: attacker re-signed -> live hash differs by one byte. */
    uint8_t wrong[32]; memcpy(wrong, SHIELD_CERT_SHA256, 32); wrong[0] ^= 0x01;
    int rc = shield_derive_key(wrong, key);
    printf("GATE_WRONG_SIGNER=%s\n", (rc == -1) ? "REFUSED" : "LEAKED");
    return 0;
}
#endif
