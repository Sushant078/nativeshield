#ifndef SHIELD_RASP_H
#define SHIELD_RASP_H
#include <stdint.h>

/*
 * Native runtime self-protection probes for NativeShield.
 *
 * Design notes:
 *  - Probes inspect process/device state. The Frida-server probe also makes a short
 *    loopback connection to the two default control ports; it does not contact the
 *    internet or modify application data.
 *  - Detection categories are returned as a bitmask so the caller (Java Rasp layer)
 *    can apply per-category policy (off / report / enforce).
 *  - The op-bound key gate (rasp_block_key) is deliberately limited to the two
 *    lowest-false-positive signals, Frida and an attached debugger, because it runs
 *    before the app exists and a false positive there permanently bricks launch.
 */

#define RASP_FRIDA     0x01u
#define RASP_DEBUGGER  0x02u
#define RASP_ROOT      0x04u
#define RASP_EMULATOR  0x08u

/* Run every probe; return the OR of the RASP_* flags that fired. */
uint32_t rasp_scan(void);

/* Individual probes (1 = detected, 0 = clean). */
int rasp_frida_present(void);
int rasp_debugger_present(void);
int rasp_root_present(void);
int rasp_emulator_present(void);

/*
 * Op-bound gate for the key-derivation path. Returns 1 when the running process
 * must be denied key material, honoring the baked-in enforcement config
 * (RASP_CRYPTO_GATE + per-category enforce actions for Frida / debugger).
 */
int rasp_block_key(void);

#endif
