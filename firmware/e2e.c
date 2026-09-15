/* Browser<->device end-to-end encryption for Pico2KVM.
 *
 * Protocol:
 *   handshake (plaintext WS text):
 *     browser->device {"type":"key-req","nonce":"<32 hex>"}
 *     device->browser {"type":"hello","fw":"pico2kvm","spub":"<130 hex>",
 *                      "epub":"<130 hex>","sig":"<128 hex r||s>"}
 *       sig = ECDSA-SHA256(static_priv, SHA256(nonce || epub))
 *     browser->device {"type":"key","pub":"<130 hex>"}
 *   data (WS binary): [0x02][seq u32 LE][ciphertext][GCM tag 16]
 *   session key: HKDF-SHA256(ECDH(ephemeral).X-coord,
 *                             salt=SHA256(pairing code) or 32*0 when no
 *                             code is configured, "pico2kvm-e2e-v1")
 *   — HKDF info string kept
 *   for compatibility with already-deployed firmware; forward secrecy:
 *   the
 *   static key only signs, never encrypts.
 *   nonce: [dir][0 x7][seq u32 LE]; dir 0 = browser->device, 1 = reverse.
 *
 * Concurrency: see e2e.h. All functions except e2e_init() run exclusively
 * inside lwIP callbacks (single async_context thread), which is why the
 * ctr_drbg context needs no locking: the main loop never calls into e2e.
 */

#include "e2e.h"
#include "device_key.h"
#include "config.h"

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/sha256.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/gcm.h"
#include "mbedtls/md.h"
#include "mbedtls/platform_util.h"

#include <string.h>
#include <stdio.h>

#define E2E_INFO "pico2kvm-e2e-v1"
#define E2E_INFO_LEN 15
#define E2E_TAG_LEN 16
#define E2E_OVERHEAD (1 + 4 + E2E_TAG_LEN)

/* {"type":"hello","fw":"pico2kvm","spub":"<130>","epub":"<130>","sig":"<128>"} */
#define E2E_HELLO_CAP 480

static mbedtls_entropy_context e2e_entropy;
static mbedtls_ctr_drbg_context e2e_drbg;
static mbedtls_ecp_group e2e_grp;
static mbedtls_mpi e2e_d;        /* static private key: ECDSA only */
static mbedtls_mpi e2e_de;       /* ephemeral ECDH private key */
static mbedtls_ecp_point e2e_qe; /* ephemeral ECDH public point */
static mbedtls_gcm_context e2e_gcm;

/* HKDF salt: all zeros, or SHA256(pairing code) when one is configured.
 * A browser must present the same code to derive the session key. */
static uint8_t e2e_salt[32];

static bool e2e_ok;        /* init succeeded */
static bool e2e_is_ready;  /* session key established */
static bool e2e_have_eph;  /* ephemeral key generated for this handshake */
static char e2e_hello[E2E_HELLO_CAP];
static size_t e2e_hello_len;
static uint32_t e2e_tx_seq[2];
static bool e2e_rx_seen;
static uint32_t e2e_rx_seq_max;

static void make_nonce(uint8_t dir, uint32_t seq, uint8_t nonce[12]) {
  memset(nonce, 0, 12);
  nonce[0] = dir;
  nonce[8] = (uint8_t)seq;
  nonce[9] = (uint8_t)(seq >> 8);
  nonce[10] = (uint8_t)(seq >> 16);
  nonce[11] = (uint8_t)(seq >> 24);
}

static const uint8_t *find_sub(const uint8_t *hay, size_t hlen,
                               const char *needle, size_t nlen) {
  if (nlen > hlen) return NULL;
  for (size_t i = 0; i + nlen <= hlen; i++)
    if (memcmp(hay + i, needle, nlen) == 0) return hay + i;
  return NULL;
}

static int hex_nibble(uint8_t c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static bool hex_decode(const uint8_t *hex, size_t hexlen, uint8_t *out) {
  if (hexlen & 1) return false;
  for (size_t i = 0; i < hexlen / 2; i++) {
    int hi = hex_nibble(hex[2 * i]);
    int lo = hex_nibble(hex[2 * i + 1]);
    if (hi < 0 || lo < 0) return false;
    out[i] = (uint8_t)((hi << 4) | lo);
  }
  return true;
}

static void hex_encode(const uint8_t *in, size_t n, char *out) {
  static const char HEX[] = "0123456789abcdef";
  for (size_t i = 0; i < n; i++) {
    out[2 * i] = HEX[in[i] >> 4];
    out[2 * i + 1] = HEX[in[i] & 15];
  }
}

static void e2e_clear_eph(void) {
  /* mbedtls_mpi_free/ecp_point_free zeroize the key material. */
  mbedtls_mpi_free(&e2e_de);
  mbedtls_mpi_init(&e2e_de);
  mbedtls_ecp_point_free(&e2e_qe);
  mbedtls_ecp_point_init(&e2e_qe);
  e2e_have_eph = false;
}

void e2e_init(void) {
  mbedtls_entropy_init(&e2e_entropy);
  mbedtls_ctr_drbg_init(&e2e_drbg);
  mbedtls_ecp_group_init(&e2e_grp);
  mbedtls_mpi_init(&e2e_d);
  mbedtls_mpi_init(&e2e_de);
  mbedtls_ecp_point_init(&e2e_qe);
  mbedtls_gcm_init(&e2e_gcm);
  e2e_ok = false;
  e2e_is_ready = false;
  e2e_have_eph = false;
  e2e_hello_len = 0;

  if (PICO2KVM_PAIRING_CODE[0]) {
    mbedtls_sha256((const uint8_t *)PICO2KVM_PAIRING_CODE,
                   sizeof(PICO2KVM_PAIRING_CODE) - 1, e2e_salt, 0);
  } else {
    memset(e2e_salt, 0, sizeof e2e_salt);
  }

  int rc = mbedtls_ctr_drbg_seed(&e2e_drbg, mbedtls_entropy_func,
                                 &e2e_entropy, NULL, 0);
  if (!rc) rc = mbedtls_ecp_group_load(&e2e_grp, MBEDTLS_ECP_DP_SECP256R1);
  if (!rc)
    rc = mbedtls_mpi_read_binary(&e2e_d, PICO2KVM_DEV_PRIV,
                                 sizeof(PICO2KVM_DEV_PRIV));
  if (!rc) rc = mbedtls_ecp_check_privkey(&e2e_grp, &e2e_d);
  if (rc) {
    printf("e2e: init failed (%d)\n", rc);
    return;
  }
  e2e_ok = true;
}

/* Build the hello response to a key-req: fresh ephemeral ECDH key plus an
 * ECDSA signature (static key) over SHA256(nonce || epub). Returns 0 on
 * success; the JSON is kept in e2e_hello[] for e2e_take_hello(). */
static int e2e_build_hello(const uint8_t nonce[16]) {
  static const char PRE[] =
      "{\"type\":\"hello\",\"fw\":\"pico2kvm\",\"spub\":\"";
  static const char MID[] = "\",\"epub\":\"";
  static const char SIG[] = "\",\"sig\":\"";
  static const char END[] = "\"}";
  uint8_t epub[65];
  uint8_t sig[64];
  uint8_t digest_in[16 + 65];
  uint8_t hash[32];
  mbedtls_mpi r, s;
  mbedtls_mpi_init(&r);
  mbedtls_mpi_init(&s);
  size_t olen = 0;

  e2e_clear_eph(); /* drop any previous handshake's ephemeral key */
  int rc = mbedtls_ecp_gen_keypair(&e2e_grp, &e2e_de, &e2e_qe,
                                   mbedtls_ctr_drbg_random, &e2e_drbg);
  if (!rc)
    rc = mbedtls_ecp_point_write_binary(&e2e_grp, &e2e_qe,
                                        MBEDTLS_ECP_PF_UNCOMPRESSED, &olen,
                                        epub, sizeof epub);
  if (!rc && olen != 65) rc = -1;
  if (!rc) {
    memcpy(digest_in, nonce, 16);
    memcpy(digest_in + 16, epub, 65);
    rc = mbedtls_sha256(digest_in, sizeof digest_in, hash, 0);
  }
  if (!rc)
    rc = mbedtls_ecdsa_sign(&e2e_grp, &r, &s, &e2e_d, hash, sizeof hash,
                            mbedtls_ctr_drbg_random, &e2e_drbg);
  if (!rc) rc = mbedtls_mpi_write_binary(&r, sig, 32);
  if (!rc) rc = mbedtls_mpi_write_binary(&s, sig + 32, 32);
  mbedtls_mpi_free(&r);
  mbedtls_mpi_free(&s);
  mbedtls_platform_zeroize(digest_in, sizeof digest_in);
  mbedtls_platform_zeroize(hash, sizeof hash);
  if (rc) {
    e2e_clear_eph();
    e2e_hello_len = 0;
    printf("e2e: hello build failed (%d)\n", rc);
    return -1;
  }
  e2e_have_eph = true;

  char *p = e2e_hello;
  memcpy(p, PRE, sizeof(PRE) - 1);
  p += sizeof(PRE) - 1;
  hex_encode(PICO2KVM_DEV_PUB, sizeof(PICO2KVM_DEV_PUB), p);
  p += 2 * sizeof(PICO2KVM_DEV_PUB);
  memcpy(p, MID, sizeof(MID) - 1);
  p += sizeof(MID) - 1;
  hex_encode(epub, sizeof epub, p);
  p += 130;
  memcpy(p, SIG, sizeof(SIG) - 1);
  p += sizeof(SIG) - 1;
  hex_encode(sig, sizeof sig, p);
  p += 128;
  memcpy(p, END, sizeof(END) - 1);
  p += sizeof(END) - 1;
  e2e_hello_len = (size_t)(p - e2e_hello);
  return 0;
}

size_t e2e_take_hello(char *buf, size_t cap) {
  if (!e2e_hello_len || e2e_hello_len + 1 > cap) return 0;
  memcpy(buf, e2e_hello, e2e_hello_len);
  buf[e2e_hello_len] = 0;
  return e2e_hello_len;
}

/* ECDH between our ephemeral private key and the browser's ephemeral
 * public key, then HKDF -> AES-256-GCM. */
static void e2e_establish(const uint8_t peer_pub[65]) {
  mbedtls_ecp_point qp;
  mbedtls_mpi z;
  mbedtls_ecp_point_init(&qp);
  mbedtls_mpi_init(&z);
  uint8_t shared[32];
  uint8_t key[32];

  if (!e2e_have_eph) {
    printf("e2e: key before key-req, ignored\n");
    mbedtls_ecp_point_free(&qp);
    mbedtls_mpi_free(&z);
    return;
  }
  int rc = mbedtls_ecp_point_read_binary(&e2e_grp, &qp, peer_pub, 65);
  /* Reject points not on the curve (invalid-point attack). */
  if (!rc) rc = mbedtls_ecp_check_pubkey(&e2e_grp, &qp);
  if (!rc)
    rc = mbedtls_ecdh_compute_shared(&e2e_grp, &z, &qp, &e2e_de,
                                     mbedtls_ctr_drbg_random, &e2e_drbg);
  if (!rc) rc = mbedtls_mpi_write_binary(&z, shared, sizeof shared);
  if (!rc)
    rc = mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                      e2e_salt, sizeof e2e_salt, shared, sizeof shared,
                      (const uint8_t *)E2E_INFO, E2E_INFO_LEN, key,
                      sizeof key);
  if (!rc)
    rc = mbedtls_gcm_setkey(&e2e_gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
  if (!rc) {
    e2e_tx_seq[0] = e2e_tx_seq[1] = 0;
    e2e_rx_seen = false;
    e2e_rx_seq_max = 0;
    e2e_is_ready = true;
    printf("e2e: session established\n");
  } else {
    printf("e2e: key agreement failed (%d)\n", rc);
  }
  mbedtls_platform_zeroize(shared, sizeof shared);
  mbedtls_platform_zeroize(key, sizeof key);
  mbedtls_ecp_point_free(&qp);
  mbedtls_mpi_free(&z);
}

int e2e_handle_text(const uint8_t *msg, size_t len) {
  if (!e2e_ok || !msg || !len) return E2E_ACT_NONE;
  const uint8_t *p = find_sub(msg, len, "\"pub\":\"", 7);
  if (p) {
    p += 7;
    if ((size_t)(len - (size_t)(p - msg)) < 130) return E2E_ACT_NONE;
    uint8_t pub[65];
    if (!hex_decode(p, 130, pub) || pub[0] != 0x04) return E2E_ACT_NONE;
    e2e_establish(pub);
    return e2e_is_ready ? E2E_ACT_READY : E2E_ACT_NONE;
  }
  if (find_sub(msg, len, "key-req", 7)) {
    uint8_t nonce[16];
    memset(nonce, 0, sizeof nonce);
    const uint8_t *np = find_sub(msg, len, "\"nonce\":\"", 9);
    if (np) {
      np += 9;
      size_t rem = len - (size_t)(np - msg);
      if (rem < 32 || !hex_decode(np, 32, nonce)) {
        printf("e2e: bad key-req nonce\n");
        return E2E_ACT_NONE;
      }
    } else {
      /* Legacy key-req without nonce: sign over a zero nonce. */
      printf("e2e: key-req without nonce\n");
    }
    return e2e_build_hello(nonce) == 0 ? E2E_ACT_HELLO : E2E_ACT_NONE;
  }
  return E2E_ACT_NONE;
}

bool e2e_ready(void) {
  return e2e_is_ready;
}

void e2e_reset(void) {
  e2e_is_ready = false;
  e2e_tx_seq[0] = e2e_tx_seq[1] = 0;
  e2e_rx_seen = false;
  e2e_rx_seq_max = 0;
  e2e_hello_len = 0;
  e2e_clear_eph(); /* destroy the ephemeral private key */
}

size_t e2e_encrypt(uint8_t dir, const uint8_t *pt, size_t ptlen,
                   uint8_t *out, size_t cap) {
  if (!e2e_is_ready || ptlen + E2E_OVERHEAD > cap) return 0;
  dir &= 1;
  uint32_t seq = e2e_tx_seq[dir]++;
  uint8_t nonce[12];
  make_nonce(dir, seq, nonce);
  out[0] = 0x02;
  out[1] = (uint8_t)seq;
  out[2] = (uint8_t)(seq >> 8);
  out[3] = (uint8_t)(seq >> 16);
  out[4] = (uint8_t)(seq >> 24);
  /* GCM encrypt needs no RNG: safe in callback context. */
  int rc = mbedtls_gcm_crypt_and_tag(&e2e_gcm, MBEDTLS_GCM_ENCRYPT, ptlen,
                                     nonce, sizeof nonce, NULL, 0, pt,
                                     out + 5, E2E_TAG_LEN, out + 5 + ptlen);
  if (rc) return 0;
  return 5 + ptlen + E2E_TAG_LEN;
}

int e2e_decrypt_report(const uint8_t *frame, size_t len,
                       uint8_t *modifier, uint8_t keys[6]) {
  if (!e2e_is_ready) return 0;
  /* browser->device plaintext is exactly the 8-byte HID report. */
  if (len != E2E_OVERHEAD + 8 || frame[0] != 0x02) return 0;
  uint32_t seq = (uint32_t)frame[1] | ((uint32_t)frame[2] << 8) |
                 ((uint32_t)frame[3] << 16) | ((uint32_t)frame[4] << 24);
  if (e2e_rx_seen && seq <= e2e_rx_seq_max) return 0; /* replay */
  uint8_t nonce[12];
  make_nonce(0, seq, nonce); /* peer direction: browser->device */
  uint8_t pt[8];
  const size_t ctlen = len - E2E_OVERHEAD;
  /* GCM decrypt needs no RNG: safe in callback context. */
  int rc = mbedtls_gcm_auth_decrypt(&e2e_gcm, ctlen, nonce, sizeof nonce,
                                    NULL, 0, frame + 5 + ctlen, E2E_TAG_LEN,
                                    frame + 5, pt);
  if (rc) return 0; /* tag mismatch */
  if (pt[0] != 0x01) return 0;
  *modifier = pt[1];
  memcpy(keys, pt + 2, 6);
  e2e_rx_seen = true;
  e2e_rx_seq_max = seq;
  return 1;
}
