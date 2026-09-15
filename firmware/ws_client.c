/* WebSocket-over-TLS client to the Pico2KVM Cloudflare Worker relay.
 *
 * Runs on the lwIP callback (async_context) side for RX, and from the
 * main loop (via ws_client_poll, bracketed by cyw43_arch_lwip_begin/end)
 * for connect/timers/keepalive. Received HID reports go into a single
 * producer / single consumer ring consumed by the main loop.
 */

#include "ws_client.h"
#include "ws_frame.h"
#include "e2e.h"
#include "config.h"

#include "pico/cyw43_arch.h"
#include "pico/rand.h"
#include "cyw43.h"

#include "lwip/altcp.h"
#include "lwip/altcp_tcp.h"
#include "lwip/altcp_tls.h"
#include "lwip/dns.h"
#include "lwip/pbuf.h"
#include "mbedtls/ssl.h"

#include <string.h>
#include <stdio.h>
#include <time.h>

/* mbedtls is built with MBEDTLS_HAVE_TIME_DATE, so certificate
 * notBefore/notAfter are checked against time(). The Pico has no RTC:
 * report the firmware build epoch plus uptime, which always sits inside
 * the CA's and server cert's validity window. */
time_t time(time_t *t) {
  time_t v = (time_t)PICO2KVM_BUILD_EPOCH +
             (time_t)(time_us_64() / 1000000);
  if (t) *t = v;
  return v;
}

mbedtls_ms_time_t mbedtls_ms_time(void) {
  return (mbedtls_ms_time_t)(time_us_64() / 1000);
}

#define WS_PEND_CAP 2048
#define WS_HTTP_HDR_MAX 2048
#define WS_RING_CAP 16
#define WS_PING_MS 20000
#define WS_RX_TIMEOUT_MS 60000
#define WS_HS_TIMEOUT_MS 15000
#define WS_BACKOFF_INIT_MS 2000
#define WS_BACKOFF_MAX_MS 30000

typedef enum {
  WS_IDLE,
  WS_DNS,
  WS_CONNECTING,
  WS_HANDSHAKE,
  WS_OPEN,
  WS_BACKOFF,
} ws_state_t;

static ws_state_t ws_state = WS_IDLE;
static struct altcp_pcb *ws_pcb;
static struct altcp_tls_config *ws_tls_config;
static ip_addr_t ws_ip;

static uint8_t ws_pend[WS_PEND_CAP];
static size_t ws_pend_len;
static uint64_t ws_skip_len; /* remaining bytes of an oversized payload */

static uint32_t ws_backoff_ms;
static uint32_t ws_next_try_ms;
static uint32_t ws_last_rx_ms;
static uint32_t ws_last_ping_ms;
static uint32_t ws_hs_start_ms;
static bool ws_was_open;

static struct {
  uint8_t modifier;
  uint8_t keys[6];
} ws_ring[WS_RING_CAP];
static volatile uint8_t ws_ring_head, ws_ring_tail;

static uint32_t prng_state;
static uint32_t prng_next(void) {
  uint32_t x = prng_state;
  x ^= x << 13;
  x ^= x >> 17;
  x ^= x << 5;
  prng_state = x;
  return x;
}

static uint32_t now_ms(void) {
  return to_ms_since_boot(get_absolute_time());
}

static bool wifi_link_up(void) {
  return cyw43_tcpip_link_status(&cyw43_state, CYW43_ITF_STA) == CYW43_LINK_UP;
}

static void ring_push(uint8_t modifier, const uint8_t keys[6]) {
  uint8_t next = (uint8_t)((ws_ring_head + 1) % WS_RING_CAP);
  if (next == ws_ring_tail) return; /* full: drop */
  ws_ring[ws_ring_head].modifier = modifier;
  memcpy(ws_ring[ws_ring_head].keys, keys, 6);
  __asm volatile("dmb" ::: "memory");
  ws_ring_head = next;
}

static void ring_push_release_all(void) {
  static const uint8_t zeros[6];
  ring_push(0, zeros);
}

bool ws_client_pop_report(uint8_t *modifier, uint8_t keys[6]) {
  if (ws_ring_tail == ws_ring_head) return false;
  *modifier = ws_ring[ws_ring_tail].modifier;
  memcpy(keys, ws_ring[ws_ring_tail].keys, 6);
  __asm volatile("dmb" ::: "memory");
  ws_ring_tail = (uint8_t)((ws_ring_tail + 1) % WS_RING_CAP);
  return true;
}

bool ws_client_connected(void) {
  return ws_state == WS_OPEN;
}

static bool ws_pcb_aborted; /* set when we altcp_abort() our own pcb */

static void ws_pend_consume(size_t n) {
  if (n > ws_pend_len) {
    ws_pend_len = 0;
    return;
  }
  memmove(ws_pend, ws_pend + n, ws_pend_len - n);
  ws_pend_len -= n;
}

/* --- send path (client frames are always masked) --- */

static void ws_send_frame(uint8_t opcode, const uint8_t *payload, size_t len) {
  if (!ws_pcb || len > WS_FRAME_MAX_PAYLOAD) return;
  uint8_t hdr[8];
  size_t hlen;
  hdr[0] = 0x80 | opcode;
  if (len < 126) {
    hdr[1] = (uint8_t)len;
    hlen = 2;
  } else {
    hdr[1] = 126;
    hdr[2] = (uint8_t)(len >> 8);
    hdr[3] = (uint8_t)len;
    hlen = 4;
  }
  hdr[1] |= 0x80; /* client frames are masked */
  uint8_t mask[4];
  for (int i = 0; i < 4; i++) mask[i] = (uint8_t)prng_next();
  memcpy(hdr + hlen, mask, 4);
  hlen += 4;
  uint8_t buf[8 + WS_FRAME_MAX_PAYLOAD];
  memcpy(buf, hdr, hlen);
  for (size_t i = 0; i < len; i++) buf[hlen + i] = payload[i] ^ mask[i & 3];
  err_t e = altcp_write(ws_pcb, buf, (u16_t)(hlen + len), TCP_WRITE_FLAG_COPY);
  if (e == ERR_OK)
    altcp_output(ws_pcb);
  else
    printf("ws: send frame dropped (err %d)\n", e);
}

static void ws_send_hello(void) {
  char buf[512];
  size_t n = e2e_take_hello(buf, sizeof buf);
  if (n) ws_send_frame(0x1, (const uint8_t *)buf, n);
}

/* --- teardown / reconnect --- */

static void ws_close_pcb(void) {
  if (ws_pcb) {
    altcp_abort(ws_pcb);
    ws_pcb = NULL;
    ws_pcb_aborted = true;
  }
}

static void ws_to_backoff(void) {
  ws_close_pcb();
  ws_state = WS_BACKOFF;
  ws_pend_len = 0;
  ws_skip_len = 0;
  if (ws_was_open || ws_backoff_ms == 0) ws_backoff_ms = WS_BACKOFF_INIT_MS;
  ws_next_try_ms = now_ms() + ws_backoff_ms;
  if (ws_backoff_ms < WS_BACKOFF_MAX_MS) ws_backoff_ms *= 2;
  ws_was_open = false;
  e2e_reset(); /* new handshake required after reconnect */
  ring_push_release_all(); /* don't leave keys stuck down on the PC */
  printf("ws: backoff %ums\n", ws_backoff_ms);
}

/* --- connect --- */

static err_t ws_on_connected(void *arg, struct altcp_pcb *pcb, err_t err);
static void ws_on_dns(const char *name, const ip_addr_t *ip, void *arg);
static err_t ws_on_recv(void *arg, struct altcp_pcb *pcb, struct pbuf *p, err_t err);
static err_t ws_on_sent(void *arg, struct altcp_pcb *pcb, u16_t len);
static err_t ws_on_poll(void *arg, struct altcp_pcb *pcb);
static void ws_on_err(void *arg, err_t err);

static void ws_start_connect(const ip_addr_t *ip) {
  struct altcp_pcb *inner = altcp_tcp_new_ip_type(IPADDR_TYPE_V4);
  if (!inner) {
    ws_to_backoff();
    return;
  }
  struct altcp_pcb *pcb = altcp_tls_wrap(ws_tls_config, inner);
  if (!pcb) {
    altcp_abort(inner);
    ws_to_backoff();
    return;
  }
  /* SNI is required by Cloudflare. */
  mbedtls_ssl_set_hostname(altcp_tls_context(pcb), PICO2KVM_SERVER_HOST);
  altcp_arg(pcb, NULL);
  altcp_recv(pcb, ws_on_recv);
  altcp_sent(pcb, ws_on_sent);
  altcp_poll(pcb, ws_on_poll, 4);
  altcp_err(pcb, ws_on_err);
  ws_pcb = pcb;
  ws_pcb_aborted = false;
  ws_state = WS_CONNECTING;
  err_t e = altcp_connect(pcb, ip, PICO2KVM_SERVER_PORT, ws_on_connected);
  if (e != ERR_OK) {
    printf("ws: connect err %d\n", e);
    ws_to_backoff();
  }
}

static void ws_start_dns(void) {
  ws_state = WS_DNS;
  err_t e = dns_gethostbyname(PICO2KVM_SERVER_HOST, &ws_ip, ws_on_dns, NULL);
  if (e == ERR_OK) {
    ws_start_connect(&ws_ip); /* cached */
  } else if (e != ERR_INPROGRESS) {
    printf("ws: dns err %d\n", e);
    ws_to_backoff();
  }
}

static void ws_on_dns(const char *name, const ip_addr_t *ip, void *arg) {
  (void)name;
  (void)arg;
  if (ws_state != WS_DNS) return;
  if (!ip) {
    printf("ws: dns failed\n");
    ws_to_backoff();
    return;
  }
  ws_ip = *ip;
  ws_start_connect(&ws_ip);
}

/* --- HTTP upgrade --- */

static size_t b64_encode(const uint8_t *in, size_t n, char *out) {
  static const char T[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  size_t o = 0;
  for (size_t i = 0; i < n; i += 3) {
    uint32_t v = (uint32_t)in[i] << 16;
    int rem = (int)(n - i);
    if (rem > 1) v |= (uint32_t)in[i + 1] << 8;
    if (rem > 2) v |= in[i + 2];
    out[o++] = T[(v >> 18) & 63];
    out[o++] = T[(v >> 12) & 63];
    out[o++] = rem > 1 ? T[(v >> 6) & 63] : '=';
    out[o++] = rem > 2 ? T[v & 63] : '=';
  }
  out[o] = 0;
  return o;
}

static err_t ws_send_handshake(struct altcp_pcb *pcb) {
  uint8_t key_raw[16];
  for (int i = 0; i < 4; i++) {
    uint32_t r = prng_next();
    memcpy(key_raw + 4 * i, &r, 4);
  }
  char key[25];
  b64_encode(key_raw, 16, key);
  char req[512];
  int n = snprintf(req, sizeof req,
                   "GET /device/%s HTTP/1.1\r\n"
                   "Host: %s\r\n"
                   "Upgrade: websocket\r\n"
                   "Connection: Upgrade\r\n"
                   "Sec-WebSocket-Key: %s\r\n"
                   "Sec-WebSocket-Version: 13\r\n"
                   "Authorization: Bearer %s\r\n"
                   "User-Agent: pico2kvm\r\n\r\n",
                   PICO2KVM_DEVICE_ID, PICO2KVM_SERVER_HOST, key,
                   PICO2KVM_DEVICE_TOKEN);
  if (n <= 0 || n >= (int)sizeof req) return ERR_VAL;
  err_t e = altcp_write(pcb, req, (u16_t)n, TCP_WRITE_FLAG_COPY);
  if (e == ERR_OK) e = altcp_output(pcb);
  return e;
}

static err_t ws_on_connected(void *arg, struct altcp_pcb *pcb, err_t err) {
  (void)arg;
  if (err != ERR_OK) {
    ws_to_backoff();
    return ERR_OK;
  }
  ws_state = WS_HANDSHAKE;
  ws_hs_start_ms = now_ms();
  ws_pend_len = 0;
  ws_skip_len = 0;
  if (ws_send_handshake(pcb) != ERR_OK) {
    printf("ws: handshake send failed\n");
    ws_to_backoff();
  }
  return ERR_OK;
}

/* --- receive path --- */

static void ws_process_stream(void);

static void ws_handle_frame(const ws_frame_t *f) {
  ws_last_rx_ms = now_ms();
  uint8_t *payload = (uint8_t *)f->payload;
  if (f->masked && payload) {
    for (uint64_t i = 0; i < f->payload_len; i++) payload[i] ^= f->mask[i & 3];
  }
  switch (f->opcode) {
  case 0x2: /* binary: only E2E frames are accepted */
    if (f->payload_len >= 1 && payload[0] == 0x02) {
      uint8_t modifier, keys[6];
      if (e2e_decrypt_report(payload, (size_t)f->payload_len, &modifier,
                             keys))
        ring_push(modifier, keys);
    }
    /* plaintext 0x01 reports are dropped: downgrade prevention */
    break;
  case 0x1: { /* text: E2E handshake */
    int act = e2e_handle_text(payload, (size_t)f->payload_len);
    if (act == E2E_ACT_HELLO) {
      ws_send_hello(); /* key-req */
    } else if (act == E2E_ACT_READY) {
      /* session key (re)established: send encrypted {"type":"ready"} */
      static const char ready_msg[] = "{\"type\":\"ready\"}";
      uint8_t frame[64];
      size_t n = e2e_encrypt(1, (const uint8_t *)ready_msg,
                             sizeof(ready_msg) - 1, frame, sizeof frame);
      if (n) ws_send_frame(0x2, frame, n);
    }
    break;
  }
  case 0x9: /* ping -> pong */
    ws_send_frame(0xA, payload, (size_t)f->payload_len);
    break;
  case 0xA: /* pong: last_rx already refreshed */
    break;
  case 0x8: /* close */
    ws_send_frame(0x8, payload, (size_t)f->payload_len);
    if (ws_pcb && altcp_close(ws_pcb) == ERR_OK)
      ws_pcb = NULL; /* lwIP completes the close handshake itself */
    ws_to_backoff();
    break;
  default:
    break;
  }
}

static void ws_process_stream(void) {
  while (ws_pend_len > 0) {
    if (ws_skip_len > 0) {
      size_t n = ws_skip_len < ws_pend_len ? ws_pend_len : (size_t)ws_skip_len;
      ws_pend_consume(n);
      ws_skip_len -= n;
      continue;
    }
    ws_frame_t f;
    int used = ws_frame_parse(ws_pend, ws_pend_len, &f);
    if (used == 0) break;
    if (f.too_big) {
      ws_pend_consume((size_t)used);
      ws_skip_len = f.payload_len;
      continue;
    }
    /* f.payload points into ws_pend: handle before consuming. */
    if (ws_state == WS_OPEN) ws_handle_frame(&f);
    ws_pend_consume((size_t)used);
  }
}

static void ws_handshake_input(void) {
  /* find end of HTTP header */
  size_t end = 0;
  for (size_t i = 0; i + 3 < ws_pend_len; i++) {
    if (ws_pend[i] == '\r' && ws_pend[i + 1] == '\n' && ws_pend[i + 2] == '\r' &&
        ws_pend[i + 3] == '\n') {
      end = i + 4;
      break;
    }
  }
  if (end == 0) {
    if (ws_pend_len >= WS_HTTP_HDR_MAX) {
      printf("ws: http header too large\n");
      ws_to_backoff();
    }
    return;
  }
  bool ok = ws_pend_len >= 12 && memcmp(ws_pend, "HTTP/1.1 101", 12) == 0;
  if (!ok) {
    printf("ws: upgrade rejected: %.40s\n", ws_pend);
    ws_pend_len = 0;
    ws_to_backoff();
    return;
  }
  ws_pend_consume(end);
  ws_state = WS_OPEN;
  ws_was_open = true;
  ws_backoff_ms = WS_BACKOFF_INIT_MS;
  ws_last_rx_ms = ws_last_ping_ms = now_ms();
  printf("ws: open\n");
  /* No unsolicited hello: it must be signed over the browser's nonce, so
   * it can only be built in response to a key-req. */
  ws_process_stream(); /* bytes after \r\n\r\n are already frames */
}

static err_t ws_on_recv(void *arg, struct altcp_pcb *pcb, struct pbuf *p, err_t err) {
  (void)arg;
  if (err != ERR_OK || !p) {
    if (p) pbuf_free(p);
    ws_to_backoff();
    return ws_pcb_aborted ? ERR_ABRT : ERR_OK;
  }
  for (struct pbuf *q = p; q; q = q->next) {
    size_t off = 0;
    while (off < q->len) {
      size_t space = WS_PEND_CAP - ws_pend_len;
      size_t n = q->len - off;
      if (n > space) n = space;
      if (n == 0) {
        /* pend full with no parseable frame: desync, drop and resync */
        ws_pend_len = 0;
        ws_skip_len = 0;
        break;
      }
      memcpy(ws_pend + ws_pend_len, (const uint8_t *)q->payload + off, n);
      ws_pend_len += n;
      off += n;
      if (ws_state == WS_OPEN)
        ws_process_stream();
      else if (ws_state == WS_HANDSHAKE)
        ws_handshake_input();
      else
        ws_pend_len = 0;
      if (ws_state == WS_BACKOFF) {
        pbuf_free(p);
        if (ws_pcb_aborted) return ERR_ABRT; /* we aborted pcb: must not touch it */
        altcp_recved(pcb, p->tot_len);
        return ERR_OK;
      }
    }
  }
  altcp_recved(pcb, p->tot_len);
  pbuf_free(p);
  return ERR_OK;
}

static err_t ws_on_sent(void *arg, struct altcp_pcb *pcb, u16_t len) {
  (void)arg;
  (void)pcb;
  (void)len;
  return ERR_OK;
}

static err_t ws_on_poll(void *arg, struct altcp_pcb *pcb) {
  (void)arg;
  (void)pcb;
  if (ws_state == WS_HANDSHAKE &&
      (int32_t)(now_ms() - ws_hs_start_ms) > WS_HS_TIMEOUT_MS) {
    printf("ws: handshake timeout\n");
    ws_to_backoff();
    return ws_pcb_aborted ? ERR_ABRT : ERR_OK;
  }
  return ERR_OK;
}

static void ws_on_err(void *arg, err_t err) {
  (void)arg;
  printf("ws: err %d\n", err);
  ws_pcb = NULL; /* pcb already freed by lwIP; never call altcp_* on it */
  ws_to_backoff();
}

/* --- public --- */

void ws_client_init(void) {
  prng_state = (uint32_t)get_rand_64();
  if (!prng_state) prng_state = 0x9e3779b9u;
  e2e_init();
  cyw43_arch_lwip_begin();
  /* sizeof includes the trailing NUL: mbedtls only detects PEM when the
   * buffer's last byte is '\0'. */
  ws_tls_config = altcp_tls_create_config_client(
      (const uint8_t *)PICO2KVM_CA_PEM, sizeof(PICO2KVM_CA_PEM));
  cyw43_arch_lwip_end();
  ws_state = WS_IDLE;
  ws_next_try_ms = now_ms();
  ring_push_release_all();
}

void ws_client_poll(void) {
  cyw43_arch_lwip_begin();
  uint32_t now = now_ms();
  if (!wifi_link_up()) {
    if (ws_pcb) ws_to_backoff();
    if (ws_state != WS_BACKOFF) ws_state = WS_IDLE;
    cyw43_arch_lwip_end();
    return;
  }
  switch (ws_state) {
  case WS_IDLE:
    if ((int32_t)(now - ws_next_try_ms) >= 0) ws_start_dns();
    break;
  case WS_BACKOFF:
    if ((int32_t)(now - ws_next_try_ms) >= 0) ws_state = WS_IDLE;
    break;
  case WS_OPEN:
    if ((int32_t)(now - ws_last_rx_ms) > WS_RX_TIMEOUT_MS) {
      printf("ws: rx timeout\n");
      ws_to_backoff();
    } else if ((int32_t)(now - ws_last_ping_ms) > WS_PING_MS) {
      ws_last_ping_ms = now;
      ws_send_frame(0x9, NULL, 0);
    }
    break;
  default:
    break;
  }
  cyw43_arch_lwip_end();
}
