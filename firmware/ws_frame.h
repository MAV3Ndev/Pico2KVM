#pragma once

/* Pure WebSocket frame parser, shared between the firmware (ws_client.c)
 * and the host-side test (test/ws_frame_test.c). No lwIP dependency. */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#define WS_FRAME_MAX_PAYLOAD 1024u

typedef struct {
  bool fin;
  uint8_t opcode;
  bool masked;
  /* true when payload_len exceeds WS_FRAME_MAX_PAYLOAD: only the header was
   * consumed; the caller must skip payload_len bytes of stream data. */
  bool too_big;
  uint64_t payload_len;
  const uint8_t *payload; /* NULL unless the whole payload is present */
  uint8_t mask[4];
} ws_frame_t;

/* Parse one frame at the head of buf.
 * Returns >0: bytes consumed (header+payload normally; header only when
 *             out->too_big is set).
 * Returns  0: more input bytes are needed. */
static int ws_frame_parse(const uint8_t *buf, size_t len, ws_frame_t *out) {
  if (!buf || !out || len < 2) return 0;
  memset(out, 0, sizeof *out);
  out->fin = (buf[0] & 0x80) != 0;
  out->opcode = buf[0] & 0x0f;
  out->masked = (buf[1] & 0x80) != 0;
  uint64_t plen = buf[1] & 0x7f;
  size_t hlen = 2;
  if (plen == 126) {
    if (len < 4) return 0;
    plen = ((uint64_t)buf[2] << 8) | buf[3];
    hlen = 4;
  } else if (plen == 127) {
    if (len < 10) return 0;
    plen = 0;
    for (int i = 0; i < 8; i++) plen = (plen << 8) | buf[2 + i];
    hlen = 10;
  }
  if (out->masked) {
    if (len < hlen + 4) return 0;
    memcpy(out->mask, buf + hlen, 4);
    hlen += 4;
  }
  out->payload_len = plen;
  if (plen > WS_FRAME_MAX_PAYLOAD) {
    out->too_big = true;
    return (int)hlen;
  }
  if (len < hlen + plen) return 0;
  out->payload = buf + hlen;
  return (int)(hlen + plen);
}
