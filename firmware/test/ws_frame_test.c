/* Host-side test for the ws_frame_parse() stream parser.
 * Build: cc -I.. -o ws_frame_test ws_frame_test.c   (from firmware/test) */

#include "../ws_frame.h"
#include <stdio.h>

static int failures;
#define CHECK(cond, name)                                              \
  do {                                                                 \
    if (cond) {                                                        \
      printf("PASS %s\n", name);                                       \
    } else {                                                           \
      printf("FAIL %s\n", name);                                       \
      failures++;                                                      \
    }                                                                  \
  } while (0)

int main(void) {
  ws_frame_t f;

  /* 1. plain 2-byte header + 8-byte binary payload (key report) */
  {
    const uint8_t buf[] = {0x82, 0x08, 0x01, 0x02, 0x04, 0, 0, 0, 0, 0};
    int used = ws_frame_parse(buf, sizeof buf, &f);
    CHECK(used == 10 && f.opcode == 0x2 && f.payload_len == 8 &&
              f.payload[0] == 0x01 && f.payload[1] == 0x02,
          "2-byte header binary frame");
  }

  /* 2. 126 extended length */
  {
    uint8_t buf[4 + 130];
    buf[0] = 0x82;
    buf[1] = 126;
    buf[2] = 0;
    buf[3] = 130;
    for (int i = 0; i < 130; i++) buf[4 + i] = (uint8_t)i;
    int used = ws_frame_parse(buf, sizeof buf, &f);
    CHECK(used == 134 && f.payload_len == 130 && f.payload[129] == 129,
          "126 extended length");
  }

  /* 3. split input: partial header then rest, then partial payload */
  {
    const uint8_t buf[] = {0x82, 0x08, 0x01, 0x00, 0x04, 0, 0, 0, 0, 0};
    CHECK(ws_frame_parse(buf, 1, &f) == 0, "split: 1 byte -> need more");
    CHECK(ws_frame_parse(buf, 2, &f) == 0, "split: header only -> need more");
    CHECK(ws_frame_parse(buf, 6, &f) == 0, "split: partial payload -> need more");
    int used = ws_frame_parse(buf, sizeof buf, &f);
    CHECK(used == 10 && f.payload_len == 8 && f.payload[0] == 0x01,
          "split: full frame parses");
  }

  /* 4. masked frame (client->server direction) */
  {
    const uint8_t buf[] = {0x81, 0x83, 0xAA, 0xBB, 0xCC, 0xDD, 'h' ^ 0xAA,
                           'i' ^ 0xBB, '!' ^ 0xCC};
    int used = ws_frame_parse(buf, sizeof buf, &f);
    CHECK(used == 9 && f.masked && f.mask[0] == 0xAA && f.payload_len == 3,
          "masked frame");
  }

  /* 5. oversized payload -> header consumed, too_big set */
  {
    const uint8_t buf[] = {0x82, 126, (2000 >> 8) & 0xff, 2000 & 0xff};
    int used = ws_frame_parse(buf, sizeof buf, &f);
    CHECK(used == 4 && f.too_big && f.payload_len == 2000 && !f.payload,
          "oversize payload -> header only");
  }

  /* 6. 127 64-bit length */
  {
    const uint8_t buf[] = {0x82, 127, 0, 0, 0, 0, 0, 0, 0, 5,
                           1,   2,   3, 4, 5};
    int used = ws_frame_parse(buf, sizeof buf, &f);
    CHECK(used == 15 && f.payload_len == 5 && f.payload[4] == 5,
          "127 64-bit length");
  }

  printf(failures ? "%d FAILURES\n" : "ALL PASS\n", failures);
  return failures ? 1 : 0;
}
