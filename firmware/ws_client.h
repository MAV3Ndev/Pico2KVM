#pragma once

#include <stdint.h>
#include <stdbool.h>

void ws_client_init(void);
/* Call every main-loop iteration. Manages the connection state machine,
 * reconnect backoff and keepalive pings. lwIP calls are bracketed
 * internally with cyw43_arch_lwip_begin/end. */
void ws_client_poll(void);
bool ws_client_connected(void);
/* Pop one queued HID report (consumer: main loop). Returns false when
 * the ring is empty. */
bool ws_client_pop_report(uint8_t *modifier, uint8_t keys[6]);
