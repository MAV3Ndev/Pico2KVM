#include "pico/stdlib.h"
#include "pico/cyw43_arch.h"
#include "hardware/watchdog.h"
#include "bsp/board.h"
#include "tusb.h"
#include "cyw43.h"
#include "config.h"
#include "ws_client.h"
#include <string.h>
#include <stdbool.h>
#include <stdio.h>

#define WIFI_RETRY_MS 10000
#define LINK_CHECK_MS 1000
#define LED_BLINK_MS 500

int main(void) {
  board_init();
  tud_init(0);
  stdio_init_all();

  watchdog_enable(8000, 1);

  bool wifi_ok = cyw43_arch_init() == 0;
  if (wifi_ok) {
    cyw43_arch_enable_sta_mode();
    ws_client_init();
  } else {
    printf("cyw43 init failed\n");
  }

  uint32_t last_link_check = 0;
  uint32_t last_connect_try = 0;
  uint32_t last_led_toggle = 0;
  bool led = false;

  while (true) {
    tud_task();
    if (wifi_ok) ws_client_poll();

    uint8_t modifier, keys[6];
    while (tud_hid_ready() && ws_client_pop_report(&modifier, keys))
      tud_hid_keyboard_report(0, modifier, keys);

    uint32_t now = to_ms_since_boot(get_absolute_time());
    bool wifi_up = false;
    if (wifi_ok) {
      wifi_up =
          cyw43_tcpip_link_status(&cyw43_state, CYW43_ITF_STA) == CYW43_LINK_UP;
      if ((int32_t)(now - last_link_check) >= LINK_CHECK_MS) {
        last_link_check = now;
        if (!wifi_up && (int32_t)(now - last_connect_try) >= WIFI_RETRY_MS) {
          last_connect_try = now;
          cyw43_arch_lwip_begin();
          cyw43_arch_wifi_connect_async(PICO2KVM_WIFI_SSID,
                                        PICO2KVM_WIFI_PASSWORD,
                                        CYW43_AUTH_WPA2_AES_PSK);
          cyw43_arch_lwip_end();
        }
      }
    }

    bool ws_up = ws_client_connected();
    if (!wifi_up) {
      led = false;
    } else if (ws_up) {
      led = true;
    } else if ((int32_t)(now - last_led_toggle) >= LED_BLINK_MS) {
      last_led_toggle = now;
      led = !led;
    }
    if (wifi_ok) cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, led);

    watchdog_update();
    sleep_ms(1);
  }
}

uint16_t tud_hid_get_report_cb(uint8_t instance, uint8_t report_id,
                               hid_report_type_t report_type, uint8_t *buffer,
                               uint16_t reqlen) {
  return 0;
}

void tud_hid_set_report_cb(uint8_t instance, uint8_t report_id,
                           hid_report_type_t report_type, uint8_t const *buffer,
                           uint16_t bufsize) {}
