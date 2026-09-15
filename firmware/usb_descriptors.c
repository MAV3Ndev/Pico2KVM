#include "tusb.h"
#include <string.h>

// USB HID keyboard report: modifier, reserved byte, and six key usages.
uint8_t const desc_hid_report[] = {
  TUD_HID_REPORT_DESC_KEYBOARD()
};

enum {
  ITF_NUM_HID,
  ITF_NUM_TOTAL
};

#define CONFIG_TOTAL_LEN (TUD_CONFIG_DESC_LEN + TUD_HID_DESC_LEN)
#define EPNUM_HID 0x81

const tusb_desc_device_t desc_device = {
  .bLength = sizeof(tusb_desc_device_t),
  .bDescriptorType = TUSB_DESC_DEVICE,
  .bcdUSB = 0x0200,
  .bDeviceClass = 0,
  .bDeviceSubClass = 0,
  .bDeviceProtocol = 0,
  .bMaxPacketSize0 = CFG_TUD_ENDPOINT0_SIZE,
  .idVendor = 0xCafe,
  .idProduct = 0x4001,
  .bcdDevice = 0x0100,
  .iManufacturer = 1,
  .iProduct = 2,
  .iSerialNumber = 3,
  .bNumConfigurations = 1
};

uint8_t const desc_configuration[] = {
  TUD_CONFIG_DESCRIPTOR(1, ITF_NUM_TOTAL, 0, CONFIG_TOTAL_LEN,
                        TUSB_DESC_CONFIG_ATT_REMOTE_WAKEUP, 100),
  TUD_HID_DESCRIPTOR(ITF_NUM_HID, 4, HID_ITF_PROTOCOL_KEYBOARD,
                     sizeof(desc_hid_report), EPNUM_HID, CFG_TUD_HID_EP_BUFSIZE,
                     10)
};

static char const *string_desc[] = {
  (const char[]){0x09, 0x04},
  "Pico2KVM",
  "Remote HID Keyboard",
  "0001",
  "Keyboard",
};

static uint16_t _desc_str[32];

uint8_t const *tud_descriptor_device_cb(void) {
  return (uint8_t const *)&desc_device;
}

uint8_t const *tud_descriptor_configuration_cb(uint8_t index) {
  (void) index;
  return desc_configuration;
}

uint8_t const *tud_hid_descriptor_report_cb(uint8_t instance) {
  (void) instance;
  return desc_hid_report;
}

uint16_t const *tud_descriptor_string_cb(uint8_t index, uint16_t langid) {
  (void) langid;
  uint8_t chr_count;
  if (index == 0) {
    memcpy(&_desc_str[1], string_desc[0], 2);
    chr_count = 1;
  } else {
    if (index >= (sizeof(string_desc) / sizeof(string_desc[0]))) return NULL;
    const char *str = string_desc[index];
    chr_count = (uint8_t) strlen(str);
    if (chr_count > 31) chr_count = 31;
    for (uint8_t i = 0; i < chr_count; i++) _desc_str[1 + i] = str[i];
  }
  _desc_str[0] = (uint16_t)((TUSB_DESC_STRING << 8) | (2 * chr_count + 2));
  return _desc_str;
}
