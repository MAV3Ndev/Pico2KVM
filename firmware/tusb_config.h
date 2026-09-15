#pragma once
// The Pico SDK's RP2350 USB peripheral is supported by TinyUSB's
// raspberrypi/rp2040 DCD. Keep this value in sync with the SDK family
// configuration (it is also what enables dcd_rp2040.c).
#define CFG_TUSB_MCU OPT_MCU_RP2040
#define CFG_TUSB_OS OPT_OS_PICO
#define CFG_TUD_ENABLED 1
#define CFG_TUD_HID 1
#define CFG_TUD_ENDPOINT0_SIZE 64
#define CFG_TUD_HID_EP_BUFSIZE 16
