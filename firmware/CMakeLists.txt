cmake_minimum_required(VERSION 3.13)
include(pico_sdk_import.cmake)
project(pico2kvm C CXX ASM)
pico_sdk_init()

# Credentials/tokens are supplied at configure time and written only to the
# generated build tree.  Never commit the generated header.
set(WIFI_SSID "" CACHE STRING "Wi-Fi SSID")
set(WIFI_PASSWORD "" CACHE STRING "Wi-Fi password")
set(DEVICE_TOKEN "" CACHE STRING "Device bearer token")
set(SERVER_HOST "pico2kvm.konekosann.workers.dev" CACHE STRING "KVM server host")
set(SERVER_PORT "443" CACHE STRING "KVM server port")
set(DEVICE_ID "default" CACHE STRING "Device id path segment")
configure_file(${CMAKE_CURRENT_LIST_DIR}/config.h.in
               ${CMAKE_CURRENT_BINARY_DIR}/generated/config.h @ONLY)

# Generate the static device ECDH key (firmware/device_key.h) once. The
# script is idempotent: an existing device_key.h is never overwritten.
find_program(NODE_EXE NAMES node)
if (NOT NODE_EXE)
  message(FATAL_ERROR
    "node was not found in PATH. It is required once to generate "
    "firmware/device_key.h (see firmware/gen_device_key.mjs).")
endif()
execute_process(
  COMMAND ${NODE_EXE} ${CMAKE_CURRENT_LIST_DIR}/gen_device_key.mjs
  WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
  RESULT_VARIABLE gen_key_result)
if (NOT gen_key_result EQUAL 0)
  message(FATAL_ERROR "gen_device_key.mjs failed (${gen_key_result})")
endif()

add_executable(pico2kvm main.c ws_client.c e2e.c usb_descriptors.c)
target_include_directories(pico2kvm PRIVATE ${CMAKE_CURRENT_LIST_DIR}
                                      ${CMAKE_CURRENT_BINARY_DIR}/generated)
target_link_libraries(pico2kvm pico_stdlib tinyusb_device tinyusb_board
                      pico_cyw43_arch_lwip_threadsafe_background
                      pico_lwip_mbedtls pico_mbedtls pico_rand
                      hardware_watchdog)
pico_enable_stdio_uart(pico2kvm 1)
pico_enable_stdio_usb(pico2kvm 0)
pico_add_extra_outputs(pico2kvm)
