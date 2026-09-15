#pragma once

/* Small, callback-only lwIP profile used by pico_cyw43_arch. */
#define NO_SYS                          1
#define MEM_ALIGNMENT                   4
/* altcp_tls_mbedtls allocates the mbedtls context and its RX/TX record
 * buffers from this heap via mem_malloc(). 16K IN + 2K OUT + handshake
 * state and cert parsing need ~40K during the TLS handshake. */
#define MEM_SIZE                        49152
#define LWIP_RAW                        1
#define LWIP_NETCONN                    0
#define LWIP_SOCKET                     0
#define LWIP_DHCP                       1
#define LWIP_DNS                        1
#define LWIP_ICMP                       1
#define LWIP_UDP                        1
#define LWIP_TCP                        1
#define LWIP_IPV4                       1
#define LWIP_IPV6                       0
#define ETH_PAD_SIZE                    0
#define LWIP_SINGLE_NETIF               1
#define PBUF_POOL_SIZE                  8
#define MEMP_NUM_TCP_SEG                32
#define MEMP_NUM_TCP_PCB                10
#define MEMP_NUM_SYS_TIMEOUT            (LWIP_NUM_SYS_TIMEOUT_INTERNAL + 1)
#define TCP_MSS                         1460
#define TCP_SND_BUF                     (4 * TCP_MSS)
#define TCP_WND                         (8 * TCP_MSS)
#define LWIP_TCP_KEEPALIVE              1
#define LWIP_NETIF_STATUS_CALLBACK      1
#define LWIP_NETIF_LINK_CALLBACK        1
#define LWIP_TIMEVAL_PRIVATE            0
#define LWIP_ALTCP                      1
#define LWIP_ALTCP_TLS                  1
#define LWIP_ALTCP_TLS_MBEDTLS          1
/* The GTS R4 root CA is embedded via PICO2KVM_CA_PEM: require full chain
 * and hostname verification against it. */
#define ALTCP_MBEDTLS_AUTHMODE          MBEDTLS_SSL_VERIFY_REQUIRED
