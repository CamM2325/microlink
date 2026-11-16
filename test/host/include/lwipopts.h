/* Minimal lwIP options for compiling wireguard-lwip filter code on a host PC. */
#ifndef LWIPOPTS_H
#define LWIPOPTS_H
#define NO_SYS                  1
#define LWIP_IPV4               1
#define LWIP_IPV6               1
#define LWIP_SOCKET             0
#define LWIP_NETCONN            0
#define LWIP_UDP                1
#define LWIP_TCP                0
#define SYS_LIGHTWEIGHT_PROT    0
#define LWIP_NETIF_STATUS_CALLBACK 0
#define LWIP_NETIF_LINK_CALLBACK   0
#endif
