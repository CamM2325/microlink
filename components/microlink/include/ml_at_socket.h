/**
 * @file ml_at_socket.h
 * @brief AT Socket Bridge — BSD socket API over SIM7600 internal TCP/IP stack
 *
 * Provides socket(), connect(), send(), recv(), sendto(), recvfrom(), close(),
 * select(), getaddrinfo(), setsockopt(), and fcntl() implementations that
 * route through SIM7600 AT commands (AT+NETOPEN/CIPOPEN/CIPSEND/CIPRXGET).
 *
 * MicroLink's coord, DERP, STUN, and net_io code can use these instead of
 * lwIP BSD sockets when running over cellular.
 */

#pragma once

#include "sdkconfig.h"
#include "esp_err.h"
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/socket.h>
#include <netdb.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef CONFIG_ML_ENABLE_CELLULAR

/* ============================================================================
 * Initialization
 * ========================================================================== */

/**
 * Initialize the AT socket bridge.
 * - Sends AT+NETOPEN to activate modem internal TCP/IP stack
 * - Starts URC handler task for async receive notifications
 * Must be called AFTER ml_cellular_init() and network registration.
 *
 * @return ESP_OK on success
 */
esp_err_t ml_at_socket_init(void);

/**
 * Deinitialize the AT socket bridge.
 * - Closes all open sockets
 * - Sends AT+NETCLOSE
 * - Stops URC handler task
 */
void ml_at_socket_deinit(void);

/**
 * Check if AT socket bridge is active and ready.
 */
bool ml_at_socket_is_ready(void);

/**
 * Internal: run one AT command through the bridge's reader so that URCs in
 * the response are processed. The caller must hold the modem UART lock
 * (ml_cellular_uart_lock()) and must have validated @p cmd. Applications
 * use ml_cellular_send_at_cmd() instead.
 *
 * @return Bytes received, or -1 on error / no response
 */
int ml_at_socket_cmd_locked(const char *cmd, char *resp, size_t resp_size, int timeout_ms);

/* ============================================================================
 * BSD Socket API Wrappers
 * ========================================================================== */

/**
 * Create a socket. Returns a virtual FD (ML_AT_SOCK_FD_BASE + link_num,
 * within FD_SETSIZE so FD_SET/FD_ISSET work correctly).
 *
 * @param domain   AF_INET only (AF_INET6 falls back to lwIP)
 * @param type     SOCK_STREAM (TCP) or SOCK_DGRAM (UDP)
 * @param protocol 0 or IPPROTO_TCP or IPPROTO_UDP
 * @return Virtual FD on success, -1 on error (sets errno)
 */
int ml_at_socket(int domain, int type, int protocol);

/**
 * Connect a TCP socket to remote address.
 * Sends AT+CIPOPEN=N,"TCP",IP,port and waits for result.
 *
 * @return 0 on success, -1 on error (sets errno)
 */
int ml_at_connect(int fd, const struct sockaddr *addr, socklen_t addrlen);

/**
 * Send data on a connected socket.
 * Sends AT+CIPSEND=N,len then the data payload.
 * Chunks if data > 1460 bytes.
 *
 * @return Bytes sent, or -1 on error
 */
ssize_t ml_at_send(int fd, const void *buf, size_t len, int flags);

/**
 * Receive data from a connected socket.
 * Uses AT+CIPRXGET=2,N,len to read buffered data.
 *
 * @return Bytes received, or -1 on error, 0 if connection closed
 */
ssize_t ml_at_recv(int fd, void *buf, size_t len, int flags);

/**
 * Send data to a specific destination (UDP).
 * Sends AT+CIPSEND=N,len,"IP",port then the data payload.
 *
 * @return Bytes sent, or -1 on error
 */
ssize_t ml_at_sendto(int fd, const void *buf, size_t len, int flags,
                      const struct sockaddr *dest_addr, socklen_t addrlen);

/**
 * Receive data and get source address (UDP).
 * Uses AT+CIPRXGET=2,N,len. The source address is taken from the
 * +CIPRXGET header when the modem reports one; otherwise 0.0.0.0:0 is
 * returned. Datagram boundaries are NOT preserved: the bridge stores UDP
 * payloads in a byte ring, so back-to-back datagrams may be returned
 * merged. Do not rely on UDP over the AT bridge for framing-sensitive
 * protocols (MicroLink itself relays via DERP in AT mode).
 *
 * @return Bytes received, or -1 on error
 */
ssize_t ml_at_recvfrom(int fd, void *buf, size_t len, int flags,
                        struct sockaddr *src_addr, socklen_t *addrlen);

/**
 * Close a socket.
 * Sends AT+CIPCLOSE=N and frees the link_num slot.
 *
 * @return 0 on success, -1 on error
 */
int ml_at_close(int fd);

/**
 * Bind a socket to a local address/port.
 * For UDP: stores port for use in CIPOPEN.
 * For TCP: stores port (not commonly used on client).
 *
 * @return 0 on success, -1 on error
 */
int ml_at_bind(int fd, const struct sockaddr *addr, socklen_t addrlen);

/**
 * Set socket options.
 * Supports: SO_RCVTIMEO, SO_SNDTIMEO, SO_KEEPALIVE.
 * Other options stored but may not apply to AT sockets.
 *
 * @return 0 on success, -1 on error
 */
int ml_at_setsockopt(int fd, int level, int optname,
                      const void *optval, socklen_t optlen);

/**
 * fcntl for O_NONBLOCK flag.
 *
 * @return depends on cmd (F_GETFL, F_SETFL)
 */
int ml_at_fcntl(int fd, int cmd, int arg);

/**
 * select()-like multiplexing for AT sockets.
 * Readable when buffered data, a pending modem buffer, remote close or a
 * receive error is seen (polls with AT+CIPRXGET=4).
 *
 * @param nfds     Highest FD + 1
 * @param readfds  Set of FDs to check for readability
 * @param writefds Always set for connected sockets (TX via AT is always ready)
 * @param exceptfds Ignored
 * @param timeout  Timeout (NULL = block forever)
 * @return Number of ready FDs, 0 on timeout, -1 on error
 */
int ml_at_select(int nfds, fd_set *readfds, fd_set *writefds,
                  fd_set *exceptfds, struct timeval *timeout);

/* ============================================================================
 * DNS Resolution
 * ========================================================================== */

/**
 * Resolve hostname using AT+CDNSGIP.
 * Compatible with getaddrinfo() return format.
 *
 * @return 0 on success, EAI_* error code on failure
 */
int ml_at_getaddrinfo(const char *hostname, const char *service,
                       const struct addrinfo *hints, struct addrinfo **res);

/**
 * Free addrinfo returned by ml_at_getaddrinfo().
 */
void ml_at_freeaddrinfo(struct addrinfo *res);

/* ============================================================================
 * Helpers
 * ========================================================================== */

/** Virtual FD range for AT sockets — must fit within FD_SETSIZE (64) */
#define ML_AT_SOCK_FD_BASE  32
#define ML_AT_SOCK_MAX      10

/**
 * Check if an FD belongs to the AT socket bridge (FD >= 32 and < 42).
 */
bool ml_at_socket_is_at_fd(int fd);

/**
 * Send raw data on a socket (for mbedTLS BIO callback compatibility).
 * Same as ml_at_send() but with write() signature.
 */
ssize_t ml_at_write(int fd, const void *buf, size_t len);

/**
 * Read data from a socket (for mbedTLS BIO callback compatibility).
 * Same as ml_at_recv() but with read() signature.
 */
ssize_t ml_at_read(int fd, void *buf, size_t len);

#else /* !CONFIG_ML_ENABLE_CELLULAR */

/* Stubs when cellular is disabled — always report "not ready" */
static inline bool ml_at_socket_is_ready(void) { return false; }
static inline bool ml_at_socket_is_at_fd(int fd) { (void)fd; return false; }

#endif /* CONFIG_ML_ENABLE_CELLULAR */

#ifdef __cplusplus
}
#endif
