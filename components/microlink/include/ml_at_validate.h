/**
 * @file ml_at_validate.h
 * @brief Validation, redaction and parsing helpers for modem AT commands
 *
 * Any string that is placed inside an AT command line (APN, PPP
 * credentials, SIM PIN, host names, application pass-through commands)
 * must pass one of these checks first. A '"' would close the quoted
 * argument and a CR/LF would end the command line, letting a crafted
 * value run arbitrary AT commands on the modem (radio off, SIM lock,
 * SMS, baud rate change, ...).
 *
 * Pure C with no ESP-IDF dependencies, so it is unit tested on the host
 * (test/host/test_at_validate.c).
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum lengths accepted by the type-specific validators */
#define ML_AT_APN_MAX        100   /* 3GPP TS 23.003 s9.1: APN <= 100 octets */
#define ML_AT_PIN_MIN        4
#define ML_AT_PIN_MAX        8
#define ML_AT_HOSTNAME_MAX   253   /* RFC 1035/1123 */
#define ML_AT_CRED_MAX       64    /* PPP user name / password */
#define ML_AT_CMD_MAX        200   /* pass-through command line, without CR/LF */

typedef enum {
    ML_AT_PARAM_APN,        /* [A-Za-z0-9-] labels separated by '.', may be empty */
    ML_AT_PARAM_PIN,        /* 4-8 decimal digits */
    ML_AT_PARAM_HOSTNAME,   /* RFC 1123 host name (LDH labels, '.'), not empty */
    ML_AT_PARAM_CREDENTIAL, /* printable ASCII except '"' and '\\', may be empty */
} ml_at_param_kind_t;

/**
 * Baseline check for any string that goes inside a quoted AT argument:
 * non-NULL, at most @p maxlen bytes, only printable ASCII (0x20-0x7E), and
 * no '"' or '\\' (some modems treat "\XX" as a hex escape inside strings).
 * Control characters (CR, LF, Ctrl-Z, ESC, ...) and bytes >= 0x80 are
 * rejected. An empty string passes.
 */
bool ml_at_is_safe_param(const char *s, size_t maxlen);

/**
 * Type-specific check. @p maxlen further limits the length (pass the
 * destination buffer size minus one, or 0 to use only the type's limit).
 */
bool ml_at_param_valid(ml_at_param_kind_t kind, const char *s, size_t maxlen);

static inline bool ml_at_valid_apn(const char *s) {
    return ml_at_param_valid(ML_AT_PARAM_APN, s, 0);
}
static inline bool ml_at_valid_pin(const char *s) {
    return ml_at_param_valid(ML_AT_PARAM_PIN, s, 0);
}
static inline bool ml_at_valid_hostname(const char *s) {
    return ml_at_param_valid(ML_AT_PARAM_HOSTNAME, s, 0);
}
static inline bool ml_at_valid_credential(const char *s) {
    return ml_at_param_valid(ML_AT_PARAM_CREDENTIAL, s, 0);
}

/**
 * Check an application-supplied AT command line (without the trailing
 * CR/LF): must start with "AT" (any case), be at most @p maxlen bytes
 * (0 = ML_AT_CMD_MAX) and contain only printable ASCII, so it cannot carry
 * a second command line, Ctrl-Z (end of SMS / data) or ESC.
 */
bool ml_at_cmd_is_safe(const char *cmd, size_t maxlen);

/**
 * Stricter check used while the AT socket bridge owns the modem.
 * In addition to ml_at_cmd_is_safe(): only "AT", "ATI" or one extended
 * command from an allowlist of query/information commands (identification,
 * signal and registration state, clock, battery, temperature, GNSS), e.g.
 * AT+CSQ, AT+CPSI?, AT+CREG?, AT+CEREG?, AT+COPS?, AT+CCLK?, AT+CBC,
 * AT+CPMUTEMP, AT+SIMCOMATI, AT+CGMR, AT+CGPS=1, AT+CGPSINFO,
 * AT+CGNSSINFO. The name must match exactly, in an allowed form (exec,
 * "?", "=?" or "=args"); set-command arguments may only contain letters,
 * digits, ',', '.', '-' and '"'. No spaces, no ';' and no second '+'.
 * The list is s_bridge_allowed[] in ml_at_validate.c.
 */
bool ml_at_cmd_allowed_with_bridge(const char *cmd);

/**
 * Copy @p cmd to @p out for logging, replacing the arguments of commands
 * that carry secrets (AT+CPIN, AT+CGAUTH, AT+CPWD, AT+CLCK, ..., and the
 * SIMCom FTP/MQTT/HTTP/SSL/e-mail login and URL commands such as
 * AT+CFTPSLOGIN, AT+CMQTTCONNECT, AT+HTTPPARA) with "****". Non-printable bytes are shown as '.'. Always NUL-terminates when
 * @p out_size > 0. Returns @p out.
 */
const char *ml_at_redact_cmd(const char *cmd, char *out, size_t out_size);

/** Buffer size for ml_at_mask_id(): "****" + 4 characters + NUL */
#define ML_AT_MASKED_ID_SIZE 9

/**
 * Copy a device/SIM identifier (IMEI, ICCID, ...) to @p out for logging
 * with everything but the last 4 characters replaced by "****"
 * ("490154203237518" -> "****7518"). Identifiers of 4 characters or fewer
 * (or longer than 64) are fully masked, an empty one stays empty.
 * Always NUL-terminates when @p out_size > 0. Returns @p out.
 */
const char *ml_at_mask_id(const char *id, char *out, size_t out_size);

/** Zero a buffer that held a secret (not optimised away). */
void ml_at_secure_zero(void *buf, size_t len);

/** Parsed "+CIPRXGET: 2,<link>,<read_len>,<rest_len>[,<src>]" header line */
typedef struct {
    int      link;
    int      read_len;
    int      rest_len;
    bool     has_src;
    uint32_t src_ip;     /* IPv4, network byte order (valid if has_src) */
    uint16_t src_port;   /* host byte order (valid if has_src) */
} ml_at_rxget_hdr_t;

/**
 * Parse a "+CIPRXGET: 2,..." header line of @p len bytes (CR/LF optional).
 * Optional source suffixes ',"a.b.c.d",port' and ',a.b.c.d:port' are
 * recognised. Returns false unless link is 0..max_link-1, read_len is
 * 0..max_read and rest_len is >= 0 (missing rest_len reads as 0).
 */
bool ml_at_parse_rxget_hdr(const char *line, size_t len, int max_link,
                           int max_read, ml_at_rxget_hdr_t *out);

#ifdef __cplusplus
}
#endif
