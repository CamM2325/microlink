/**
 * @file ml_at_validate.c
 * @brief Validation, redaction and parsing helpers for modem AT commands
 *
 * No ESP-IDF dependencies: also compiled by the host unit tests.
 */

#include "ml_at_validate.h"

#include <string.h>

/* ============================================================================
 * Small helpers (no locale, no libc ctype: behaviour must not depend on
 * the C library or on bytes >= 0x80)
 * ========================================================================== */

static bool is_digit(char c) { return c >= '0' && c <= '9'; }
static bool is_alpha(char c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'); }
static bool is_alnum(char c) { return is_digit(c) || is_alpha(c); }
static bool is_print(char c) { return c >= 0x20 && c <= 0x7E; }
static char to_upper(char c) { return (c >= 'a' && c <= 'z') ? (char)(c - 'a' + 'A') : c; }

/* strlen bounded to limit+1, so a missing terminator is never read past
 * limit+1 bytes and "too long" can be detected. */
static size_t bounded_len(const char *s, size_t limit)
{
    size_t n = 0;
    while (n <= limit && s[n] != '\0') n++;
    return n;
}

static size_t effective_max(size_t type_max, size_t caller_max)
{
    return (caller_max != 0 && caller_max < type_max) ? caller_max : type_max;
}

/* Case-insensitive prefix test */
static bool starts_with_ci(const char *s, const char *prefix)
{
    while (*prefix) {
        if (to_upper(*s) != to_upper(*prefix)) return false;
        s++;
        prefix++;
    }
    return true;
}

/* Case-insensitive search; returns pointer into s or NULL */
static const char *find_ci(const char *s, const char *needle)
{
    for (; *s; s++) {
        if (starts_with_ci(s, needle)) return s;
    }
    return NULL;
}

/* DNS-style label list: labels of [A-Za-z0-9-], 1..63 chars, not starting
 * or ending with '-', separated by single '.'; no leading/trailing dot. */
static bool valid_label_list(const char *s, size_t len)
{
    size_t label_len = 0;
    char prev = '.';
    for (size_t i = 0; i < len; i++) {
        char c = s[i];
        if (c == '.') {
            if (label_len == 0 || prev == '-') return false;
            label_len = 0;
        } else if (is_alnum(c) || c == '-') {
            if (label_len == 0 && c == '-') return false;
            if (++label_len > 63) return false;
        } else {
            return false;
        }
        prev = c;
    }
    return label_len > 0 && prev != '-';
}

/* ============================================================================
 * Parameter validation
 * ========================================================================== */

bool ml_at_is_safe_param(const char *s, size_t maxlen)
{
    if (!s) return false;
    size_t len = bounded_len(s, maxlen);
    if (len > maxlen) return false;
    for (size_t i = 0; i < len; i++) {
        char c = s[i];
        if (!is_print(c) || c == '"' || c == '\\') return false;
    }
    return true;
}

bool ml_at_param_valid(ml_at_param_kind_t kind, const char *s, size_t maxlen)
{
    if (!s) return false;

    switch (kind) {
    case ML_AT_PARAM_APN: {
        size_t max = effective_max(ML_AT_APN_MAX, maxlen);
        size_t len = bounded_len(s, max);
        if (len > max) return false;
        if (len == 0) return true;      /* empty = network default */
        return valid_label_list(s, len);
    }
    case ML_AT_PARAM_PIN: {
        size_t max = effective_max(ML_AT_PIN_MAX, maxlen);
        size_t len = bounded_len(s, max);
        if (len < ML_AT_PIN_MIN || len > max) return false;
        for (size_t i = 0; i < len; i++) {
            if (!is_digit(s[i])) return false;
        }
        return true;
    }
    case ML_AT_PARAM_HOSTNAME: {
        size_t max = effective_max(ML_AT_HOSTNAME_MAX, maxlen);
        size_t len = bounded_len(s, max);
        if (len == 0 || len > max) return false;
        return valid_label_list(s, len);
    }
    case ML_AT_PARAM_CREDENTIAL:
        /* ';' and ',' are allowed: they are inside a quoted string, and a
         * quote can never appear, so they cannot end the argument. */
        return ml_at_is_safe_param(s, effective_max(ML_AT_CRED_MAX, maxlen));
    }
    return false;
}

/* ============================================================================
 * Application pass-through commands
 * ========================================================================== */

bool ml_at_cmd_is_safe(const char *cmd, size_t maxlen)
{
    if (!cmd) return false;
    size_t max = effective_max(ML_AT_CMD_MAX, maxlen);
    size_t len = bounded_len(cmd, max);
    if (len < 2 || len > max) return false;
    if (!starts_with_ci(cmd, "AT")) return false;
    for (size_t i = 0; i < len; i++) {
        if (!is_print(cmd[i])) return false;   /* CR, LF, Ctrl-Z, ESC, 8-bit */
    }
    return true;
}

/* Extended commands that would disturb the AT socket bridge or the UART */
static const char *const s_bridge_denied[] = {
    "+CIP",     /* sockets owned by the bridge (CIPOPEN/CIPSEND/CIPRXGET/...) */
    "+NET",     /* NETOPEN/NETCLOSE: the bridge's PDP/network session */
    "+CDNS",    /* DNS is done by the bridge */
    "+IPR",     /* baud rate */
    "+ICF",     /* character framing */
    "+IFC",     /* flow control */
    "+CFUN",    /* radio / modem reset */
    "+CMUX",    /* multiplexer mode */
    "+CGACT",   /* PDP context used by the bridge */
    "+CRESET",
    "+CPOF",
    "+CSCLK",   /* UART sleep */
};

bool ml_at_cmd_allowed_with_bridge(const char *cmd)
{
    if (!ml_at_cmd_is_safe(cmd, 0)) return false;

    const char *rest = cmd + 2;
    /* Basic commands can be chained without separators ("ATE1V0H"), so
     * only plain "AT" and "ATI" are allowed among them. */
    if (*rest == '\0') return true;
    if ((rest[0] == 'I' || rest[0] == 'i') && rest[1] == '\0') return true;
    if (rest[0] != '+') return false;
    if (strchr(rest, ';')) return false;   /* no command concatenation */

    for (size_t i = 0; i < sizeof(s_bridge_denied) / sizeof(s_bridge_denied[0]); i++) {
        if (starts_with_ci(rest, s_bridge_denied[i])) return false;
    }
    return true;
}

/* ============================================================================
 * Log redaction
 * ========================================================================== */

/* Commands whose arguments contain a PIN, PUK, password or raw SIM APDU */
static const char *const s_secret_cmds[] = {
    "+CPIN=", "+CPIN2=", "+CPWD=", "+CLCK=", "+CGAUTH=", "+CSIM=", "+CRSM=",
    "+CPINR=", "+SPIC=",
};

const char *ml_at_redact_cmd(const char *cmd, char *out, size_t out_size)
{
    if (!out || out_size == 0) return out;
    out[0] = '\0';
    if (!cmd) return out;

    /* Earliest secret-carrying command anywhere in the line ("AT+CSQ;+CPIN=..") */
    const char *cut = NULL;
    for (size_t i = 0; i < sizeof(s_secret_cmds) / sizeof(s_secret_cmds[0]); i++) {
        const char *p = find_ci(cmd, s_secret_cmds[i]);
        if (p) {
            p += strlen(s_secret_cmds[i]);     /* just after '=' */
            if (!cut || p < cut) cut = p;
        }
    }

    size_t keep = cut ? (size_t)(cut - cmd) : strlen(cmd);
    size_t o = 0;
    for (size_t i = 0; i < keep && o + 1 < out_size; i++) {
        char c = cmd[i];
        out[o++] = is_print(c) ? c : '.';
    }
    if (cut) {
        const char *mask = "****";
        for (size_t i = 0; mask[i] && o + 1 < out_size; i++) out[o++] = mask[i];
    }
    out[o] = '\0';
    return out;
}

void ml_at_secure_zero(void *buf, size_t len)
{
    volatile uint8_t *p = (volatile uint8_t *)buf;
    while (len--) *p++ = 0;
}

/* ============================================================================
 * +CIPRXGET: 2 header parsing
 * ========================================================================== */

/* Parse an unsigned decimal <= max. Advances *pp. */
static bool parse_uint(const char **pp, const char *end, long max, long *out)
{
    const char *p = *pp;
    long v = 0;
    if (p >= end || !is_digit(*p)) return false;
    while (p < end && is_digit(*p)) {
        int d = *p - '0';
        if (d > max || v > (max - d) / 10) return false;   /* v*10+d > max, no overflow */
        v = v * 10 + d;
        p++;
    }
    *pp = p;
    *out = v;
    return true;
}

static bool parse_ipv4(const char **pp, const char *end, uint32_t *out_be)
{
    uint8_t b[4];
    const char *p = *pp;
    for (int i = 0; i < 4; i++) {
        long v;
        if (!parse_uint(&p, end, 255, &v)) return false;
        b[i] = (uint8_t)v;
        if (i < 3) {
            if (p >= end || *p != '.') return false;
            p++;
        }
    }
    /* Store in network byte order independent of host endianness */
    uint8_t *o = (uint8_t *)out_be;
    o[0] = b[0]; o[1] = b[1]; o[2] = b[2]; o[3] = b[3];
    *pp = p;
    return true;
}

static bool parse_src_suffix(const char *p, const char *end,
                             uint32_t *ip, uint16_t *port)
{
    long v;
    if (p < end && *p == '"') {
        p++;
        if (!parse_ipv4(&p, end, ip)) return false;
        if (p + 1 >= end || p[0] != '"' || p[1] != ',') return false;
        p += 2;
    } else {
        if (!parse_ipv4(&p, end, ip)) return false;
        if (p >= end || *p != ':') return false;
        p++;
    }
    if (!parse_uint(&p, end, 65535, &v)) return false;
    *port = (uint16_t)v;
    return true;
}

bool ml_at_parse_rxget_hdr(const char *line, size_t len, int max_link,
                           int max_read, ml_at_rxget_hdr_t *out)
{
    static const char prefix[] = "+CIPRXGET:";
    const size_t plen = sizeof(prefix) - 1;
    if (!line || !out || max_link <= 0 || max_read < 0) return false;

    /* Trim trailing CR/LF and blanks */
    while (len > 0 && (line[len - 1] == '\r' || line[len - 1] == '\n' ||
                       line[len - 1] == ' ' || line[len - 1] == '\t')) len--;
    if (len < plen || memcmp(line, prefix, plen) != 0) return false;

    const char *p = line + plen;
    const char *end = line + len;
    long v;

    while (p < end && *p == ' ') p++;
    if (p + 1 >= end || p[0] != '2' || p[1] != ',') return false;
    p += 2;

    memset(out, 0, sizeof(*out));

    if (!parse_uint(&p, end, (long)max_link - 1, &v)) return false;
    out->link = (int)v;
    if (p >= end || *p != ',') return false;
    p++;

    if (!parse_uint(&p, end, max_read, &v)) return false;
    out->read_len = (int)v;

    if (p < end) {
        if (*p != ',') return false;
        p++;
        if (!parse_uint(&p, end, 0x7FFFFFFFL, &v)) return false;
        out->rest_len = (int)v;
    }

    if (p < end) {
        if (*p != ',') return false;
        p++;
        /* An unrecognised suffix is ignored (the lengths are what matter) */
        out->has_src = parse_src_suffix(p, end, &out->src_ip, &out->src_port);
    }
    return true;
}
