/*
 * Tests for the AT command parameter validators, pass-through checks, log
 * redaction and +CIPRXGET header parsing (components/microlink/src/ml_at_validate.c).
 */
#include <stdio.h>
#include <string.h>
#include "ml_at_validate.h"

static int failures = 0;
#define CHECK(cond) do { if (!(cond)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); failures++; } } while (0)

static void test_safe_param(void) {
	CHECK(ml_at_is_safe_param("", 10));
	CHECK(ml_at_is_safe_param("abc def!#$%&'()*+,-./:;<=>?@[]^_`{|}~", 64));
	CHECK(!ml_at_is_safe_param(NULL, 10));
	CHECK(!ml_at_is_safe_param("a\"b", 10));
	CHECK(!ml_at_is_safe_param("a\\22b", 10));
	CHECK(!ml_at_is_safe_param("a\rAT+CFUN=0", 64));
	CHECK(!ml_at_is_safe_param("a\nb", 10));
	CHECK(!ml_at_is_safe_param("a\x1a", 10));       /* Ctrl-Z */
	CHECK(!ml_at_is_safe_param("a\x1b", 10));       /* ESC */
	CHECK(!ml_at_is_safe_param("caf\xc3\xa9", 10)); /* UTF-8 */
	CHECK(!ml_at_is_safe_param("a\x7f", 10));       /* DEL */
	CHECK(ml_at_is_safe_param("12345", 5));
	CHECK(!ml_at_is_safe_param("123456", 5));
}

static void test_apn(void) {
	CHECK(ml_at_valid_apn(""));
	CHECK(ml_at_valid_apn("internet"));
	CHECK(ml_at_valid_apn("america.bics"));
	CHECK(ml_at_valid_apn("fast.t-mobile.com"));
	CHECK(ml_at_valid_apn("iot.1nce.net"));
	CHECK(ml_at_valid_apn("TM"));
	CHECK(!ml_at_valid_apn(NULL));
	CHECK(!ml_at_valid_apn("x\"\rAT+CFUN=0\r"));
	CHECK(!ml_at_valid_apn("a;b"));
	CHECK(!ml_at_valid_apn("a b"));
	CHECK(!ml_at_valid_apn("a_b"));
	CHECK(!ml_at_valid_apn(".internet"));
	CHECK(!ml_at_valid_apn("internet."));
	CHECK(!ml_at_valid_apn("a..b"));
	CHECK(!ml_at_valid_apn("-a"));
	CHECK(!ml_at_valid_apn("a-.b"));
	char lab[70]; memset(lab, 'a', 64); lab[64] = 0;
	CHECK(!ml_at_valid_apn(lab));                   /* label > 63 */
	lab[63] = 0;
	CHECK(ml_at_valid_apn(lab));
	char longapn[120];
	for (int i = 0; i < 101; i++) longapn[i] = (i % 10 == 9) ? '.' : 'a';
	longapn[101] = 0;
	CHECK(!ml_at_valid_apn(longapn));               /* > 100 */
	longapn[99] = 'a'; longapn[100] = 0;
	CHECK(ml_at_valid_apn(longapn));
	/* caller limit (destination buffer) */
	CHECK(ml_at_param_valid(ML_AT_PARAM_APN, "abcd", 4));
	CHECK(!ml_at_param_valid(ML_AT_PARAM_APN, "abcde", 4));
}

static void test_pin(void) {
	CHECK(ml_at_valid_pin("1234"));
	CHECK(ml_at_valid_pin("12345678"));
	CHECK(!ml_at_valid_pin("123"));
	CHECK(!ml_at_valid_pin("123456789"));
	CHECK(!ml_at_valid_pin(""));
	CHECK(!ml_at_valid_pin(NULL));
	CHECK(!ml_at_valid_pin("12a4"));
	CHECK(!ml_at_valid_pin("1234\""));
	CHECK(!ml_at_valid_pin("1234\r"));
	CHECK(!ml_at_valid_pin(" 1234"));
}

static void test_hostname(void) {
	CHECK(ml_at_valid_hostname("controlplane.tailscale.com"));
	CHECK(ml_at_valid_hostname("derp1f.tailscale.com"));
	CHECK(ml_at_valid_hostname("localhost"));
	CHECK(ml_at_valid_hostname("1.2.3.4"));
	CHECK(ml_at_valid_hostname("hs-1.example.org"));
	CHECK(!ml_at_valid_hostname(""));
	CHECK(!ml_at_valid_hostname(NULL));
	CHECK(!ml_at_valid_hostname("a\"b"));
	CHECK(!ml_at_valid_hostname("evil.com\"\r\nAT+CFUN=0"));
	CHECK(!ml_at_valid_hostname("a b.com"));
	CHECK(!ml_at_valid_hostname("a_b.com"));
	CHECK(!ml_at_valid_hostname("a;b"));
	CHECK(!ml_at_valid_hostname("host:443"));
	CHECK(!ml_at_valid_hostname("2001:db8::1"));
	CHECK(!ml_at_valid_hostname("-a.com"));
	CHECK(!ml_at_valid_hostname("a-.com"));
	CHECK(!ml_at_valid_hostname("a..com"));
	CHECK(!ml_at_valid_hostname("a.com."));
	char big[300]; memset(big, 'a', sizeof(big)); big[299] = 0;
	for (int i = 50; i < 299; i += 50) big[i] = '.';
	CHECK(!ml_at_valid_hostname(big));              /* > 253 */
	CHECK(!ml_at_param_valid(ML_AT_PARAM_HOSTNAME, "abcdef", 5));
}

static void test_credential(void) {
	CHECK(ml_at_valid_credential(""));
	CHECK(ml_at_valid_credential("sora"));
	CHECK(ml_at_valid_credential("p@ss;w,rd with space"));
	CHECK(!ml_at_valid_credential("pa\"ss"));
	CHECK(!ml_at_valid_credential("pa\\ss"));
	CHECK(!ml_at_valid_credential("pa\r\nss"));
	CHECK(!ml_at_valid_credential("pa\tss"));
	CHECK(!ml_at_valid_credential(NULL));
	CHECK(ml_at_param_valid(ML_AT_PARAM_CREDENTIAL, "0123456789012345678901234567890", 31));
	CHECK(!ml_at_param_valid(ML_AT_PARAM_CREDENTIAL, "01234567890123456789012345678901", 31));
}

static void test_cmd(void) {
	CHECK(ml_at_cmd_is_safe("AT", 0));
	CHECK(ml_at_cmd_is_safe("at+cgpsinfo", 0));
	CHECK(ml_at_cmd_is_safe("AT+CGPS=1,1", 0));
	CHECK(ml_at_cmd_is_safe("AT+CUSD=1,\"*100#\"", 0));
	CHECK(!ml_at_cmd_is_safe(NULL, 0));
	CHECK(!ml_at_cmd_is_safe("", 0));
	CHECK(!ml_at_cmd_is_safe("A", 0));
	CHECK(!ml_at_cmd_is_safe("+CSQ", 0));
	CHECK(!ml_at_cmd_is_safe("AT+CSQ\r", 0));
	CHECK(!ml_at_cmd_is_safe("AT+CSQ\r\nAT+CFUN=0", 0));
	CHECK(!ml_at_cmd_is_safe("AT+CMGS=\"1\"\rhi\x1a", 0));
	CHECK(!ml_at_cmd_is_safe("AT+CSQ", 5));
	char longcmd[300]; memset(longcmd, 'A', sizeof(longcmd)); longcmd[1] = 'T'; longcmd[299] = 0;
	CHECK(!ml_at_cmd_is_safe(longcmd, 0));

	/* AT socket bridge mode */
	CHECK(ml_at_cmd_allowed_with_bridge("AT"));
	CHECK(ml_at_cmd_allowed_with_bridge("ATI"));
	CHECK(ml_at_cmd_allowed_with_bridge("AT+CGPSINFO"));
	CHECK(ml_at_cmd_allowed_with_bridge("AT+CGNSSINFO"));
	CHECK(ml_at_cmd_allowed_with_bridge("AT+CGPS=1"));
	CHECK(ml_at_cmd_allowed_with_bridge("AT+CSQ"));
	CHECK(ml_at_cmd_allowed_with_bridge("AT+CPSI?"));
	CHECK(!ml_at_cmd_allowed_with_bridge("ATD*99#"));
	CHECK(!ml_at_cmd_allowed_with_bridge("ATH"));
	CHECK(!ml_at_cmd_allowed_with_bridge("ATO"));
	CHECK(!ml_at_cmd_allowed_with_bridge("ATE1"));
	CHECK(!ml_at_cmd_allowed_with_bridge("ATIE1"));
	CHECK(!ml_at_cmd_allowed_with_bridge("AT&F"));
	CHECK(!ml_at_cmd_allowed_with_bridge("AT+CIPCLOSE=0"));
	CHECK(!ml_at_cmd_allowed_with_bridge("at+cipsend=0,5"));
	CHECK(!ml_at_cmd_allowed_with_bridge("AT+NETCLOSE"));
	CHECK(!ml_at_cmd_allowed_with_bridge("AT+IPR=9600"));
	CHECK(!ml_at_cmd_allowed_with_bridge("AT+CFUN=0"));
	CHECK(!ml_at_cmd_allowed_with_bridge("AT+CGACT=0,1"));
	CHECK(!ml_at_cmd_allowed_with_bridge("AT+CMUX=0"));
	CHECK(!ml_at_cmd_allowed_with_bridge("AT+CSQ;+NETCLOSE"));
	CHECK(!ml_at_cmd_allowed_with_bridge("AT+CSQ;H"));
	CHECK(!ml_at_cmd_allowed_with_bridge("AT+CSQ\r\nAT+NETCLOSE"));
	/* allowlist: queries, info and GNSS */
	CHECK(ml_at_cmd_allowed_with_bridge("at+csq"));
	CHECK(ml_at_cmd_allowed_with_bridge("AT+CSQ=?"));
	CHECK(ml_at_cmd_allowed_with_bridge("AT+CREG?"));
	CHECK(ml_at_cmd_allowed_with_bridge("AT+CEREG?"));
	CHECK(ml_at_cmd_allowed_with_bridge("AT+COPS?"));
	CHECK(ml_at_cmd_allowed_with_bridge("AT+CCLK?"));
	CHECK(ml_at_cmd_allowed_with_bridge("AT+CBC"));
	CHECK(ml_at_cmd_allowed_with_bridge("AT+CPMUTEMP"));
	CHECK(ml_at_cmd_allowed_with_bridge("AT+SIMCOMATI"));
	CHECK(ml_at_cmd_allowed_with_bridge("AT+CGMR"));
	CHECK(ml_at_cmd_allowed_with_bridge("AT+CGPS?"));
	CHECK(ml_at_cmd_allowed_with_bridge("AT+CGPS=0"));
	CHECK(ml_at_cmd_allowed_with_bridge("AT+CGNSSPWR=1"));
	CHECK(ml_at_cmd_allowed_with_bridge("AT+CGPADDR=1"));
	CHECK(ml_at_cmd_allowed_with_bridge("AT+CGACT?"));
	/* not on the list, or not in an allowed form */
	CHECK(!ml_at_cmd_allowed_with_bridge("AT+CGATT=0"));
	CHECK(!ml_at_cmd_allowed_with_bridge("AT+COPS=2"));
	CHECK(!ml_at_cmd_allowed_with_bridge("AT+CNMP=38"));
	CHECK(!ml_at_cmd_allowed_with_bridge("AT+CGDCONT=1,\"IP\",\"x\""));
	CHECK(!ml_at_cmd_allowed_with_bridge("AT+CSOCKSETPN=1"));
	CHECK(!ml_at_cmd_allowed_with_bridge("AT+CATR=1"));
	CHECK(!ml_at_cmd_allowed_with_bridge("AT+CPSMS=1"));
	CHECK(!ml_at_cmd_allowed_with_bridge("AT+CEDRXS=1"));
	CHECK(!ml_at_cmd_allowed_with_bridge("AT+CMGS=\"123\""));
	CHECK(!ml_at_cmd_allowed_with_bridge("AT+HTTPDATA=10,1000"));
	CHECK(!ml_at_cmd_allowed_with_bridge("AT+CLCK=\"SC\",1,\"1234\""));
	CHECK(!ml_at_cmd_allowed_with_bridge("AT+CGPSINFO=10"));
	CHECK(!ml_at_cmd_allowed_with_bridge("AT+CGNSSTST=1"));
	CHECK(!ml_at_cmd_allowed_with_bridge("AT+CSQ?"));
	CHECK(!ml_at_cmd_allowed_with_bridge("AT+CSQX"));
	CHECK(!ml_at_cmd_allowed_with_bridge("AT+CGP"));
	CHECK(!ml_at_cmd_allowed_with_bridge("AT+CREG=2"));
	CHECK(!ml_at_cmd_allowed_with_bridge("AT+CGPS="));
	/* spaces and '+' tricks */
	CHECK(!ml_at_cmd_allowed_with_bridge("AT+ CFUN=0"));
	CHECK(!ml_at_cmd_allowed_with_bridge("AT +CSQ"));
	CHECK(!ml_at_cmd_allowed_with_bridge("AT+CSQ "));
	CHECK(!ml_at_cmd_allowed_with_bridge("AT+CGPS= 1"));
	CHECK(!ml_at_cmd_allowed_with_bridge("AT+CSQ+CFUN=0"));
	CHECK(!ml_at_cmd_allowed_with_bridge("AT+CGPS=1+CFUN=0"));
	CHECK(!ml_at_cmd_allowed_with_bridge("AT++CSQ"));
	CHECK(!ml_at_cmd_allowed_with_bridge("AT+"));
}

static void test_redact(void) {
	char out[64];
	CHECK(strcmp(ml_at_redact_cmd("AT+CPIN=\"1234\"", out, sizeof(out)), "AT+CPIN=****") == 0);
	CHECK(strcmp(ml_at_redact_cmd("at+cpin=1234", out, sizeof(out)), "at+cpin=****") == 0);
	CHECK(strcmp(ml_at_redact_cmd("AT+CGAUTH=1,2,\"user\",\"secret\"", out, sizeof(out)), "AT+CGAUTH=****") == 0);
	CHECK(strcmp(ml_at_redact_cmd("AT+CLCK=\"SC\",1,\"1234\"", out, sizeof(out)), "AT+CLCK=****") == 0);
	CHECK(strcmp(ml_at_redact_cmd("AT+CSQ;+CPIN=1234", out, sizeof(out)), "AT+CSQ;+CPIN=****") == 0);
	CHECK(strcmp(ml_at_redact_cmd("AT+CPIN?", out, sizeof(out)), "AT+CPIN?") == 0);
	CHECK(strcmp(ml_at_redact_cmd("AT+CGDCONT=1,\"IP\",\"internet\"", out, sizeof(out)),
	             "AT+CGDCONT=1,\"IP\",\"internet\"") == 0);
	CHECK(strcmp(ml_at_redact_cmd("AT\r\n", out, sizeof(out)), "AT..") == 0);
	CHECK(strcmp(ml_at_redact_cmd(NULL, out, sizeof(out)), "") == 0);
	CHECK(strcmp(ml_at_redact_cmd("AT+CFTPSLOGIN=\"ftp.example.com\",21,\"u\",\"p\",0", out, sizeof(out)),
	             "AT+CFTPSLOGIN=****") == 0);
	CHECK(strcmp(ml_at_redact_cmd("AT+CMQTTCONNECT=0,\"tcp://h:1883\",60,1,\"u\",\"p\"", out, sizeof(out)),
	             "AT+CMQTTCONNECT=****") == 0);
	CHECK(strcmp(ml_at_redact_cmd("AT+HTTPPARA=\"URL\",\"https://u:p@h/\"", out, sizeof(out)),
	             "AT+HTTPPARA=****") == 0);
	CHECK(strcmp(ml_at_redact_cmd("AT+CMQTTCONNECT?", out, sizeof(out)), "AT+CMQTTCONNECT?") == 0);
	char tiny[6];
	CHECK(strcmp(ml_at_redact_cmd("AT+CPIN=1234", tiny, sizeof(tiny)), "AT+CP") == 0);
	char one[1];
	CHECK(ml_at_redact_cmd("AT", one, sizeof(one))[0] == '\0');
}

static void test_mask_id(void) {
	char out[ML_AT_MASKED_ID_SIZE];
	CHECK(strcmp(ml_at_mask_id("490154203237518", out, sizeof(out)), "****7518") == 0);
	CHECK(strcmp(ml_at_mask_id("89000000000000005678", out, sizeof(out)), "****5678") == 0);
	CHECK(strcmp(ml_at_mask_id("12345", out, sizeof(out)), "****2345") == 0);
	CHECK(strcmp(ml_at_mask_id("1234", out, sizeof(out)), "****") == 0);
	CHECK(strcmp(ml_at_mask_id("", out, sizeof(out)), "") == 0);
	CHECK(strcmp(ml_at_mask_id(NULL, out, sizeof(out)), "") == 0);
	CHECK(strcmp(ml_at_mask_id("12345\r", out, sizeof(out)), "****345.") == 0);
	char small[6];
	CHECK(strcmp(ml_at_mask_id("490154203237518", small, sizeof(small)), "****7") == 0);
	char one[1];
	CHECK(ml_at_mask_id("490154203237518", one, sizeof(one))[0] == '\0');
}

static void test_rxget(void) {
	ml_at_rxget_hdr_t h;
	const char *l = "+CIPRXGET: 2,3,1460,2000\r\n";
	CHECK(ml_at_parse_rxget_hdr(l, strlen(l), 10, 1460, &h));
	CHECK(h.link == 3 && h.read_len == 1460 && h.rest_len == 2000 && !h.has_src);

	l = "+CIPRXGET: 2,0,12";
	CHECK(ml_at_parse_rxget_hdr(l, strlen(l), 10, 1460, &h));
	CHECK(h.link == 0 && h.read_len == 12 && h.rest_len == 0);

	l = "+CIPRXGET: 2,1,48,0,\"203.0.113.7\",3478";
	CHECK(ml_at_parse_rxget_hdr(l, strlen(l), 10, 1460, &h));
	CHECK(h.has_src && h.src_port == 3478);
	{ const unsigned char *b = (const unsigned char *)&h.src_ip; CHECK(b[0] == 203 && b[1] == 0 && b[2] == 113 && b[3] == 7); }

	l = "+CIPRXGET: 2,1,48,0,198.51.100.2:41641\r";
	CHECK(ml_at_parse_rxget_hdr(l, strlen(l), 10, 1460, &h));
	CHECK(h.has_src && h.src_port == 41641);

	l = "+CIPRXGET: 2,1,48,7 \r\n";
	CHECK(ml_at_parse_rxget_hdr(l, strlen(l), 10, 1460, &h) && h.rest_len == 7);

	l = "+CIPRXGET: 2,1,48,0,garbage";
	CHECK(ml_at_parse_rxget_hdr(l, strlen(l), 10, 1460, &h));
	CHECK(!h.has_src);

	/* bounds */
	l = "+CIPRXGET: 2,3,1461,0";  CHECK(!ml_at_parse_rxget_hdr(l, strlen(l), 10, 1460, &h));
	l = "+CIPRXGET: 2,3,600,0";   CHECK(!ml_at_parse_rxget_hdr(l, strlen(l), 10, 512, &h));
	l = "+CIPRXGET: 2,3,-5,0";    CHECK(!ml_at_parse_rxget_hdr(l, strlen(l), 10, 1460, &h));
	l = "+CIPRXGET: 2,10,5,0";    CHECK(!ml_at_parse_rxget_hdr(l, strlen(l), 10, 1460, &h));
	l = "+CIPRXGET: 2,3,99999999999999999999,0"; CHECK(!ml_at_parse_rxget_hdr(l, strlen(l), 10, 1460, &h));
	l = "+CIPRXGET: 2,3,5,99999999999999999999"; CHECK(!ml_at_parse_rxget_hdr(l, strlen(l), 10, 1460, &h));
	l = "+CIPRXGET: 2,3,5,-1";    CHECK(!ml_at_parse_rxget_hdr(l, strlen(l), 10, 1460, &h));
	l = "+CIPRXGET: 4,3,5";       CHECK(!ml_at_parse_rxget_hdr(l, strlen(l), 10, 1460, &h));
	l = "+CIPRXGET: 2,3";         CHECK(!ml_at_parse_rxget_hdr(l, strlen(l), 10, 1460, &h));
	l = "+CIPRXGET: 2,3,5x";      CHECK(!ml_at_parse_rxget_hdr(l, strlen(l), 10, 1460, &h));
	l = "+CIPRXGET: 2,3,0,0";     CHECK(ml_at_parse_rxget_hdr(l, strlen(l), 10, 0, &h) && h.read_len == 0);
	l = "+IPD12";                 CHECK(!ml_at_parse_rxget_hdr(l, strlen(l), 10, 1460, &h));
	CHECK(!ml_at_parse_rxget_hdr(NULL, 0, 10, 1460, &h));
	/* length is honoured: no read past len */
	l = "+CIPRXGET: 2,3,14";
	CHECK(ml_at_parse_rxget_hdr(l, strlen(l) - 1, 10, 1460, &h) && h.read_len == 1);
}

int main(void) {
	test_safe_param();
	test_apn();
	test_pin();
	test_hostname();
	test_credential();
	test_cmd();
	test_redact();
	test_mask_id();
	test_rxget();
	if (failures) {
		fprintf(stderr, "%d failure(s)\n", failures);
		return 1;
	}
	printf("test_at_validate: all passed\n");
	return 0;
}
