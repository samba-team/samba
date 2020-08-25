/*
 * Copyright (c) 2014-2018 Andreas Schneider <asn@samba.org>
 * Copyright (c) 2014-2016 Jakub Hrozek <jakub.hrozek@posteo.se>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the author nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "config.h"

#include <errno.h>
#include <arpa/inet.h>
#ifdef HAVE_ARPA_NAMESER_H
#include <arpa/nameser.h>
#endif /* HAVE_ARPA_NAMESER_H */
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

#include <resolv.h>

#if defined(HAVE_RES_STATE_U_EXT_NSADDRS) || defined(HAVE_RES_SOCKADDR_UNION_SIN6)
#define HAVE_RESOLV_IPV6_NSADDRS 1
#endif

/* GCC has printf type attribute check. */
#ifdef HAVE_ATTRIBUTE_PRINTF_FORMAT
#define PRINTF_ATTRIBUTE(a,b) __attribute__ ((__format__ (__printf__, a, b)))
#else
#define PRINTF_ATTRIBUTE(a,b)
#endif /* HAVE_ATTRIBUTE_PRINTF_FORMAT */

#ifdef HAVE_DESTRUCTOR_ATTRIBUTE
#define DESTRUCTOR_ATTRIBUTE __attribute__ ((destructor))
#else
#define DESTRUCTOR_ATTRIBUTE
#endif /* HAVE_DESTRUCTOR_ATTRIBUTE */

#ifndef RWRAP_DEFAULT_FAKE_TTL
#define RWRAP_DEFAULT_FAKE_TTL 600
#endif  /* RWRAP_DEFAULT_FAKE_TTL */

#ifndef HAVE_NS_NAME_COMPRESS
#define ns_name_compress dn_comp
#endif

#define ns_t_uri 256

enum rwrap_dbglvl_e {
	RWRAP_LOG_ERROR = 0,
	RWRAP_LOG_WARN,
	RWRAP_LOG_NOTICE,
	RWRAP_LOG_DEBUG,
	RWRAP_LOG_TRACE
};

#ifndef HAVE_GETPROGNAME
static const char *getprogname(void)
{
#if defined(HAVE_PROGRAM_INVOCATION_SHORT_NAME)
	return program_invocation_short_name;
#elif defined(HAVE_GETEXECNAME)
	return getexecname();
#else
	return NULL;
#endif /* HAVE_PROGRAM_INVOCATION_SHORT_NAME */
}
#endif /* HAVE_GETPROGNAME */

static void rwrap_log(enum rwrap_dbglvl_e dbglvl, const char *func, const char *format, ...) PRINTF_ATTRIBUTE(3, 4);
# define RWRAP_LOG(dbglvl, ...) rwrap_log((dbglvl), __func__, __VA_ARGS__)

static void rwrap_log(enum rwrap_dbglvl_e dbglvl,
		      const char *func,
		      const char *format, ...)
{
	char buffer[1024];
	va_list va;
	const char *d;
	unsigned int lvl = 0;
	const char *prefix = NULL;
	const char *progname = NULL;

	d = getenv("RESOLV_WRAPPER_DEBUGLEVEL");
	if (d != NULL) {
		lvl = atoi(d);
	}

	if (lvl < dbglvl) {
		return;
	}

	va_start(va, format);
	vsnprintf(buffer, sizeof(buffer), format, va);
	va_end(va);

	switch (dbglvl) {
		case RWRAP_LOG_ERROR:
			prefix = "RWRAP_ERROR";
			break;
		case RWRAP_LOG_WARN:
			prefix = "RWRAP_WARN";
			break;
		case RWRAP_LOG_NOTICE:
			prefix = "RWRAP_NOTICE";
			break;
		case RWRAP_LOG_DEBUG:
			prefix = "RWRAP_DEBUG";
			break;
		case RWRAP_LOG_TRACE:
			prefix = "RWRAP_TRACE";
			break;
	}

	progname = getprogname();
	if (progname == NULL) {
		progname = "<unknown>";
	}

	fprintf(stderr,
		"%s[%s (%u)] - %s: %s\n",
		prefix,
		progname,
		(unsigned int)getpid(),
		func,
		buffer);
}

#ifndef SAFE_FREE
#define SAFE_FREE(x) do { if ((x) != NULL) {free(x); (x)=NULL;} } while(0)
#endif

#define NEXT_KEY(buf, key) do {					\
	(key) = (buf) ? strpbrk((buf), " \t") : NULL;		\
	if ((key) != NULL) {					\
		(key)[0] = '\0';				\
		(key)++;					\
	}							\
	while ((key) != NULL					\
	       && (isblank((int)(key)[0]))) {			\
		(key)++;					\
	}							\
} while(0);

#define RWRAP_MAX_RECURSION 64

union rwrap_sockaddr {
	struct sockaddr sa;
	struct sockaddr_in in;
	struct sockaddr_in6 in6;
};

/* Priority and weight can be omitted from the hosts file, but need to be part
 * of the output
 */
#define DFL_SRV_PRIO	1
#define DFL_SRV_WEIGHT	100
#define DFL_URI_PRIO	1
#define DFL_URI_WEIGHT	100

struct rwrap_srv_rrdata {
	uint16_t port;
	uint16_t prio;
	uint16_t weight;
	char hostname[MAXDNAME];
};

struct rwrap_uri_rrdata {
	uint16_t prio;
	uint16_t weight;
	char uri[MAXDNAME];
};

struct rwrap_soa_rrdata {
	uint32_t serial;
	uint32_t refresh;
	uint32_t retry;
	uint32_t expire;
	uint32_t minimum;
	char nameserver[MAXDNAME];
	char mailbox[MAXDNAME];
};

struct rwrap_fake_rr {
	union fake_rrdata {
		struct in_addr a_rec;
		struct in6_addr aaaa_rec;
		struct rwrap_srv_rrdata srv_rec;
		struct rwrap_uri_rrdata uri_rec;
		struct rwrap_soa_rrdata soa_rec;
		char cname_rec[MAXDNAME];
		char ptr_rec[MAXDNAME];
		char txt_rec[MAXDNAME];
	} rrdata;

	char key[MAXDNAME];
	int type; /* ns_t_* */
};

static void rwrap_fake_rr_init(struct rwrap_fake_rr *rr, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++) {
		rr[i].type = ns_t_invalid;
	}
}

static int rwrap_create_fake_a_rr(const char *key,
				  const char *value,
				  struct rwrap_fake_rr *rr)
{
	int ok;

	ok = inet_pton(AF_INET, value, &rr->rrdata.a_rec);
	if (!ok) {
		RWRAP_LOG(RWRAP_LOG_ERROR,
			  "Failed to convert [%s] to binary\n", value);
		return -1;
	}

	memcpy(rr->key, key, strlen(key) + 1);
	rr->type = ns_t_a;
	return 0;
}

static int rwrap_create_fake_aaaa_rr(const char *key,
				     const char *value,
				     struct rwrap_fake_rr *rr)
{
	int ok;

	ok = inet_pton(AF_INET6, value, &rr->rrdata.aaaa_rec);
	if (!ok) {
		RWRAP_LOG(RWRAP_LOG_ERROR,
			  "Failed to convert [%s] to binary\n", value);
		return -1;
	}

	memcpy(rr->key, key, strlen(key) + 1);
	rr->type = ns_t_aaaa;
	return 0;
}
static int rwrap_create_fake_ns_rr(const char *key,
				   const char *value,
				   struct rwrap_fake_rr *rr)
{
	memcpy(rr->rrdata.srv_rec.hostname, value, strlen(value) + 1);
	memcpy(rr->key, key, strlen(key) + 1);
	rr->type = ns_t_ns;
	return 0;
}

static int rwrap_create_fake_srv_rr(const char *key,
				    const char *value,
				    struct rwrap_fake_rr *rr)
{
	char *str_prio;
	char *str_weight;
	char *str_port;
	const char *hostname;

	/* parse the value into priority, weight, port and hostname
	 * and check the validity */
	hostname = value;
	NEXT_KEY(hostname, str_port);
	NEXT_KEY(str_port, str_prio);
	NEXT_KEY(str_prio, str_weight);
	if (str_port == NULL || hostname == NULL) {
		RWRAP_LOG(RWRAP_LOG_ERROR,
			  "Malformed SRV entry [%s]\n", value);
		return -1;
	}

	if (str_prio) {
		rr->rrdata.srv_rec.prio = atoi(str_prio);
	} else {
		rr->rrdata.srv_rec.prio = DFL_SRV_PRIO;
	}
	if (str_weight) {
		rr->rrdata.srv_rec.weight = atoi(str_weight);
	} else {
		rr->rrdata.srv_rec.weight = DFL_SRV_WEIGHT;
	}
	rr->rrdata.srv_rec.port = atoi(str_port);
	memcpy(rr->rrdata.srv_rec.hostname , hostname, strlen(hostname) + 1);

	memcpy(rr->key, key, strlen(key) + 1);
	rr->type = ns_t_srv;
	return 0;
}

static int rwrap_create_fake_uri_rr(const char *key,
				    const char *value,
				    struct rwrap_fake_rr *rr)
{
	char *str_prio;
	char *str_weight;
	const char *uri;

	/* parse the value into priority, weight, and uri
	 * and check the validity */
	uri = value;
	NEXT_KEY(uri, str_prio);
	NEXT_KEY(str_prio, str_weight);
	if (uri == NULL) {
		RWRAP_LOG(RWRAP_LOG_ERROR,
			  "Malformed URI entry [<null>]\n");
		return -1;
	}

	if (str_prio) {
		rr->rrdata.uri_rec.prio = atoi(str_prio);
	} else {
		rr->rrdata.uri_rec.prio = DFL_URI_PRIO;
	}
	if (str_weight) {
		rr->rrdata.uri_rec.weight = atoi(str_weight);
	} else {
		rr->rrdata.uri_rec.weight = DFL_URI_WEIGHT;
	}
	memcpy(rr->rrdata.uri_rec.uri, uri, strlen(uri) + 1);

	memcpy(rr->key, key, strlen(key) + 1);
	rr->type = ns_t_uri;
	return 0;
}

static int rwrap_create_fake_txt_rr(const char *key,
				    const char *value,
				    struct rwrap_fake_rr *rr)
{
	memcpy(rr->rrdata.txt_rec, value, strlen(value) + 1);

	memcpy(rr->key, key, strlen(key) + 1);
	rr->type = ns_t_txt;
	return 0;
}

static int rwrap_create_fake_soa_rr(const char *key,
				    const char *value,
				    struct rwrap_fake_rr *rr)
{
	const char *nameserver;
	char *mailbox;
	char *str_serial;
	char *str_refresh;
	char *str_retry;
	char *str_expire;
	char *str_minimum;

	/* parse the value into nameserver, mailbox, serial, refresh,
	 * retry, expire, minimum and check the validity
	 */
	nameserver = value;
	NEXT_KEY(nameserver, mailbox);
	NEXT_KEY(mailbox, str_serial);
	NEXT_KEY(str_serial, str_refresh);
	NEXT_KEY(str_refresh, str_retry);
	NEXT_KEY(str_retry, str_expire);
	NEXT_KEY(str_expire, str_minimum);
	if (nameserver == NULL || mailbox == NULL || str_serial == NULL ||
	    str_refresh == NULL || str_retry == NULL || str_expire == NULL ||
	    str_minimum == NULL) {
		RWRAP_LOG(RWRAP_LOG_ERROR,
			  "Malformed SOA entry [%s]\n", value);
		return -1;
	}

	memcpy(rr->rrdata.soa_rec.nameserver, nameserver, strlen(nameserver)+1);
	memcpy(rr->rrdata.soa_rec.mailbox, mailbox, strlen(mailbox)+1);

	rr->rrdata.soa_rec.serial = atoi(str_serial);
	rr->rrdata.soa_rec.refresh = atoi(str_refresh);
	rr->rrdata.soa_rec.retry = atoi(str_retry);
	rr->rrdata.soa_rec.expire = atoi(str_expire);
	rr->rrdata.soa_rec.minimum = atoi(str_minimum);

	memcpy(rr->key, key, strlen(key) + 1);
	rr->type = ns_t_soa;
	return 0;
}

static int rwrap_create_fake_cname_rr(const char *key,
				      const char *value,
				      struct rwrap_fake_rr *rr)
{
	memcpy(rr->rrdata.cname_rec , value, strlen(value) + 1);
	memcpy(rr->key, key, strlen(key) + 1);
	rr->type = ns_t_cname;
	return 0;
}

static int rwrap_create_fake_ptr_rr(const char *key,
				    const char *value,
				    struct rwrap_fake_rr *rr)
{
	memcpy(rr->rrdata.ptr_rec , value, strlen(value) + 1);
	memcpy(rr->key, key, strlen(key) + 1);
	rr->type = ns_t_ptr;
	return 0;
}

/* Prepares a fake header with a single response. Advances header_blob */
static ssize_t rwrap_fake_header(uint8_t **header_blob, size_t remaining,
			         size_t ancount, size_t arcount)
{
	union {
		uint8_t *blob;
		HEADER *header;
	} h;

	if (remaining < NS_HFIXEDSZ) {
		RWRAP_LOG(RWRAP_LOG_ERROR, "Buffer too small!\n");
		return -1;
	}

	h.blob = *header_blob;
	memset(h.blob, 0, NS_HFIXEDSZ);

	h.header->id = res_randomid();		/* random query ID */
	h.header->qr = 1;			/* response flag */
	h.header->rd = 1;			/* recursion desired */
	h.header->ra = 1;			/* recursion available */

	h.header->qdcount = htons(1);		/* no. of questions */
	h.header->ancount = htons(ancount);	/* no. of answers */
	h.header->arcount = htons(arcount);	/* no. of add'tl records */

	/* move past the header */
	*header_blob = h.blob += NS_HFIXEDSZ;

	return NS_HFIXEDSZ;
}

static ssize_t rwrap_fake_question(const char *question,
				   uint16_t type,
				   uint8_t **question_ptr,
				   size_t remaining)
{
	uint8_t *qb = *question_ptr;
	int n;

	n = ns_name_compress(question, qb, remaining, NULL, NULL);
	if (n < 0) {
		RWRAP_LOG(RWRAP_LOG_ERROR,
			  "Failed to compress [%s]\n", question);
		return -1;
	}

	qb += n;
	remaining -= n;

	if (remaining < 2 * sizeof(uint16_t)) {
		RWRAP_LOG(RWRAP_LOG_ERROR, "Buffer too small!\n");
		return -1;
	}

	NS_PUT16(type, qb);
	NS_PUT16(ns_c_in, qb);

	*question_ptr = qb;
	return n + 2 * sizeof(uint16_t);
}

static ssize_t rwrap_fake_rdata_common(uint16_t type,
				       size_t rdata_size,
				       const char *key,
				       size_t remaining,
				       uint8_t **rdata_ptr)
{
	uint8_t *rd = *rdata_ptr;
	ssize_t written = 0;

	written = ns_name_compress(key, rd, remaining, NULL, NULL);
	if (written < 0) {
		RWRAP_LOG(RWRAP_LOG_ERROR,
			  "Failed to compress [%s]\n", key);
		return -1;
	}
	rd += written;
	remaining -= written;

	if (remaining < 3 * sizeof(uint16_t) + sizeof(uint32_t)) {
		RWRAP_LOG(RWRAP_LOG_ERROR, "Buffer too small\n");
		return -1;
	}

	NS_PUT16(type, rd);
	NS_PUT16(ns_c_in, rd);
	NS_PUT32(RWRAP_DEFAULT_FAKE_TTL, rd);
	NS_PUT16(rdata_size, rd);

	if (remaining < rdata_size) {
		RWRAP_LOG(RWRAP_LOG_ERROR, "Buffer too small\n");
		return -1;
	}

	*rdata_ptr = rd;
	return written + 3 * sizeof(uint16_t) + sizeof(uint32_t) + rdata_size;
}

static ssize_t rwrap_fake_a(struct rwrap_fake_rr *rr,
			    uint8_t *answer_ptr,
			    size_t anslen)
{
	uint8_t *a = answer_ptr;
	ssize_t resp_size;

	if (rr->type != ns_t_a) {
		RWRAP_LOG(RWRAP_LOG_ERROR, "Wrong type!\n");
		return -1;
	}
	RWRAP_LOG(RWRAP_LOG_TRACE, "Adding A RR");

	resp_size = rwrap_fake_rdata_common(ns_t_a, sizeof(struct in_addr), rr->key,
					    anslen, &a);
	if (resp_size < 0) {
		return -1;
	}

	memcpy(a, &rr->rrdata.a_rec, sizeof(struct in_addr));

	return resp_size;
}

static ssize_t rwrap_fake_aaaa(struct rwrap_fake_rr *rr,
			       uint8_t *answer,
			       size_t anslen)
{
	uint8_t *a = answer;
	ssize_t resp_size;

	if (rr->type != ns_t_aaaa) {
		RWRAP_LOG(RWRAP_LOG_ERROR, "Wrong type!\n");
		return -1;
	}
	RWRAP_LOG(RWRAP_LOG_TRACE, "Adding AAAA RR");

	resp_size = rwrap_fake_rdata_common(ns_t_aaaa, sizeof(struct in6_addr),
					    rr->key, anslen, &a);
	if (resp_size < 0) {
		return -1;
	}

	memcpy(a, &rr->rrdata.aaaa_rec, sizeof(struct in6_addr));

	return resp_size;
}

static ssize_t rwrap_fake_ns(struct rwrap_fake_rr *rr,
			     uint8_t *answer,
			    size_t anslen)
{
	uint8_t *a = answer;
	ssize_t resp_size = 0;
	size_t rdata_size;
	unsigned char hostname_compressed[MAXDNAME];
	ssize_t compressed_len;

	if (rr->type != ns_t_ns) {
		RWRAP_LOG(RWRAP_LOG_ERROR, "Wrong type!\n");
		return -1;
	}
	RWRAP_LOG(RWRAP_LOG_TRACE, "Adding NS RR");

	/* Prepare the data to write */
	compressed_len = ns_name_compress(rr->rrdata.srv_rec.hostname,
					  hostname_compressed,
					  MAXDNAME,
					  NULL,
					  NULL);
	if (compressed_len < 0) {
		return -1;
	}

	/* Is this enough? */
	rdata_size = compressed_len;

	resp_size = rwrap_fake_rdata_common(ns_t_ns, rdata_size,
					    rr->key, anslen, &a);
	if (resp_size < 0) {
		return -1;
	}

	memcpy(a, hostname_compressed, compressed_len);

	return resp_size;
}

static ssize_t rwrap_fake_srv(struct rwrap_fake_rr *rr,
			      uint8_t *answer,
			      size_t anslen)
{
	uint8_t *a = answer;
	ssize_t resp_size;
	size_t rdata_size;
	unsigned char hostname_compressed[MAXDNAME];
	ssize_t compressed_len;

	if (rr->type != ns_t_srv) {
		RWRAP_LOG(RWRAP_LOG_ERROR, "Wrong type!\n");
		return -1;
	}
	RWRAP_LOG(RWRAP_LOG_TRACE, "Adding SRV RR");
	rdata_size = 3 * sizeof(uint16_t);

	/* Prepare the data to write */
	compressed_len = ns_name_compress(rr->rrdata.srv_rec.hostname,
					  hostname_compressed, MAXDNAME,
					  NULL, NULL);
	if (compressed_len < 0) {
		return -1;
	}
	rdata_size += compressed_len;

	resp_size = rwrap_fake_rdata_common(ns_t_srv, rdata_size,
					    rr->key, anslen, &a);
	if (resp_size < 0) {
		return -1;
	}

	NS_PUT16(rr->rrdata.srv_rec.prio, a);
	NS_PUT16(rr->rrdata.srv_rec.weight, a);
	NS_PUT16(rr->rrdata.srv_rec.port, a);
	memcpy(a, hostname_compressed, compressed_len);

	return resp_size;
}

static ssize_t rwrap_fake_uri(struct rwrap_fake_rr *rr,
			      uint8_t *answer,
			      size_t anslen)
{
	uint8_t *a = answer;
	ssize_t resp_size;
	size_t rdata_size;
	size_t uri_len;

	if (rr->type != ns_t_uri) {
		RWRAP_LOG(RWRAP_LOG_ERROR, "Wrong type!\n");
		return -1;
	}
	RWRAP_LOG(RWRAP_LOG_TRACE, "Adding URI RR");
	rdata_size = 3 * sizeof(uint16_t);
	uri_len = strlen(rr->rrdata.uri_rec.uri) + 1;
	rdata_size += uri_len;

	resp_size = rwrap_fake_rdata_common(ns_t_uri, rdata_size,
					    rr->key, anslen, &a);
	if (resp_size < 0) {
		return -1;
	}

	NS_PUT16(rr->rrdata.uri_rec.prio, a);
	NS_PUT16(rr->rrdata.uri_rec.weight, a);
	memcpy(a, rr->rrdata.uri_rec.uri, uri_len);

	return resp_size;
}

static ssize_t rwrap_fake_txt(struct rwrap_fake_rr *rr,
			      uint8_t *answer,
			      size_t anslen)
{
	uint8_t *a = answer;
	ssize_t resp_size;
	size_t rdata_size;
	size_t txt_len;

	if (rr->type != ns_t_txt) {
		RWRAP_LOG(RWRAP_LOG_ERROR, "Wrong type!\n");
		return -1;
	}
	RWRAP_LOG(RWRAP_LOG_TRACE, "Adding TXT RR");
	txt_len = strlen(rr->rrdata.txt_rec) + 1;
	rdata_size = txt_len;

	resp_size = rwrap_fake_rdata_common(ns_t_txt, rdata_size,
					    rr->key, anslen, &a);
	if (resp_size < 0) {
		return -1;
	}

	memcpy(a, rr->rrdata.txt_rec, txt_len);

	return resp_size;
}

static ssize_t rwrap_fake_soa(struct rwrap_fake_rr *rr,
			      uint8_t *answer,
			      size_t anslen)
{
	uint8_t *a = answer;
	ssize_t resp_size;
	size_t rdata_size;
	unsigned char nameser_compressed[MAXDNAME];
	ssize_t compressed_ns_len;
	unsigned char mailbox_compressed[MAXDNAME];
	ssize_t compressed_mb_len;

	if (rr->type != ns_t_soa) {
		RWRAP_LOG(RWRAP_LOG_ERROR, "Wrong type!\n");
		return -1;
	}
	RWRAP_LOG(RWRAP_LOG_TRACE, "Adding SOA RR");
	rdata_size = 5 * sizeof(uint16_t);

	compressed_ns_len = ns_name_compress(rr->rrdata.soa_rec.nameserver,
					     nameser_compressed,
					     MAXDNAME, NULL, NULL);
	if (compressed_ns_len < 0) {
		return -1;
	}
	rdata_size += compressed_ns_len;

	compressed_mb_len = ns_name_compress(rr->rrdata.soa_rec.mailbox,
					     mailbox_compressed,
					     MAXDNAME, NULL, NULL);
	if (compressed_mb_len < 0) {
		return -1;
	}
	rdata_size += compressed_mb_len;

	resp_size = rwrap_fake_rdata_common(ns_t_soa, rdata_size,
					    rr->key, anslen, &a);
	if (resp_size < 0) {
		return -1;
	}

	memcpy(a, nameser_compressed, compressed_ns_len);
	a += compressed_ns_len;
	memcpy(a, mailbox_compressed, compressed_mb_len);
	a += compressed_mb_len;
	NS_PUT32(rr->rrdata.soa_rec.serial, a);
	NS_PUT32(rr->rrdata.soa_rec.refresh, a);
	NS_PUT32(rr->rrdata.soa_rec.retry, a);
	NS_PUT32(rr->rrdata.soa_rec.expire, a);
	NS_PUT32(rr->rrdata.soa_rec.minimum, a);

	return resp_size;
}

static ssize_t rwrap_fake_cname(struct rwrap_fake_rr *rr,
				uint8_t *answer,
				size_t anslen)
{
	uint8_t *a = answer;
	ssize_t resp_size;
	unsigned char hostname_compressed[MAXDNAME];
	ssize_t rdata_size;

	if (rr->type != ns_t_cname) {
		RWRAP_LOG(RWRAP_LOG_ERROR, "Wrong type!\n");
		return -1;
	}
	RWRAP_LOG(RWRAP_LOG_TRACE, "Adding CNAME RR");

	/* Prepare the data to write */
	rdata_size = ns_name_compress(rr->rrdata.cname_rec,
				      hostname_compressed, MAXDNAME,
				      NULL, NULL);
	if (rdata_size < 0) {
		return -1;
	}

	resp_size = rwrap_fake_rdata_common(ns_t_cname, rdata_size,
					    rr->key, anslen, &a);
	if (resp_size < 0) {
		return -1;
	}

	memcpy(a, hostname_compressed, rdata_size);

	return resp_size;
}

static ssize_t rwrap_fake_ptr(struct rwrap_fake_rr *rr,
			      uint8_t *answer,
			      size_t anslen)
{
	uint8_t *a = answer;
	ssize_t rdata_size;
	ssize_t resp_size;
	unsigned char hostname_compressed[MAXDNAME];

	if (rr->type != ns_t_ptr) {
		RWRAP_LOG(RWRAP_LOG_ERROR, "Wrong type!\n");
		return -1;
	}
	RWRAP_LOG(RWRAP_LOG_TRACE, "Adding PTR RR");

	/* Prepare the data to write */
	rdata_size = ns_name_compress(rr->rrdata.ptr_rec,
				      hostname_compressed, MAXDNAME,
				      NULL, NULL);
	if (rdata_size < 0) {
		return -1;
	}

	resp_size = rwrap_fake_rdata_common(ns_t_ptr, rdata_size,
					    rr->key, anslen, &a);
	if (resp_size < 0) {
		return -1;
	}

	memcpy(a, hostname_compressed, rdata_size);

	return resp_size;
}

#define RESOLV_MATCH(line, name) \
	(strncmp(line, name, sizeof(name) - 1) == 0 && \
	(line[sizeof(name) - 1] == ' ' || \
	 line[sizeof(name) - 1] == '\t'))

#define TYPE_MATCH(type, ns_type, rec_type, str_type, key, query) \
	((type) == (ns_type) && \
	 (strncmp((rec_type), (str_type), sizeof(str_type)) == 0) && \
	 (strcasecmp(key, query)) == 0)


static int rwrap_get_record(const char *hostfile, unsigned recursion,
			    const char *query, int type,
			    struct rwrap_fake_rr *rr);

static int rwrap_uri_recurse(const char *hostfile, unsigned recursion,
			     const char *query, struct rwrap_fake_rr *rr)
{
	int rc;

	rc = rwrap_get_record(hostfile, recursion, query, ns_t_uri, rr);
	if (rc == ENOENT) {
		rc = 0;
	}

	return rc;
}

static int rwrap_srv_recurse(const char *hostfile, unsigned recursion,
			     const char *query, struct rwrap_fake_rr *rr)
{
	int rc;

	rc = rwrap_get_record(hostfile, recursion, query, ns_t_a, rr);
	if (rc == 0) return 0;

	rc = rwrap_get_record(hostfile, recursion, query, ns_t_aaaa, rr);
	if (rc == ENOENT) rc = 0;

	return rc;
}

static int rwrap_cname_recurse(const char *hostfile, unsigned recursion,
			       const char *query, struct rwrap_fake_rr *rr)
{
	int rc;

	rc = rwrap_get_record(hostfile, recursion, query, ns_t_a, rr);
	if (rc == 0) return 0;

	rc = rwrap_get_record(hostfile, recursion, query, ns_t_aaaa, rr);
	if (rc == 0) return 0;

	rc = rwrap_get_record(hostfile, recursion, query, ns_t_cname, rr);
	if (rc == ENOENT) rc = 0;

	return rc;
}

static int rwrap_get_record(const char *hostfile, unsigned recursion,
			    const char *query, int type,
			    struct rwrap_fake_rr *rr)
{
	FILE *fp = NULL;
	char buf[BUFSIZ];
	char *key = NULL;
	char *value = NULL;
	int rc = ENOENT;
	unsigned num_uris = 0;

	if (recursion >= RWRAP_MAX_RECURSION) {
		RWRAP_LOG(RWRAP_LOG_ERROR, "Recursed too deep!\n");
		return -1;
	}

	RWRAP_LOG(RWRAP_LOG_TRACE,
		  "Searching in fake hosts file %s for %s:%d\n", hostfile,
		  query, type);

	fp = fopen(hostfile, "r");
	if (fp == NULL) {
		RWRAP_LOG(RWRAP_LOG_WARN,
			  "Opening %s failed: %s",
			  hostfile, strerror(errno));
		return -1;
	}

	while (fgets(buf, sizeof(buf), fp) != NULL) {
		char *rec_type;
		char *q;

		rec_type = buf;
		key = value = NULL;

		NEXT_KEY(rec_type, key);
		NEXT_KEY(key, value);

		if (key == NULL || value == NULL) {
			RWRAP_LOG(RWRAP_LOG_WARN,
				"Malformed line: not enough parts, use \"rec_type key data\n"
				"For example \"A cwrap.org 10.10.10.10\"");
			continue;
		}

		q = value;
		while(q[0] != '\n' && q[0] != '\0') {
			q++;
		}
		q[0] = '\0';

		if (type == ns_t_uri && recursion > 0) {
			/* Skip non-URI records. */
			if (!TYPE_MATCH(type, ns_t_uri, rec_type, "URI", key, query)) {
				continue;
			}
			/* Skip previous records based on the recurse depth. */
			num_uris++;
			if (num_uris <= recursion) {
				continue;
			}
		}

		if (TYPE_MATCH(type, ns_t_a, rec_type, "A", key, query)) {
			rc = rwrap_create_fake_a_rr(key, value, rr);
			break;
		} else if (TYPE_MATCH(type, ns_t_aaaa,
				      rec_type, "AAAA", key, query)) {
			rc = rwrap_create_fake_aaaa_rr(key, value, rr);
			break;
		} else if (TYPE_MATCH(type, ns_t_ns,
				      rec_type, "NS", key, query)) {
			rc = rwrap_create_fake_ns_rr(key, value, rr);
			break;
		} else if (TYPE_MATCH(type, ns_t_srv,
				      rec_type, "SRV", key, query)) {
			rc = rwrap_create_fake_srv_rr(key, value, rr);
			if (rc == 0) {
				rc = rwrap_srv_recurse(hostfile, recursion+1,
						rr->rrdata.srv_rec.hostname,
						rr + 1);
			}
			break;
		} else if (TYPE_MATCH(type, ns_t_uri,
				      rec_type, "URI", key, query)) {
			rc = rwrap_create_fake_uri_rr(key, value, rr);
			if (rc == 0) {
				/* Recurse to collect multiple URI answers under a single key. */
				rc = rwrap_uri_recurse(hostfile, recursion + 1, key, rr + 1);
			}
			break;
		} else if (TYPE_MATCH(type, ns_t_soa,
				      rec_type, "SOA", key, query)) {
			rc = rwrap_create_fake_soa_rr(key, value, rr);
			break;
		} else if (TYPE_MATCH(type, ns_t_cname,
				      rec_type, "CNAME", key, query)) {
			rc = rwrap_create_fake_cname_rr(key, value, rr);
			if (rc == 0) {
				rc = rwrap_cname_recurse(hostfile, recursion+1,
							 value, rr + 1);
			}
			break;
		} else if (TYPE_MATCH(type, ns_t_a, rec_type, "CNAME", key, query)) {
			rc = rwrap_create_fake_cname_rr(key, value, rr);
			if (rc == 0) {
				rc = rwrap_cname_recurse(hostfile, recursion+1,
							 value, rr + 1);
			}
			break;
		} else if (TYPE_MATCH(type, ns_t_ptr,
				      rec_type, "PTR", key, query)) {
			rc = rwrap_create_fake_ptr_rr(key, value, rr);
			break;
		}
		else if (TYPE_MATCH(type, ns_t_txt,
				      rec_type, "TXT", key, query)) {
			rc = rwrap_create_fake_txt_rr(key, value, rr);
			break;
		}
	}

	if (rc == ENOENT && recursion == 0 && key != NULL) {
		RWRAP_LOG(RWRAP_LOG_TRACE, "Record for [%s] not found\n", query);
		memcpy(rr->key, key, strlen(key) + 1);
	}

	fclose(fp);
	return rc;
}

static ssize_t rwrap_fake_empty(int type,
				const char *question,
				uint8_t *answer,
				size_t anslen)
{
	ssize_t resp_data;
	size_t remaining = anslen;

	resp_data = rwrap_fake_header(&answer, remaining, 0, 0);
	if (resp_data < 0) {
		return -1;
	}
	remaining -= resp_data;

	resp_data += rwrap_fake_question(question, type, &answer, remaining);
	if (resp_data < 0) {
		return -1;
	}
	remaining -= resp_data;

	resp_data += rwrap_fake_rdata_common(type, 0, question,
					    remaining, &answer);
	if (resp_data < 0) {
		return -1;
	}

	return resp_data;
}

static inline bool rwrap_known_type(int type)
{
	switch (type) {
	case ns_t_a:
	case ns_t_aaaa:
	case ns_t_ns:
	case ns_t_srv:
	case ns_t_uri:
	case ns_t_soa:
	case ns_t_cname:
	case ns_t_ptr:
	case ns_t_txt:
		return true;
	}

	return false;
}

static int rwrap_ancount(struct rwrap_fake_rr *rrs, int qtype)
{
	int i;
	int ancount = 0;

	/* For URI return the number of URIs. */
	if (qtype == ns_t_uri) {
		for (i = 0; i < RWRAP_MAX_RECURSION; i++) {
			if (rwrap_known_type(rrs[i].type) &&
			    rrs[i].type == qtype) {
				ancount++;
			}
		}
		return ancount;
	}

	/* Include all RRs in the stack until the sought type
	 * in the answer section. This is the case i.e. when looking
	 * up an A record but the name points to a CNAME
	 */
	for (i = 0; i < RWRAP_MAX_RECURSION; i++) {
		ancount++;

		if (rwrap_known_type(rrs[i].type) &&
		    rrs[i].type == qtype) {
			break;
		}
	}

	/* Return 0 records if the sought type wasn't in the stack */
	return i < RWRAP_MAX_RECURSION ? ancount : 0;
}

static int rwrap_arcount(struct rwrap_fake_rr *rrs, int ancount)
{
	int i;
	int arcount = 0;

	/* start from index ancount */
	for (i = ancount; i < RWRAP_MAX_RECURSION; i++) {
		if (rwrap_known_type(rrs[i].type)) {
			arcount++;
		}
	}

	return arcount;
}

static ssize_t rwrap_add_rr(struct rwrap_fake_rr *rr,
			    uint8_t *answer,
			    size_t anslen)
{
	ssize_t resp_data;

	if (rr == NULL) {
		RWRAP_LOG(RWRAP_LOG_ERROR, "Internal error!\n");
		return -1;
	}

	switch (rr->type) {
	case ns_t_a:
		resp_data = rwrap_fake_a(rr, answer, anslen);
		break;
	case ns_t_aaaa:
		resp_data = rwrap_fake_aaaa(rr, answer, anslen);
		break;
	case ns_t_ns:
		resp_data = rwrap_fake_ns(rr, answer, anslen);
		break;
	case ns_t_srv:
		resp_data = rwrap_fake_srv(rr, answer, anslen);
		break;
	case ns_t_uri:
		resp_data = rwrap_fake_uri(rr, answer, anslen);
		break;
	case ns_t_soa:
		resp_data = rwrap_fake_soa(rr, answer, anslen);
		break;
	case ns_t_cname:
		resp_data = rwrap_fake_cname(rr, answer, anslen);
		break;
	case ns_t_ptr:
		resp_data = rwrap_fake_ptr(rr, answer, anslen);
		break;
	case ns_t_txt:
		resp_data = rwrap_fake_txt(rr, answer, anslen);
		break;
	default:
		return -1;
	}

	return resp_data;
}

static ssize_t rwrap_fake_answer(struct rwrap_fake_rr *rrs,
				 int type,
				 uint8_t *answer,
				 size_t anslen)

{
	ssize_t resp_data;
	ssize_t rrlen;
	size_t remaining = anslen;
	int ancount;
	int arcount;
	int i;

	ancount = rwrap_ancount(rrs, type);
	arcount = rwrap_arcount(rrs, ancount);
	RWRAP_LOG(RWRAP_LOG_TRACE,
		  "Got %d answers and %d additional records\n", ancount, arcount);

	resp_data = rwrap_fake_header(&answer, remaining, ancount, arcount);
	if (resp_data < 0) {
		return -1;
	}
	remaining -= resp_data;

	resp_data += rwrap_fake_question(rrs->key, rrs->type, &answer, remaining);
	if (resp_data < 0) {
		return -1;
	}
	remaining -= resp_data;

	/* answer */
	for (i = 0; i < ancount; i++) {
		rrlen = rwrap_add_rr(&rrs[i], answer, remaining);
		if (rrlen < 0) {
			return -1;
		}
		remaining -= rrlen;
		answer += rrlen;
		resp_data += rrlen;
	}

	/* add authoritative NS here? */

	/* additional records */
	for (i = ancount; i < ancount + arcount; i++) {
		rrlen = rwrap_add_rr(&rrs[i], answer, remaining);
		if (rrlen < 0) {
			return -1;
		}
		remaining -= rrlen;
		answer += rrlen;
		resp_data += rrlen;
	}

	return resp_data;
}

/* Reads in a file in the following format:
 * TYPE RDATA
 *
 * Malformed entries are silently skipped.
 * Allocates answer buffer of size anslen that has to be freed after use.
 */
static int rwrap_res_fake_hosts(const char *hostfile,
				const char *query,
				int type,
				unsigned char *answer,
				size_t anslen)
{
	int rc = ENOENT;
	char *query_name = NULL;
	size_t qlen = strlen(query);
	struct rwrap_fake_rr rrs[RWRAP_MAX_RECURSION];
	ssize_t resp_size;

	RWRAP_LOG(RWRAP_LOG_TRACE,
		  "Searching in fake hosts file %s\n", hostfile);

	if (qlen > 0 && query[qlen-1] == '.') {
		qlen--;
	}

	query_name = strndup(query, qlen);
	if (query_name == NULL) {
		return -1;
	}

	rwrap_fake_rr_init(rrs, RWRAP_MAX_RECURSION);

	rc = rwrap_get_record(hostfile, 0, query_name, type, rrs);
	switch (rc) {
	case 0:
		RWRAP_LOG(RWRAP_LOG_TRACE,
				"Found record for [%s]\n", query_name);
		resp_size = rwrap_fake_answer(rrs, type, answer, anslen);
		break;
	case ENOENT:
		RWRAP_LOG(RWRAP_LOG_TRACE,
				"No record for [%s]\n", query_name);
		resp_size = rwrap_fake_empty(type, rrs->key, answer, anslen);
		break;
	default:
		RWRAP_LOG(RWRAP_LOG_NOTICE,
			  "Searching for [%s] did not return any results\n",
			  query_name);
		free(query_name);
		return -1;
	}

	switch (resp_size) {
	case -1:
		RWRAP_LOG(RWRAP_LOG_ERROR,
				"Error faking answer for [%s]\n", query_name);
		break;
	default:
		RWRAP_LOG(RWRAP_LOG_TRACE,
				"Successfully faked answer for [%s]\n",
				query_name);
		break;
	}

	free(query_name);
	return resp_size;
}

/*********************************************************
 * RWRAP LOADING LIBC FUNCTIONS
 *********************************************************/

#include <dlfcn.h>

typedef int (*__libc_res_ninit)(struct __res_state *state);
typedef int (*__libc___res_ninit)(struct __res_state *state);
typedef void (*__libc_res_nclose)(struct __res_state *state);
typedef void (*__libc___res_nclose)(struct __res_state *state);
typedef int (*__libc_res_nquery)(struct __res_state *state,
				 const char *dname,
				 int class,
				 int type,
				 unsigned char *answer,
				 int anslen);
typedef int (*__libc___res_nquery)(struct __res_state *state,
				   const char *dname,
				   int class,
				   int type,
				   unsigned char *answer,
				   int anslen);
typedef int (*__libc_res_nsearch)(struct __res_state *state,
				  const char *dname,
				  int class,
				  int type,
				  unsigned char *answer,
				  int anslen);
typedef int (*__libc___res_nsearch)(struct __res_state *state,
				    const char *dname,
				    int class,
				    int type,
				    unsigned char *answer,
				    int anslen);

#define RWRAP_SYMBOL_ENTRY(i) \
	union { \
		__libc_##i f; \
		void *obj; \
	} _libc_##i

struct rwrap_libc_symbols {
	RWRAP_SYMBOL_ENTRY(res_ninit);
	RWRAP_SYMBOL_ENTRY(__res_ninit);
	RWRAP_SYMBOL_ENTRY(res_nclose);
	RWRAP_SYMBOL_ENTRY(__res_nclose);
	RWRAP_SYMBOL_ENTRY(res_nquery);
	RWRAP_SYMBOL_ENTRY(__res_nquery);
	RWRAP_SYMBOL_ENTRY(res_nsearch);
	RWRAP_SYMBOL_ENTRY(__res_nsearch);
};
#undef RWRAP_SYMBOL_ENTRY

struct rwrap {
	struct {
		void *handle;
		struct rwrap_libc_symbols symbols;
	} libc;

	struct {
		void *handle;
		struct rwrap_libc_symbols symbols;
	} libresolv;

	bool initialised;
	bool enabled;

	char *socket_dir;
};

static struct rwrap rwrap;

enum rwrap_lib {
    RWRAP_LIBC,
    RWRAP_LIBRESOLV
};

static const char *rwrap_str_lib(enum rwrap_lib lib)
{
	switch (lib) {
	case RWRAP_LIBC:
		return "libc";
	case RWRAP_LIBRESOLV:
		return "libresolv";
	}

	/* Compiler would warn us about unhandled enum value if we get here */
	return "unknown";
}

static void *rwrap_load_lib_handle(enum rwrap_lib lib)
{
	int flags = RTLD_LAZY;
	void *handle = NULL;
	int i;

#ifdef RTLD_DEEPBIND
	const char *env_preload = getenv("LD_PRELOAD");
	const char *env_deepbind = getenv("RESOLV_WRAPPER_DISABLE_DEEPBIND");
	bool enable_deepbind = true;

	/* Don't do a deepbind if we run with libasan */
	if (env_preload != NULL && strlen(env_preload) < 1024) {
		const char *p = strstr(env_preload, "libasan.so");
		if (p != NULL) {
			enable_deepbind = false;
		}
	}

	if (env_deepbind != NULL && strlen(env_deepbind) >= 1) {
		enable_deepbind = false;
	}

	if (enable_deepbind) {
		flags |= RTLD_DEEPBIND;
	}
#endif

	switch (lib) {
	case RWRAP_LIBRESOLV:
#ifdef HAVE_LIBRESOLV
		handle = rwrap.libresolv.handle;
		if (handle == NULL) {
			for (i = 10; i >= 0; i--) {
				char soname[256] = {0};

				snprintf(soname, sizeof(soname), "libresolv.so.%d", i);
				handle = dlopen(soname, flags);
				if (handle != NULL) {
					break;
				}
			}

			rwrap.libresolv.handle = handle;
		}
		break;
#endif
		/* FALL TROUGH */
	case RWRAP_LIBC:
		handle = rwrap.libc.handle;
#ifdef LIBC_SO
		if (handle == NULL) {
			handle = dlopen(LIBC_SO, flags);

			rwrap.libc.handle = handle;
		}
#endif
		if (handle == NULL) {
			for (i = 10; i >= 0; i--) {
				char soname[256] = {0};

				snprintf(soname, sizeof(soname), "libc.so.%d", i);
				handle = dlopen(soname, flags);
				if (handle != NULL) {
					break;
				}
			}

			rwrap.libc.handle = handle;
		}
		break;
	}

	if (handle == NULL) {
#ifdef RTLD_NEXT
		handle = rwrap.libc.handle = rwrap.libresolv.handle = RTLD_NEXT;
#else
		RWRAP_LOG(RWRAP_LOG_ERROR,
			  "Failed to dlopen library: %s\n",
			  dlerror());
		exit(-1);
#endif
	}

	return handle;
}

static void *_rwrap_bind_symbol(enum rwrap_lib lib, const char *fn_name)
{
	void *handle;
	void *func;

	handle = rwrap_load_lib_handle(lib);

	func = dlsym(handle, fn_name);
	if (func == NULL) {
		RWRAP_LOG(RWRAP_LOG_ERROR,
				"Failed to find %s: %s\n",
				fn_name, dlerror());
		exit(-1);
	}

	RWRAP_LOG(RWRAP_LOG_TRACE,
			"Loaded %s from %s",
			fn_name, rwrap_str_lib(lib));
	return func;
}

#define rwrap_bind_symbol_libc(sym_name) \
	if (rwrap.libc.symbols._libc_##sym_name.obj == NULL) { \
		rwrap.libc.symbols._libc_##sym_name.obj = \
			_rwrap_bind_symbol(RWRAP_LIBC, #sym_name); \
	}

#define rwrap_bind_symbol_libresolv(sym_name) \
	if (rwrap.libresolv.symbols._libc_##sym_name.obj == NULL) { \
		rwrap.libresolv.symbols._libc_##sym_name.obj = \
			_rwrap_bind_symbol(RWRAP_LIBRESOLV, #sym_name); \
	}

/*
 * IMPORTANT
 *
 * Functions especially from libc need to be loaded individually, you can't load
 * all at once or gdb will segfault at startup. The same applies to valgrind and
 * has probably something todo with with the linker.
 * So we need load each function at the point it is called the first time.
 */

static int libc_res_ninit(struct __res_state *state)
{
#if !defined(res_ninit) && defined(HAVE_RES_NINIT)
	rwrap_bind_symbol_libresolv(res_ninit);

	return rwrap.libresolv.symbols._libc_res_ninit.f(state);
#elif defined(HAVE___RES_NINIT)
	rwrap_bind_symbol_libresolv(__res_ninit);

	return rwrap.libresolv.symbols._libc___res_ninit.f(state);
#else
#error "No res_ninit function"
#endif
}

static void libc_res_nclose(struct __res_state *state)
{
#if !defined(res_close) && defined(HAVE_RES_NCLOSE)
	rwrap_bind_symbol_libresolv(res_nclose);

	rwrap.libresolv.symbols._libc_res_nclose.f(state);
	return;
#elif defined(HAVE___RES_NCLOSE)
	rwrap_bind_symbol_libresolv(__res_nclose);

	rwrap.libresolv.symbols._libc___res_nclose.f(state);
#else
#error "No res_nclose function"
#endif
}

static int libc_res_nquery(struct __res_state *state,
			   const char *dname,
			   int class,
			   int type,
			   unsigned char *answer,
			   int anslen)
{
#if !defined(res_nquery) && defined(HAVE_RES_NQUERY)
	rwrap_bind_symbol_libresolv(res_nquery);

	return rwrap.libresolv.symbols._libc_res_nquery.f(state,
							  dname,
							  class,
							  type,
							  answer,
							  anslen);
#elif defined(HAVE___RES_NQUERY)
	rwrap_bind_symbol_libresolv(__res_nquery);

	return rwrap.libresolv.symbols._libc___res_nquery.f(state,
							    dname,
							    class,
							    type,
							    answer,
							    anslen);
#else
#error "No res_nquery function"
#endif
}

static int libc_res_nsearch(struct __res_state *state,
			    const char *dname,
			    int class,
			    int type,
			    unsigned char *answer,
			    int anslen)
{
#if !defined(res_nsearch) && defined(HAVE_RES_NSEARCH)
	rwrap_bind_symbol_libresolv(res_nsearch);

	return rwrap.libresolv.symbols._libc_res_nsearch.f(state,
							   dname,
							   class,
							   type,
							   answer,
							   anslen);
#elif defined(HAVE___RES_NSEARCH)
	rwrap_bind_symbol_libresolv(__res_nsearch);

	return rwrap.libresolv.symbols._libc___res_nsearch.f(state,
							     dname,
							     class,
							     type,
							     answer,
							     anslen);
#else
#error "No res_nsearch function"
#endif
}

/****************************************************************************
 *   RES_HELPER
 ***************************************************************************/

static size_t rwrap_get_nameservers(struct __res_state *state,
				    size_t nserv,
				    union rwrap_sockaddr *nsaddrs)
{
#ifdef HAVE_RES_SOCKADDR_UNION_SIN
	union res_sockaddr_union set[MAXNS];
	size_t i;
	int rc;

	memset(set, 0, sizeof(set));
	memset(nsaddrs, 0, sizeof(*nsaddrs) * nserv);

	if (nserv > MAXNS) {
		nserv = MAXNS;
	}

	rc = res_getservers(state, set, nserv);
	if (rc <= 0) {
		return 0;
	}
	if (rc < nserv) {
		nserv = rc;
	}

	for (i = 0; i < nserv; i++) {
		switch (set[i].sin.sin_family) {
		case AF_INET:
			nsaddrs[i] = (union rwrap_sockaddr) {
				.in = set[i].sin,
			};
			break;
#ifdef HAVE_RES_SOCKADDR_UNION_SIN6
		case AF_INET6:
			nsaddrs[i] = (union rwrap_sockaddr) {
				.in6 = set[i].sin6,
			};
			break;
#endif
		}
	}

	return nserv;
#else /* ! HAVE_RES_SOCKADDR_UNION_SIN */
	size_t i;

	memset(nsaddrs, 0, sizeof(*nsaddrs) * nserv);

	if (nserv > (size_t)state->nscount) {
		nserv = (size_t)state->nscount;
	}

	for (i = 0; i < nserv; i++) {
#ifdef HAVE_RES_STATE_U_EXT_NSADDRS
		if (state->_u._ext.nsaddrs[i] != NULL) {
			nsaddrs[i] = (union rwrap_sockaddr) {
				.in6 = *state->_u._ext.nsaddrs[i],
			};
		} else
#endif /* HAVE_RES_STATE_U_EXT_NSADDRS */
		{
			nsaddrs[i] = (union rwrap_sockaddr) {
				.in = state->nsaddr_list[i],
			};
		}
	}

	return nserv;
#endif /* ! HAVE_RES_SOCKADDR_UNION_SIN */
}

static void rwrap_log_nameservers(enum rwrap_dbglvl_e dbglvl,
				  const char *func,
				  struct __res_state *state)
{
	union rwrap_sockaddr nsaddrs[MAXNS];
	size_t nserv = MAXNS;
	size_t i;

	memset(nsaddrs, 0, sizeof(nsaddrs));
	nserv = rwrap_get_nameservers(state, nserv, nsaddrs);
	for (i = 0; i < nserv; i++) {
		char ip[INET6_ADDRSTRLEN];

		switch (nsaddrs[i].sa.sa_family) {
		case AF_INET:
			inet_ntop(AF_INET, &(nsaddrs[i].in.sin_addr),
				  ip, sizeof(ip));
			break;
		case AF_INET6:
			inet_ntop(AF_INET6, &(nsaddrs[i].in6.sin6_addr),
				  ip, sizeof(ip));
			break;
		default:
			snprintf(ip, sizeof(ip), "<unknown sa_family=%d",
				 nsaddrs[i].sa.sa_family);
			break;
		}

		rwrap_log(dbglvl, func,
			  "        nameserver: %s",
			  ip);
	}
}

static void rwrap_reset_nameservers(struct __res_state *state)
{
#ifdef HAVE_RES_SOCKADDR_UNION_SIN
	res_setservers(state, NULL, 0);
#else /* ! HAVE_RES_SOCKADDR_UNION_SIN */
#ifdef HAVE_RES_STATE_U_EXT_NSADDRS
	size_t i;

	for (i = 0; i < (size_t)state->nscount; i++) {
		if (state->_u._ext.nssocks[i] != -1) {
			close(state->_u._ext.nssocks[i]);
			state->_u._ext.nssocks[i] = -1;
		}
		SAFE_FREE(state->_u._ext.nsaddrs[i]);
	}
	memset(&state->_u._ext, 0, sizeof(state->_u._ext));
	for (i = 0; i < MAXNS; i++) {
		state->_u._ext.nssocks[i] = -1;
		state->_u._ext.nsmap[i] = MAXNS + 1;
	}
	state->ipv6_unavail = false;
#endif
	memset(state->nsaddr_list, 0, sizeof(state->nsaddr_list));
	state->nscount = 0;
#endif /* ! HAVE_RES_SOCKADDR_UNION_SIN */
}

static int rwrap_set_nameservers(struct __res_state *state,
				 size_t nserv,
				 const union rwrap_sockaddr *nsaddrs)
{
#ifdef HAVE_RES_SOCKADDR_UNION_SIN
	union res_sockaddr_union set[MAXNS];
	size_t i;

	memset(set, 0, sizeof(set));

	if (nserv > MAXNS) {
		nserv = MAXNS;
	}

	rwrap_reset_nameservers(state);

	for (i = 0; i < nserv; i++) {
		switch (nsaddrs[i].sa.sa_family) {
		case AF_INET:
			set[i] = (union res_sockaddr_union) {
				.sin = nsaddrs[i].in,
			};
			break;
#ifdef HAVE_RES_SOCKADDR_UNION_SIN6
		case AF_INET6:
			set[i] = (union res_sockaddr_union) {
				.sin6 = nsaddrs[i].in6,
			};
			break;
#endif
		default:
			RWRAP_LOG(RWRAP_LOG_ERROR,
				  "Internal error unhandled sa_family=%d",
				  nsaddrs[i].sa.sa_family);
			errno = ENOSYS;
			return -1;
		}
	}

	res_setservers(state, set, nserv);
	return 0;
#else /* ! HAVE_RES_SOCKADDR_UNION_SIN */
	size_t i;

	if (nserv > MAXNS) {
		nserv = MAXNS;
	}
	rwrap_reset_nameservers(state);

	for (i = 0; i < nserv; i++) {
		switch (nsaddrs[i].sa.sa_family) {
		case AF_INET:
			state->nsaddr_list[i] = nsaddrs[i].in;
			break;
#ifdef HAVE_RES_STATE_U_EXT_NSADDRS
		case AF_INET6:
			state->_u._ext.nsaddrs[i] = malloc(sizeof(nsaddrs[i].in6));
			if (state->_u._ext.nsaddrs[i] == NULL) {
				rwrap_reset_nameservers(state);
				errno = ENOMEM;
				return -1;
			}
			*state->_u._ext.nsaddrs[i] = nsaddrs[i].in6;
			state->_u._ext.nssocks[i] = -1;
			state->_u._ext.nsmap[i] = MAXNS + 1;
			state->_u._ext.nscount6++;
			break;
#endif
		default:
			RWRAP_LOG(RWRAP_LOG_ERROR,
				  "Internal error unhandled sa_family=%d",
				  nsaddrs[i].sa.sa_family);
			rwrap_reset_nameservers(state);
			errno = ENOSYS;
			return -1;
		}
	}

	/*
	 * note that state->_u._ext.nscount is left as 0,
	 * this matches glibc and allows resolv wrapper
	 * to work with most (maybe all) glibc versions.
	 */
	state->nscount = i;

	return 0;
#endif /* ! HAVE_RES_SOCKADDR_UNION_SIN */
}

static int rwrap_parse_resolv_conf(struct __res_state *state,
				   const char *resolv_conf)
{
	FILE *fp;
	char buf[BUFSIZ];
	size_t nserv = 0;
	union rwrap_sockaddr nsaddrs[MAXNS];

	memset(nsaddrs, 0, sizeof(nsaddrs));

	fp = fopen(resolv_conf, "r");
	if (fp == NULL) {
		RWRAP_LOG(RWRAP_LOG_WARN,
			  "Opening %s failed: %s",
			  resolv_conf, strerror(errno));
		return -1;
	}

	while(fgets(buf, sizeof(buf), fp) != NULL) {
		char *p;

		/* Ignore comments */
		if (buf[0] == '#' || buf[0] == ';') {
			continue;
		}

		if (RESOLV_MATCH(buf, "nameserver") && nserv < MAXNS) {
			struct in_addr a;
			struct in6_addr a6;
			char *q;
			int ok;

			p = buf + strlen("nameserver");

			/* Skip spaces and tabs */
			while(isblank((int)p[0])) {
				p++;
			}

			q = p;
			while(q[0] != '\n' && q[0] != '\0') {
				q++;
			}
			q[0] = '\0';

			ok = inet_pton(AF_INET, p, &a);
			if (ok) {
				nsaddrs[nserv] = (union rwrap_sockaddr) {
					.in = {
						.sin_family = AF_INET,
						.sin_addr = a,
						.sin_port = htons(53),
						.sin_zero = { 0 },
					},
				};

				nserv++;
				continue;
			}

			ok = inet_pton(AF_INET6, p, &a6);
			if (ok) {
#ifdef HAVE_RESOLV_IPV6_NSADDRS
				nsaddrs[nserv] = (union rwrap_sockaddr) {
					.in6 = {

						.sin6_family = AF_INET6,
						.sin6_port = htons(53),
						.sin6_flowinfo = 0,
						.sin6_addr = a6,
					},
				};
				nserv++;
				continue;
#else /* !HAVE_RESOLV_IPV6_NSADDRS */
				RWRAP_LOG(RWRAP_LOG_WARN,
					  "resolve_wrapper does not support "
					  "IPv6 on this platform");
				continue;
#endif
			}

			RWRAP_LOG(RWRAP_LOG_ERROR, "Malformed DNS server[%s]", p);
			continue;
		} /* TODO: match other keywords */
	}

	if (ferror(fp)) {
		RWRAP_LOG(RWRAP_LOG_ERROR,
			  "Reading from %s failed",
			  resolv_conf);
		fclose(fp);
		return -1;
	}

	fclose(fp);

	if (nserv == 0) {
		RWRAP_LOG(RWRAP_LOG_WARN,
			  "No usable nameservers found in %s",
			  resolv_conf);
		errno = ESRCH;
		return -1;
	}

	return rwrap_set_nameservers(state, nserv, nsaddrs);
}

/****************************************************************************
 *   RES_NINIT
 ***************************************************************************/

static int rwrap_res_ninit(struct __res_state *state)
{
	int rc;

	rc = libc_res_ninit(state);
	if (rc == 0) {
		const char *resolv_conf = getenv("RESOLV_WRAPPER_CONF");

		if (resolv_conf != NULL) {
			rc = rwrap_parse_resolv_conf(state, resolv_conf);
		}
	}

	return rc;
}

#if !defined(res_ninit) && defined(HAVE_RES_NINIT)
int res_ninit(struct __res_state *state)
#elif defined(HAVE___RES_NINIT)
int __res_ninit(struct __res_state *state)
#endif
{
	return rwrap_res_ninit(state);
}

/****************************************************************************
 *   RES_INIT
 ***************************************************************************/

static struct __res_state rwrap_res_state;

static int rwrap_res_init(void)
{
	int rc;

	rc = rwrap_res_ninit(&rwrap_res_state);

	return rc;
}

#if !defined(res_ninit) && defined(HAVE_RES_INIT)
int res_init(void)
#elif defined(HAVE___RES_INIT)
int __res_init(void)
#endif
{
	return rwrap_res_init();
}

/****************************************************************************
 *   RES_NCLOSE
 ***************************************************************************/

static void rwrap_res_nclose(struct __res_state *state)
{
	rwrap_reset_nameservers(state);
	libc_res_nclose(state);
}

#if !defined(res_nclose) && defined(HAVE_RES_NCLOSE)
void res_nclose(struct __res_state *state)
#elif defined(HAVE___RES_NCLOSE)
void __res_nclose(struct __res_state *state)
#endif
{
	rwrap_res_nclose(state);
}

/****************************************************************************
 *   RES_CLOSE
 ***************************************************************************/

static void rwrap_res_close(void)
{
	rwrap_res_nclose(&rwrap_res_state);
}

#if defined(HAVE_RES_CLOSE)
void res_close(void)
#elif defined(HAVE___RES_CLOSE)
void __res_close(void)
#endif
{
	rwrap_res_close();
}

/****************************************************************************
 *   RES_NQUERY
 ***************************************************************************/

static int rwrap_res_nquery(struct __res_state *state,
			    const char *dname,
			    int class,
			    int type,
			    unsigned char *answer,
			    int anslen)
{
	int rc;
	const char *fake_hosts;

	RWRAP_LOG(RWRAP_LOG_TRACE,
		  "Resolve the domain name [%s] - class=%d, type=%d",
		  dname, class, type);
	rwrap_log_nameservers(RWRAP_LOG_TRACE, __func__, state);

	fake_hosts = getenv("RESOLV_WRAPPER_HOSTS");
	if (fake_hosts != NULL) {
		rc = rwrap_res_fake_hosts(fake_hosts, dname, type, answer, anslen);
	} else {
		rc = libc_res_nquery(state, dname, class, type, answer, anslen);
	}


	RWRAP_LOG(RWRAP_LOG_TRACE,
		  "The returned response length is: %d",
		  rc);

	return rc;
}

#if !defined(res_nquery) && defined(HAVE_RES_NQUERY)
int res_nquery(struct __res_state *state,
	       const char *dname,
	       int class,
	       int type,
	       unsigned char *answer,
	       int anslen)
#elif defined(HAVE___RES_NQUERY)
int __res_nquery(struct __res_state *state,
		 const char *dname,
		 int class,
		 int type,
		 unsigned char *answer,
		 int anslen)
#endif
{
	return rwrap_res_nquery(state, dname, class, type, answer, anslen);
}

/****************************************************************************
 *   RES_QUERY
 ***************************************************************************/

static int rwrap_res_query(const char *dname,
			   int class,
			   int type,
			   unsigned char *answer,
			   int anslen)
{
	int rc;

	rc = rwrap_res_ninit(&rwrap_res_state);
	if (rc != 0) {
		return rc;
	}

	rc = rwrap_res_nquery(&rwrap_res_state,
			      dname,
			      class,
			      type,
			      answer,
			      anslen);

	return rc;
}

#if !defined(res_query) && defined(HAVE_RES_QUERY)
int res_query(const char *dname,
	      int class,
	      int type,
	      unsigned char *answer,
	      int anslen)
#elif defined(HAVE___RES_QUERY)
int __res_query(const char *dname,
		int class,
		int type,
		unsigned char *answer,
		int anslen)
#endif
{
	return rwrap_res_query(dname, class, type, answer, anslen);
}

/****************************************************************************
 *   RES_NSEARCH
 ***************************************************************************/

static int rwrap_res_nsearch(struct __res_state *state,
			     const char *dname,
			     int class,
			     int type,
			     unsigned char *answer,
			     int anslen)
{
	int rc;
	const char *fake_hosts;

	RWRAP_LOG(RWRAP_LOG_TRACE,
		  "Resolve the domain name [%s] - class=%d, type=%d",
		  dname, class, type);
	rwrap_log_nameservers(RWRAP_LOG_TRACE, __func__, state);

	fake_hosts = getenv("RESOLV_WRAPPER_HOSTS");
	if (fake_hosts != NULL) {
		rc = rwrap_res_fake_hosts(fake_hosts, dname, type, answer, anslen);
	} else {
		rc = libc_res_nsearch(state, dname, class, type, answer, anslen);
	}

	RWRAP_LOG(RWRAP_LOG_TRACE,
		  "The returned response length is: %d",
		  rc);

	return rc;
}

#if !defined(res_nsearch) && defined(HAVE_RES_NSEARCH)
int res_nsearch(struct __res_state *state,
		const char *dname,
		int class,
		int type,
		unsigned char *answer,
		int anslen)
#elif defined(HAVE___RES_NSEARCH)
int __res_nsearch(struct __res_state *state,
		  const char *dname,
		  int class,
		  int type,
		  unsigned char *answer,
		  int anslen)
#endif
{
	return rwrap_res_nsearch(state, dname, class, type, answer, anslen);
}

/****************************************************************************
 *   RES_SEARCH
 ***************************************************************************/

static int rwrap_res_search(const char *dname,
			    int class,
			    int type,
			    unsigned char *answer,
			    int anslen)
{
	int rc;

	rc = rwrap_res_ninit(&rwrap_res_state);
	if (rc != 0) {
		return rc;
	}

	rc = rwrap_res_nsearch(&rwrap_res_state,
			       dname,
			       class,
			       type,
			       answer,
			       anslen);

	return rc;
}

#if !defined(res_search) && defined(HAVE_RES_SEARCH)
int res_search(const char *dname,
	       int class,
	       int type,
	       unsigned char *answer,
	       int anslen)
#elif defined(HAVE___RES_SEARCH)
int __res_search(const char *dname,
		 int class,
		 int type,
		 unsigned char *answer,
		 int anslen)
#endif
{
	return rwrap_res_search(dname, class, type, answer, anslen);
}
