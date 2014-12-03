/*
 * Copyright (c) 2014      Andreas Schneider <asn@samba.org>
 * Copyright (c) 2014      Jakub Hrozek <jakub.hrozek@gmail.com>
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
#include <netinet/in.h>
#include <sys/types.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

#include <resolv.h>

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

enum rwrap_dbglvl_e {
	RWRAP_LOG_ERROR = 0,
	RWRAP_LOG_WARN,
	RWRAP_LOG_DEBUG,
	RWRAP_LOG_TRACE
};

#ifdef NDEBUG
# define RWRAP_LOG(...)
#else /* NDEBUG */

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
	int pid = getpid();

	d = getenv("RESOLV_WRAPPER_DEBUGLEVEL");
	if (d != NULL) {
		lvl = atoi(d);
	}

	va_start(va, format);
	vsnprintf(buffer, sizeof(buffer), format, va);
	va_end(va);

	if (lvl >= dbglvl) {
		switch (dbglvl) {
			case RWRAP_LOG_ERROR:
				fprintf(stderr,
					"RWRAP_ERROR(%d) - %s: %s\n",
					pid, func, buffer);
				break;
			case RWRAP_LOG_WARN:
				fprintf(stderr,
					"RWRAP_WARN(%d) - %s: %s\n",
					pid, func, buffer);
				break;
			case RWRAP_LOG_DEBUG:
				fprintf(stderr,
					"RWRAP_DEBUG(%d) - %s: %s\n",
					pid, func, buffer);
				break;
			case RWRAP_LOG_TRACE:
				fprintf(stderr,
					"RWRAP_TRACE(%d) - %s: %s\n",
					pid, func, buffer);
				break;
		}
	}
}
#endif /* NDEBUG RWRAP_LOG */

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

/* Priority and weight can be omitted from the hosts file, but need to be part
 * of the output
 */
#define DFL_SRV_PRIO	1
#define DFL_SRV_WEIGHT	100

struct rwrap_srv_rrdata {
	uint16_t port;
	uint16_t prio;
	uint16_t weight;
	char hostname[MAXDNAME];
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
		struct rwrap_soa_rrdata soa_rec;
		char cname_rec[MAXDNAME];
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

/* Prepares a fake header with a single response. Advances header_blob */
static ssize_t rwrap_fake_header(uint8_t **header_blob, size_t remaining,
				 size_t rdata_size)
{
	uint8_t *hb;
	HEADER *h;
	int answers;

	/* If rdata_size is zero, the answer is empty */
	answers = rdata_size > 0 ? 1 : 0;

	if (remaining < NS_HFIXEDSZ) {
		RWRAP_LOG(RWRAP_LOG_ERROR, "Buffer too small!\n");
		return -1;
	}

	hb = *header_blob;
	memset(hb, 0, NS_HFIXEDSZ);

	h = (HEADER *) hb;
	h->id = res_randomid();		/* random query ID */
	h->qr = 1;			/* response flag */
	h->rd = 1;			/* recursion desired */
	h->ra = 1;			/* resursion available */

	h->qdcount = htons(1);		/* no. of questions */
	h->ancount = htons(answers);	/* no. of answers */

	hb += NS_HFIXEDSZ;		/* move past the header */
	*header_blob = hb;

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

static ssize_t rwrap_fake_common(uint16_t type,
				 const char *question,
				 size_t rdata_size,
				 uint8_t **answer_ptr,
				 size_t anslen)
{
	uint8_t *a = *answer_ptr;
	ssize_t written;
	ssize_t total = 0;
	size_t remaining;

	remaining = anslen;

	written = rwrap_fake_header(&a, remaining, rdata_size);
	if (written < 0) {
		return -1;
	}
	total += written;
	remaining -= written;

	written = rwrap_fake_question(question, type, &a, remaining);
	if (written < 0) {
		return -1;
	}
	remaining -= written;
	total += written;

	/* rdata_size = 0 denotes an empty answer */
	if (rdata_size > 0) {
		written = rwrap_fake_rdata_common(type, rdata_size, question,
						remaining, &a);
		if (written < 0) {
			return -1;
		}
		total += written;
	}

	*answer_ptr = a;
	return total;
}

static ssize_t rwrap_fake_a(const char *key,
			    const char *value,
			    uint8_t *answer_ptr,
			    size_t anslen)
{
	uint8_t *a = answer_ptr;
	struct in_addr a_rec;
	ssize_t resp_size;
	int ok;

	if (value == NULL) {
		RWRAP_LOG(RWRAP_LOG_ERROR, "Malformed record, no value!\n");
		return -1;
	}

	resp_size = rwrap_fake_common(ns_t_a, key, sizeof(a_rec), &a, anslen);
	if (resp_size < 0) {
		return -1;
	}

	ok = inet_pton(AF_INET, value, &a_rec);
	if (!ok) {
		RWRAP_LOG(RWRAP_LOG_ERROR,
			  "Failed to convert [%s] to binary\n", value);
		return -1;
	}
	memcpy(a, &a_rec, sizeof(struct in_addr));

	return resp_size;
}

static ssize_t rwrap_fake_aaaa(const char *key,
			       const char *value,
			       uint8_t *answer,
			       size_t anslen)
{
	uint8_t *a = answer;
	struct in6_addr aaaa_rec;
	ssize_t resp_size;
	int ok;

	if (value == NULL) {
		RWRAP_LOG(RWRAP_LOG_ERROR, "Malformed record, no value!\n");
		return -1;
	}

	resp_size = rwrap_fake_common(ns_t_aaaa, key, sizeof(aaaa_rec), &a, anslen);
	if (resp_size < 0) {
		return -1;
	}

	ok = inet_pton(AF_INET6, value, &aaaa_rec);
	if (!ok) {
		RWRAP_LOG(RWRAP_LOG_ERROR,
			  "Failed to convert [%s] to binary\n", value);
		return -1;
	}
	memcpy(a, &aaaa_rec, sizeof(struct in6_addr));

	return resp_size;
}

static ssize_t rwrap_fake_srv(const char *key,
			      const char *value,
			      uint8_t *answer,
			      size_t anslen)
{
	uint8_t *a = answer;
	ssize_t resp_size;
	size_t rdata_size;
	char *str_prio;
	char *str_weight;
	char *str_port;
	const char *hostname;
	unsigned char hostname_compressed[MAXDNAME];
	ssize_t compressed_len;

	/*
	 * Parse the value into priority, weight, port and hostname
	 * and check the validity.
	 */
	hostname = value;
	NEXT_KEY(hostname, str_port);
	NEXT_KEY(str_port, str_prio);
	NEXT_KEY(str_prio, str_weight);
	if (str_port == NULL || hostname == NULL) {
		RWRAP_LOG(RWRAP_LOG_ERROR,
			  "Malformed SRV entry [%s]\n", value);
		return -1;
	}
	rdata_size = 3 * sizeof(uint16_t);

	/* Prepare the data to write */
	compressed_len = ns_name_compress(hostname,
					  hostname_compressed, MAXDNAME,
					  NULL, NULL);
	if (compressed_len < 0) {
		return -1;
	}
	rdata_size += compressed_len;

	resp_size = rwrap_fake_common(ns_t_srv, key, rdata_size, &a, anslen);
	if (resp_size < 0) {
		return -1;
	}

	if (str_prio) {
		NS_PUT16(atoi(str_prio), a);
	} else {
		NS_PUT16(DFL_SRV_PRIO, a);
	}
	if (str_weight) {
		NS_PUT16(atoi(str_weight), a);
	} else {
		NS_PUT16(DFL_SRV_WEIGHT, a);
	}
	NS_PUT16(atoi(str_port), a);
	memcpy(a, hostname_compressed, compressed_len);

	return resp_size;
}

static ssize_t rwrap_fake_soa(const char *key,
			      const char *value,
			      uint8_t *answer,
			      size_t anslen)
{
	uint8_t *a = answer;
	ssize_t resp_size;
	const char *nameserver;
	char *mailbox;
	char *str_serial;
	char *str_refresh;
	char *str_retry;
	char *str_expire;
	char *str_minimum;
	size_t rdata_size;
	unsigned char nameser_compressed[MAXDNAME];
	ssize_t compressed_ns_len;
	unsigned char mailbox_compressed[MAXDNAME];
	ssize_t compressed_mb_len;

	/*
	 * parse the value into nameserver, mailbox, serial, refresh,
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
	    str_minimum == NULL)
	{
		RWRAP_LOG(RWRAP_LOG_ERROR,
			  "Malformed SOA entry [%s]\n", value);
		return -1;
	}
	rdata_size = 5 * sizeof(uint16_t);

	compressed_ns_len = ns_name_compress(nameserver, nameser_compressed,
					     MAXDNAME, NULL, NULL);
	if (compressed_ns_len < 0) {
		return -1;
	}
	rdata_size += compressed_ns_len;

	compressed_mb_len = ns_name_compress(mailbox, mailbox_compressed,
					     MAXDNAME, NULL, NULL);
	if (compressed_mb_len < 0) {
		return -1;
	}
	rdata_size += compressed_mb_len;

	resp_size = rwrap_fake_common(ns_t_soa, key, rdata_size, &a, anslen);
	if (resp_size < 0) {
		return -1;
	}

	memcpy(a, nameser_compressed, compressed_ns_len);
	a += compressed_ns_len;
	memcpy(a, mailbox_compressed, compressed_mb_len);
	a += compressed_mb_len;
	NS_PUT32(atoi(str_serial), a);
	NS_PUT32(atoi(str_refresh), a);
	NS_PUT32(atoi(str_retry), a);
	NS_PUT32(atoi(str_expire), a);
	NS_PUT32(atoi(str_minimum), a);

	return resp_size;
}

static ssize_t rwrap_fake_cname(const char *key,
				const char *value,
				uint8_t *answer,
				size_t anslen)
{
	uint8_t *a = answer;
	ssize_t resp_size;
	unsigned char hostname_compressed[MAXDNAME];
	ssize_t rdata_size;

	if (value == NULL) {
		RWRAP_LOG(RWRAP_LOG_ERROR, "Malformed record, no value!\n");
		return -1;
	}

	/* Prepare the data to write */
	rdata_size = ns_name_compress(value,
				      hostname_compressed, MAXDNAME,
				      NULL, NULL);
	if (rdata_size < 0) {
		return -1;
	}

	resp_size = rwrap_fake_common(ns_t_cname, key, rdata_size, &a, anslen);
	if (resp_size < 0) {
		return -1;
	}

	memcpy(a, hostname_compressed, rdata_size);

	return resp_size;
}

static ssize_t rwrap_fake_empty_query(const char *key,
				      uint16_t type,
				      uint8_t *answer,
				      size_t anslen)
{
	ssize_t resp_size;

	resp_size = rwrap_fake_common(type, key, 0, &answer, anslen);
	if (resp_size < 0) {
		return -1;
	}

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


/* Reads in a file in the following format:
 * TYPE RDATA
 *
 * Malformed entried are silently skipped.
 * Allocates answer buffer of size anslen that has to be freed after use.
 */
static ssize_t rwrap_res_fake_hosts(const char *hostfile,
				    const char *query,
				    int type,
				    unsigned char *answer,
				    size_t anslen)
{
	FILE *fp = NULL;
	char buf[BUFSIZ];
	char *key = NULL;
	char *value = NULL;
	char *query_name = NULL;
	size_t qlen = strlen(query);
	ssize_t resp_size = 0;

	RWRAP_LOG(RWRAP_LOG_TRACE,
		  "Searching in fake hosts file %s\n", hostfile);

	fp = fopen(hostfile, "r");
	if (fp == NULL) {
		RWRAP_LOG(RWRAP_LOG_ERROR,
			  "Opening %s failed: %s",
			  hostfile, strerror(errno));
		return -1;
	}

	if (qlen > 0 && query[qlen-1] == '.') {
		qlen--;
	}

	query_name = strndup(query, qlen);
	if (query_name == NULL) {
		return -1;
	}

	while (fgets(buf, sizeof(buf), fp) != NULL) {
		char *rec_type;
		char *q;

		rec_type = buf;
		key = value = NULL;

		NEXT_KEY(rec_type, key);
		NEXT_KEY(key, value);

		q = value;
		while(q[0] != '\n' && q[0] != '\0') {
			q++;
		}
		q[0] = '\0';

		if (key == NULL || value == NULL) {
			RWRAP_LOG(RWRAP_LOG_WARN,
				"Malformed line: not enough parts, use \"rec_type key data\n"
				"For example \"A cwrap.org 10.10.10.10\"");
			continue;
		}

		if (TYPE_MATCH(type, ns_t_a, rec_type, "A", key, query_name)) {
			resp_size = rwrap_fake_a(key, value, answer, anslen);
			break;
		} else if (TYPE_MATCH(type, ns_t_aaaa,
				      rec_type, "AAAA", key, query_name)) {
			resp_size = rwrap_fake_aaaa(key, value, answer, anslen);
			break;
		} else if (TYPE_MATCH(type, ns_t_srv,
				      rec_type, "SRV", key, query_name)) {
			resp_size = rwrap_fake_srv(key, value, answer, anslen);
			break;
		} else if (TYPE_MATCH(type, ns_t_soa,
				      rec_type, "SOA", key, query_name)) {
			resp_size = rwrap_fake_soa(key, value, answer, anslen);
			break;
		} else if (TYPE_MATCH(type, ns_t_cname,
				      rec_type, "CNAME", key, query_name)) {
			resp_size = rwrap_fake_cname(key, value, answer, anslen);
			break;
		}
	}

	switch (resp_size) {
	case 0:
		RWRAP_LOG(RWRAP_LOG_TRACE,
				"Record for [%s] not found\n", query_name);
		resp_size = rwrap_fake_empty_query(key, type, answer, anslen);
		break;
	case -1:
		RWRAP_LOG(RWRAP_LOG_ERROR,
				"Error faking answer for [%s]\n", query_name);
		break;
	default:
		RWRAP_LOG(RWRAP_LOG_TRACE,
				"Successfully faked answer for [%s]\n", query_name);
		break;
	}

	free(query_name);
	fclose(fp);
	return resp_size;
}

/*********************************************************
 * RWRAP LOADING LIBC FUNCTIONS
 *********************************************************/

#include <dlfcn.h>

struct rwrap_libc_fns {
	int (*libc_res_init)(void);
	int (*libc___res_init)(void);
	int (*libc_res_ninit)(struct __res_state *state);
	int (*libc___res_ninit)(struct __res_state *state);
	void (*libc_res_nclose)(struct __res_state *state);
	void (*libc___res_nclose)(struct __res_state *state);
	void (*libc_res_close)(void);
	void (*libc___res_close)(void);
	int (*libc_res_nquery)(struct __res_state *state,
			       const char *dname,
			       int class,
			       int type,
			       unsigned char *answer,
			       int anslen);
	int (*libc___res_nquery)(struct __res_state *state,
				 const char *dname,
				 int class,
				 int type,
				 unsigned char *answer,
				 int anslen);
	int (*libc_res_nsearch)(struct __res_state *state,
				const char *dname,
				int class,
				int type,
				unsigned char *answer,
				int anslen);
	int (*libc___res_nsearch)(struct __res_state *state,
				  const char *dname,
				  int class,
				  int type,
				  unsigned char *answer,
				  int anslen);
};

struct rwrap {
	void *libc_handle;
	void *libresolv_handle;

	bool initialised;
	bool enabled;

	char *socket_dir;

	struct rwrap_libc_fns fns;
};

static struct rwrap rwrap;

enum rwrap_lib {
    RWRAP_LIBC,
    RWRAP_LIBRESOLV
};

#ifndef NDEBUG
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
#endif

static void *rwrap_load_lib_handle(enum rwrap_lib lib)
{
	int flags = RTLD_LAZY;
	void *handle = NULL;
	int i;

#ifdef RTLD_DEEPBIND
	flags |= RTLD_DEEPBIND;
#endif

	switch (lib) {
	case RWRAP_LIBRESOLV:
#ifdef HAVE_LIBRESOLV
		handle = rwrap.libresolv_handle;
		if (handle == NULL) {
			for (i = 10; i >= 0; i--) {
				char soname[256] = {0};

				snprintf(soname, sizeof(soname), "libresolv.so.%d", i);
				handle = dlopen(soname, flags);
				if (handle != NULL) {
					break;
				}
			}

			rwrap.libresolv_handle = handle;
		}
		break;
#endif
		/* FALL TROUGH */
	case RWRAP_LIBC:
		handle = rwrap.libc_handle;
#ifdef LIBC_SO
		if (handle == NULL) {
			handle = dlopen(LIBC_SO, flags);

			rwrap.libc_handle = handle;
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

			rwrap.libc_handle = handle;
		}
		break;
	}

	if (handle == NULL) {
#ifdef RTLD_NEXT
		handle = rwrap.libc_handle = rwrap.libresolv_handle = RTLD_NEXT;
#else
		RWRAP_LOG(RWRAP_LOG_ERROR,
			  "Failed to dlopen library: %s\n",
			  dlerror());
		exit(-1);
#endif
	}

	return handle;
}

static void *_rwrap_load_lib_function(enum rwrap_lib lib, const char *fn_name)
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

#define rwrap_load_lib_function(lib, fn_name) \
	if (rwrap.fns.libc_##fn_name == NULL) { \
		*(void **) (&rwrap.fns.libc_##fn_name) = \
			_rwrap_load_lib_function(lib, #fn_name); \
	}

/*
 * IMPORTANT
 *
 * Functions especially from libc need to be loaded individually, you can't load
 * all at once or gdb will segfault at startup. The same applies to valgrind and
 * has probably something todo with with the linker.
 * So we need load each function at the point it is called the first time.
 */
#if 0
static int libc_res_init(void)
{
#if defined(HAVE_RES_INIT)
	rwrap_load_lib_function(RWRAP_LIBRESOLV, res_init);

	return rwrap.fns.libc_res_init();
#elif defined(HAVE___RES_INIT)
	rwrap_load_lib_function(RWRAP_LIBRESOLV, __res_init);

	return rwrap.fns.libc___res_init();
#endif
}
#endif

static int libc_res_ninit(struct __res_state *state)
{
#if defined(HAVE_RES_NINIT)

#if defined(HAVE_RES_NINIT_IN_LIBRESOLV)
	rwrap_load_lib_function(RWRAP_LIBRESOLV, res_ninit);
#else /* HAVE_RES_NINIT_IN_LIBRESOLV */
	rwrap_load_lib_function(RWRAP_LIBC, res_ninit);
#endif /* HAVE_RES_NINIT_IN_LIBRESOLV */

	return rwrap.fns.libc_res_ninit(state);
#elif defined(HAVE___RES_NINIT)
	rwrap_load_lib_function(RWRAP_LIBC, __res_ninit);

	return rwrap.fns.libc___res_ninit(state);
#else
#error "No res_ninit function"
#endif
}

static void libc_res_nclose(struct __res_state *state)
{
#if defined(HAVE_RES_NCLOSE)

#if defined(HAVE_RES_NCLOSE_IN_LIBRESOLV)
	rwrap_load_lib_function(RWRAP_LIBRESOLV, res_nclose);
#else /* HAVE_RES_NCLOSE_IN_LIBRESOLV */
	rwrap_load_lib_function(RWRAP_LIBC, res_nclose);
#endif /* HAVE_RES_NCLOSE_IN_LIBRESOLV */

	rwrap.fns.libc_res_nclose(state);
#elif defined(HAVE___RES_NCLOSE)
	rwrap_load_lib_function(RWRAP_LIBC, __res_nclose);

	rwrap.fns.libc___res_nclose(state);
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
#if defined(HAVE_RES_NQUERY)
	rwrap_load_lib_function(RWRAP_LIBRESOLV, res_nquery);

	return rwrap.fns.libc_res_nquery(state,
					 dname,
					 class,
					 type,
					 answer,
					 anslen);
#elif defined(HAVE___RES_NQUERY)
	rwrap_load_lib_function(RWRAP_LIBRESOLV, __res_nquery);

	return rwrap.fns.libc___res_nquery(state,
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
#if defined(HAVE_RES_NSEARCH)
	rwrap_load_lib_function(RWRAP_LIBRESOLV, res_nsearch);

	return rwrap.fns.libc_res_nsearch(state,
					  dname,
					  class,
					  type,
					  answer,
					  anslen);
#elif defined(HAVE___RES_NSEARCH)
	rwrap_load_lib_function(RWRAP_LIBRESOLV, __res_nsearch);

	return rwrap.fns.libc___res_nsearch(state,
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

static int rwrap_parse_resolv_conf(struct __res_state *state,
				   const char *resolv_conf)
{
	FILE *fp;
	char buf[BUFSIZ];
	int nserv = 0;

	fp = fopen(resolv_conf, "r");
	if (fp == NULL) {
		RWRAP_LOG(RWRAP_LOG_ERROR,
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
				state->nsaddr_list[state->nscount] = (struct sockaddr_in) {
					.sin_family = AF_INET,
					.sin_addr = a,
					.sin_port = htons(53),
					.sin_zero = { 0 },
				};

				state->nscount++;
				nserv++;
			} else {
#ifdef HAVE_RESOLV_IPV6_NSADDRS
				/* IPv6 */
				struct in6_addr a6;
				ok = inet_pton(AF_INET6, p, &a6);
				if (ok) {
					struct sockaddr_in6 *sa6;

					sa6 = malloc(sizeof(*sa6));
					if (sa6 == NULL) {
						fclose(fp);
						return -1;
					}

					sa6->sin6_family = AF_INET6;
					sa6->sin6_port = htons(53);
					sa6->sin6_flowinfo = 0;
					sa6->sin6_addr = a6;

					state->_u._ext.nsaddrs[state->_u._ext.nscount] = sa6;
					state->_u._ext.nssocks[state->_u._ext.nscount] = -1;
					state->_u._ext.nsmap[state->_u._ext.nscount] = MAXNS + 1;

					state->_u._ext.nscount++;
					nserv++;
				} else {
					RWRAP_LOG(RWRAP_LOG_ERROR,
						"Malformed DNS server");
					continue;
				}
#else /* !HAVE_RESOLV_IPV6_NSADDRS */
				/*
				 * BSD uses an opaque structure to store the
				 * IPv6 addresses. So we can not simply store
				 * these addresses the same way as above.
				 */
				RWRAP_LOG(RWRAP_LOG_WARN,
					  "resolve_wrapper does not support "
					  "IPv6 on this platform");
					continue;
#endif
			}
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
	return 0;
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
			uint16_t i;

			(void)i; /* maybe unused */

			/* Delete name servers */
			state->nscount = 0;
			memset(state->nsaddr_list, 0, sizeof(state->nsaddr_list));

			state->_u._ext.nscount = 0;
#ifdef HAVE_RESOLV_IPV6_NSADDRS
			for (i = 0; i < state->_u._ext.nscount; i++) {
				SAFE_FREE(state->_u._ext.nsaddrs[i]);
			}
#endif

			rc = rwrap_parse_resolv_conf(state, resolv_conf);
		}
	}

	return rc;
}

#if defined(HAVE_RES_NINIT)
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

#if defined(HAVE_RES_INIT)
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
#ifdef HAVE_RESOLV_IPV6_NSADDRS
	int i;
#endif

	libc_res_nclose(state);

#ifdef HAVE_RESOLV_IPV6_NSADDRS
	if (state != NULL) {
		for (i = 0; i < state->_u._ext.nscount; i++) {
			SAFE_FREE(state->_u._ext.nsaddrs[i]);
		}
	}
#endif
}

#if defined(HAVE_RES_NCLOSE)
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
#ifndef NDEBUG
	int i;
#endif

	RWRAP_LOG(RWRAP_LOG_TRACE,
		  "Resolve the domain name [%s] - class=%d, type=%d",
		  dname, class, type);
#ifndef NDEBUG
	for (i = 0; i < state->nscount; i++) {
		char ip[INET6_ADDRSTRLEN];

		inet_ntop(AF_INET, &state->nsaddr_list[i].sin_addr, ip, sizeof(ip));
		RWRAP_LOG(RWRAP_LOG_TRACE,
			  "        nameserver: %s",
			  ip);
	}
#endif

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

#if defined(HAVE_RES_NQUERY)
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

#if defined(HAVE_RES_QUERY)
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
#ifndef NDEBUG
	int i;
#endif

	RWRAP_LOG(RWRAP_LOG_TRACE,
		  "Resolve the domain name [%s] - class=%d, type=%d",
		  dname, class, type);
#ifndef NDEBUG
	for (i = 0; i < state->nscount; i++) {
		char ip[INET6_ADDRSTRLEN];

		inet_ntop(AF_INET, &state->nsaddr_list[i].sin_addr, ip, sizeof(ip));
		RWRAP_LOG(RWRAP_LOG_TRACE,
			  "        nameserver: %s",
			  ip);
	}
#endif

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

#if defined(HAVE_RES_NSEARCH)
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
 *   RES_QUERY
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

#if defined(HAVE_RES_SEARCH)
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
