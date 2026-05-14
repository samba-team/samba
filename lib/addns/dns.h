/*
  Linux DNS client library implementation

  Copyright (C) 2006 Krishna Ganugapati <krishnag@centeris.com>
  Copyright (C) 2006 Gerald Carter <jerry@samba.org>

     ** NOTE! The following LGPL license applies to the libaddns
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _DNS_H
#define _DNS_H

#include "../replace/replace.h"
#include "system/network.h"

/* make sure we have included the correct config.h */
#ifndef NO_CONFIG_H /* for some tests */
#ifndef CONFIG_H_IS_FROM_SAMBA
#error "make sure you have removed all config.h files from standalone builds!"
#error "the included config.h isn't from samba!"
#endif
#endif /* NO_CONFIG_H */

#include <fcntl.h>
#include <time.h>
#include <netdb.h>

#include <talloc.h>

#include "dnserr.h"


#define DNS_TCP			1
#define DNS_UDP			2

/* DNS Class Types */

#define DNS_CLASS_IN		1
#define DNS_CLASS_ANY		255
#define DNS_CLASS_NONE		254

#define DNS_TCP_PORT		53
#define DNS_UDP_PORT		53

#define QTYPE_A         1
#define QTYPE_NS        2
#define QTYPE_MD        3
#define QTYPE_CNAME	5
#define QTYPE_SOA	6
#define QTYPE_AAAA	28
#define QTYPE_ANY	255
#define	QTYPE_TKEY	249
#define QTYPE_TSIG	250

/*
MF              4 a mail forwarder (Obsolete - use MX)
CNAME           5 the canonical name for an alias
SOA             6 marks the start of a zone of authority
MB              7 a mailbox domain name (EXPERIMENTAL)
MG              8 a mail group member (EXPERIMENTAL)
MR              9 a mail rename domain name (EXPERIMENTAL)
NULL            10 a null RR (EXPERIMENTAL)
WKS             11 a well known service description
PTR             12 a domain name pointer
HINFO           13 host information
MINFO           14 mailbox or mail list information
MX              15 mail exchange
TXT             16 text strings
*/

#define  DNS_NO_ERROR		0
#define  DNS_FORMAT_ERROR	1
#define  DNS_SERVER_FAILURE	2
#define  DNS_NAME_ERROR		3
#define  DNS_NOT_IMPLEMENTED	4
#define  DNS_REFUSED		5

enum dns_ServerType { DNS_SRV_ANY, DNS_SRV_WIN2000, DNS_SRV_WIN2003 };

struct dns_domain_label {
	struct dns_domain_label *next;
	char *label;
	size_t len;
};

struct dns_domain_name {
	struct dns_domain_label *pLabelList;
};

struct dns_question {
	struct dns_domain_name *name;
	uint16_t q_type;
	uint16_t q_class;
};

/*
 * Before changing the definition of dns_zone, look
 * dns_marshall_update_request(), we rely on this being the same as
 * dns_question right now.
 */

struct dns_zone {
	struct dns_domain_name *name;
	uint16_t z_type;
	uint16_t z_class;
};

struct dns_rrec {
	struct dns_domain_name *name;
	uint16_t type;
	uint16_t r_class;
	uint32_t ttl;
	uint16_t data_length;
	uint8_t *data;
};

struct dns_request {
	uint16_t id;
	uint16_t flags;
	uint16_t num_questions;
	uint16_t num_answers;
	uint16_t num_auths;
	uint16_t num_additionals;
	struct dns_question **questions;
	struct dns_rrec **answers;
	struct dns_rrec **auths;
	struct dns_rrec **additional;
};

/*
 * Before changing the definition of dns_update_request, look
 * dns_marshall_update_request(), we rely on this being the same as
 * dns_request right now.
 */

struct dns_update_request {
	uint16_t id;
	uint16_t flags;
	uint16_t num_zones;
	uint16_t num_preqs;
	uint16_t num_updates;
	uint16_t num_additionals;
	struct dns_zone **zones;
	struct dns_rrec **preqs;
	struct dns_rrec **updates;
	struct dns_rrec **additional;
};

struct dns_connection {
	int32_t hType;
	int s;
	struct sockaddr_storage RecvAddr;
};

struct dns_buffer {
	uint8_t *data;
	size_t size;
	size_t offset;
	DNS_ERROR error;
};

/* from dnsutils.c */

DNS_ERROR dns_domain_name_from_string( TALLOC_CTX *mem_ctx,
				       const char *pszDomainName,
				       struct dns_domain_name **presult );
char *dns_generate_keyname( TALLOC_CTX *mem_ctx );

/* from dnsrecord.c */

DNS_ERROR dns_create_query( TALLOC_CTX *mem_ctx, const char *name,
			    uint16_t q_type, uint16_t q_class,
			    struct dns_request **preq );
DNS_ERROR dns_create_update( TALLOC_CTX *mem_ctx, const char *name,
			     struct dns_update_request **preq );
DNS_ERROR dns_add_rrec(TALLOC_CTX *mem_ctx, struct dns_rrec *rec,
		       uint16_t *num_records, struct dns_rrec ***records);
DNS_ERROR dns_create_a_record(TALLOC_CTX *mem_ctx, const char *host,
			      uint32_t ttl, const struct sockaddr_storage *pss,
			      struct dns_rrec **prec);
DNS_ERROR dns_create_aaaa_record(TALLOC_CTX *mem_ctx, const char *host,
				 uint32_t ttl, const struct sockaddr_storage *pss,
				 struct dns_rrec **prec);

/* from dnssock.c */

DNS_ERROR dns_open_connection( const char *nameserver, int32_t dwType,
		    TALLOC_CTX *mem_ctx,
		    struct dns_connection **conn );
DNS_ERROR dns_transaction(TALLOC_CTX *mem_ctx, struct dns_connection *conn,
			  const struct dns_request *req,
			  struct dns_request **resp);
DNS_ERROR dns_update_transaction(TALLOC_CTX *mem_ctx,
				 struct dns_connection *conn,
				 struct dns_update_request *up_req,
				 struct dns_update_request **up_resp);

/* from dnsmarshall.c */

DNS_ERROR dns_marshall_request(TALLOC_CTX *mem_ctx,
			       const struct dns_request *req,
			       struct dns_buffer **pbuf);
DNS_ERROR dns_unmarshall_request(TALLOC_CTX *mem_ctx,
				 struct dns_buffer *buf,
				 struct dns_request **preq);
struct dns_request *dns_update2request(struct dns_update_request *update);
struct dns_update_request *dns_request2update(struct dns_request *request);
uint16_t dns_response_code(uint16_t flags);
const char *dns_errstr(DNS_ERROR err);

/* from dnsgss.c */

struct gensec_security;

DNS_ERROR dns_negotiate_sec_ctx(const char *serveraddress,
				const char *keyname,
				struct gensec_security *gensec,
				enum dns_ServerType srv_type);

#endif	/* _DNS_H */
