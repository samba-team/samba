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
#include "librpc/gen_ndr/dns.h"

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

#define DNS_TCP_PORT		53
#define DNS_UDP_PORT		53

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

#endif	/* _DNS_H */
