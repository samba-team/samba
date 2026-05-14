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

#include "dns.h"
#include "lib/util/genrand.h"

DNS_ERROR dns_create_query( TALLOC_CTX *mem_ctx, const char *name,
			    uint16_t q_type, uint16_t q_class,
			    struct dns_request **preq )
{
	struct dns_request *req = NULL;
	struct dns_question *q = NULL;
	DNS_ERROR err;

	if (!(req = talloc_zero(mem_ctx, struct dns_request)) ||
	    !(req->questions = talloc_array(req, struct dns_question *, 1)) ||
	    !(req->questions[0] = talloc(req->questions,
					 struct dns_question))) {
		TALLOC_FREE(req);
		return ERROR_DNS_NO_MEMORY;
	}

	generate_random_buffer((uint8_t *)&req->id, sizeof(req->id));

	req->num_questions = 1;
	q = req->questions[0];

	err = dns_domain_name_from_string(q, name, &q->name);
	if (!ERR_DNS_IS_OK(err)) {
		TALLOC_FREE(req);
		return err;
	}

	q->q_type = q_type;
	q->q_class = q_class;

	*preq = req;
	return ERROR_DNS_SUCCESS;
}

DNS_ERROR dns_create_update( TALLOC_CTX *mem_ctx, const char *name,
			     struct dns_update_request **preq )
{
	struct dns_update_request *req = NULL;
	struct dns_zone *z = NULL;
	DNS_ERROR err;

	if (!(req = talloc_zero(mem_ctx, struct dns_update_request)) ||
	    !(req->zones = talloc_array(req, struct dns_zone *, 1)) ||
	    !(req->zones[0] = talloc(req->zones, struct dns_zone))) {
		TALLOC_FREE(req);
		return ERROR_DNS_NO_MEMORY;
	}

	req->id = random();
	req->flags = 0x2800;	/* Dynamic update */

	req->num_zones = 1;
	z = req->zones[0];

	err = dns_domain_name_from_string(z, name, &z->name);
	if (!ERR_DNS_IS_OK(err)) {
		TALLOC_FREE(req);
		return err;
	}

	z->z_type = QTYPE_SOA;
	z->z_class = DNS_CLASS_IN;

	*preq = req;
	return ERROR_DNS_SUCCESS;
}

static DNS_ERROR dns_create_rrec(TALLOC_CTX *mem_ctx, const char *name,
			  uint16_t type, uint16_t r_class, uint32_t ttl,
			  uint16_t data_length, uint8_t *data,
			  struct dns_rrec **prec)
{
	struct dns_rrec *rec = NULL;
	DNS_ERROR err;

	if (!(rec = talloc(mem_ctx, struct dns_rrec))) {
		return ERROR_DNS_NO_MEMORY;
	}

	err = dns_domain_name_from_string(rec, name, &rec->name);
	if (!(ERR_DNS_IS_OK(err))) {
		TALLOC_FREE(rec);
		return err;
	}

	rec->type = type;
	rec->r_class = r_class;
	rec->ttl = ttl;
	rec->data_length = data_length;
	rec->data = talloc_move(rec, &data);

	*prec = rec;
	return ERROR_DNS_SUCCESS;
}

DNS_ERROR dns_create_a_record(TALLOC_CTX *mem_ctx, const char *host,
			      uint32_t ttl, const struct sockaddr_storage *pss,
			      struct dns_rrec **prec)
{
	uint8_t *data;
	DNS_ERROR err;
	struct in_addr ip;

	if (pss->ss_family != AF_INET) {
		return ERROR_DNS_INVALID_PARAMETER;
	}

	ip = ((const struct sockaddr_in *)pss)->sin_addr;
	if (!(data = (uint8_t *)talloc_memdup(mem_ctx, (const void *)&ip.s_addr,
					    sizeof(ip.s_addr)))) {
		return ERROR_DNS_NO_MEMORY;
	}

	err = dns_create_rrec(mem_ctx, host, QTYPE_A, DNS_CLASS_IN, ttl,
			      sizeof(ip.s_addr), data, prec);

	if (!ERR_DNS_IS_OK(err)) {
		TALLOC_FREE(data);
	}

	return err;
}

DNS_ERROR dns_create_aaaa_record(TALLOC_CTX *mem_ctx, const char *host,
				 uint32_t ttl, const struct sockaddr_storage *pss,
				 struct dns_rrec **prec)
{
#ifdef HAVE_IPV6
	uint8_t *data;
	DNS_ERROR err;
	struct in6_addr ip6;

	if (pss->ss_family != AF_INET6) {
		return ERROR_DNS_INVALID_PARAMETER;
	}

	ip6 = ((const struct sockaddr_in6 *)pss)->sin6_addr;
	if (!(data = (uint8_t *)talloc_memdup(mem_ctx, (const void *)&ip6.s6_addr,
					    sizeof(ip6.s6_addr)))) {
		return ERROR_DNS_NO_MEMORY;
	}

	err = dns_create_rrec(mem_ctx, host, QTYPE_AAAA, DNS_CLASS_IN, ttl,
			      sizeof(ip6.s6_addr), data, prec);

	if (!ERR_DNS_IS_OK(err)) {
		TALLOC_FREE(data);
	}

	return err;
#else
	return ERROR_DNS_INVALID_PARAMETER;
#endif
}

DNS_ERROR dns_add_rrec(TALLOC_CTX *mem_ctx, struct dns_rrec *rec,
		       uint16_t *num_records, struct dns_rrec ***records)
{
	struct dns_rrec **new_records;

	if (!(new_records = talloc_realloc(mem_ctx, *records,
						 struct dns_rrec *,
						 (*num_records)+1))) {
		return ERROR_DNS_NO_MEMORY;
	}

	new_records[*num_records] = talloc_move(new_records, &rec);

	*num_records += 1;
	*records = new_records;
	return ERROR_DNS_SUCCESS;
}
