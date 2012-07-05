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

	req->id = random();

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

DNS_ERROR dns_create_rrec(TALLOC_CTX *mem_ctx, const char *name,
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

DNS_ERROR dns_create_name_in_use_record(TALLOC_CTX *mem_ctx,
					const char *name,
					const struct sockaddr_storage *ss,
					struct dns_rrec **prec)
{
	if (ss != NULL) {
		switch (ss->ss_family) {
		case AF_INET:
			return dns_create_a_record(mem_ctx, name, 0, ss, prec);
#ifdef HAVE_IPV6
		case AF_INET6:
			return dns_create_aaaa_record(mem_ctx, name, 0, ss, prec);
#endif
		default:
			return ERROR_DNS_INVALID_PARAMETER;
		}
	}

	return dns_create_rrec(mem_ctx, name, QTYPE_ANY, DNS_CLASS_IN, 0, 0,
			       NULL, prec);
}

DNS_ERROR dns_create_name_not_in_use_record(TALLOC_CTX *mem_ctx,
					    const char *name, uint32_t type,
					    struct dns_rrec **prec)
{
	return dns_create_rrec(mem_ctx, name, type, DNS_CLASS_NONE, 0,
			       0, NULL, prec);
}

DNS_ERROR dns_create_delete_record(TALLOC_CTX *mem_ctx, const char *name,
				   uint16_t type, uint16_t r_class,
				   struct dns_rrec **prec)
{
	return dns_create_rrec(mem_ctx, name, type, r_class, 0, 0, NULL, prec);
}

DNS_ERROR dns_create_tkey_record(TALLOC_CTX *mem_ctx, const char *keyname,
				 const char *algorithm_name, time_t inception,
				 time_t expiration, uint16_t mode, uint16_t error,
				 uint16_t key_length, const uint8_t *key,
				 struct dns_rrec **prec)
{
	struct dns_buffer *buf = NULL;
	struct dns_domain_name *algorithm = NULL;
	DNS_ERROR err;

	if (!(buf = dns_create_buffer(mem_ctx))) {
		return ERROR_DNS_NO_MEMORY;
	}

	err = dns_domain_name_from_string(buf, algorithm_name, &algorithm);
	if (!ERR_DNS_IS_OK(err)) goto error;

	dns_marshall_domain_name(buf, algorithm);
	dns_marshall_uint32(buf, inception);
	dns_marshall_uint32(buf, expiration);
	dns_marshall_uint16(buf, mode);
	dns_marshall_uint16(buf, error);
	dns_marshall_uint16(buf, key_length);
	dns_marshall_buffer(buf, key, key_length);
	dns_marshall_uint16(buf, 0); /* Other Size */

	if (!ERR_DNS_IS_OK(buf->error)) {
		err = buf->error;
		goto error;
	}

	err = dns_create_rrec(mem_ctx, keyname, QTYPE_TKEY, DNS_CLASS_ANY, 0,
			      buf->offset, buf->data, prec);

 error:
	TALLOC_FREE(buf);
	return err;
}

DNS_ERROR dns_unmarshall_tkey_record(TALLOC_CTX *mem_ctx, struct dns_rrec *rec,
				     struct dns_tkey_record **ptkey)
{
	struct dns_tkey_record *tkey;
	struct dns_buffer buf;
	uint32_t tmp_inception, tmp_expiration;
	
	if (!(tkey = talloc(mem_ctx, struct dns_tkey_record))) {
		return ERROR_DNS_NO_MEMORY;
	}

	buf.data = rec->data;
	buf.size = rec->data_length;
	buf.offset = 0;
	buf.error = ERROR_DNS_SUCCESS;

	dns_unmarshall_domain_name(tkey, &buf, &tkey->algorithm);
	dns_unmarshall_uint32(&buf, &tmp_inception);
	dns_unmarshall_uint32(&buf, &tmp_expiration);
	dns_unmarshall_uint16(&buf, &tkey->mode);
	dns_unmarshall_uint16(&buf, &tkey->error);
	dns_unmarshall_uint16(&buf, &tkey->key_length);

	if (!ERR_DNS_IS_OK(buf.error)) goto error;

	if (tkey->key_length) {
		if (!(tkey->key = talloc_array(tkey, uint8_t, tkey->key_length))) {
			buf.error = ERROR_DNS_NO_MEMORY;
			goto error;
		}
	} else {
		tkey->key = NULL;
	}

	dns_unmarshall_buffer(&buf, tkey->key, tkey->key_length);
	if (!ERR_DNS_IS_OK(buf.error)) goto error;

	tkey->inception = (time_t)tmp_inception;
	tkey->expiration = (time_t)tmp_expiration;

	*ptkey = tkey;
	return ERROR_DNS_SUCCESS;

 error:
	TALLOC_FREE(tkey);
	return buf.error;
}

DNS_ERROR dns_create_tsig_record(TALLOC_CTX *mem_ctx, const char *keyname,
				 const char *algorithm_name,
				 time_t time_signed, uint16_t fudge,
				 uint16_t mac_length, const uint8_t *mac,
				 uint16_t original_id, uint16_t error,
				 struct dns_rrec **prec)
{
	struct dns_buffer *buf = NULL;
	struct dns_domain_name *algorithm = NULL;
	DNS_ERROR err;

	if (!(buf = dns_create_buffer(mem_ctx))) {
		return ERROR_DNS_NO_MEMORY;
	}

	err = dns_domain_name_from_string(buf, algorithm_name, &algorithm);
	if (!ERR_DNS_IS_OK(err)) goto error;

	dns_marshall_domain_name(buf, algorithm);
	dns_marshall_uint16(buf, 0); /* time prefix */
	dns_marshall_uint32(buf, time_signed);
	dns_marshall_uint16(buf, fudge);
	dns_marshall_uint16(buf, mac_length);
	dns_marshall_buffer(buf, mac, mac_length);
	dns_marshall_uint16(buf, original_id);
	dns_marshall_uint16(buf, error);
	dns_marshall_uint16(buf, 0); /* Other Size */

	if (!ERR_DNS_IS_OK(buf->error)) {
		err = buf->error;
		goto error;
	}

	err = dns_create_rrec(mem_ctx, keyname, QTYPE_TSIG, DNS_CLASS_ANY, 0,
			      buf->offset, buf->data, prec);

 error:
	TALLOC_FREE(buf);
	return err;
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

/*
 * Create a request that probes a server whether the list of IP addresses
 * provides meets our expectations
 */

DNS_ERROR dns_create_probe(TALLOC_CTX *mem_ctx, const char *zone,
			   const char *host, int num_ips,
			   const struct sockaddr_storage *sslist,
			   struct dns_update_request **preq)
{
	struct dns_update_request *req = NULL;
	struct dns_rrec *rec = NULL;
	DNS_ERROR err;
	uint16_t i;

	err = dns_create_update(mem_ctx, zone, &req);
	if (!ERR_DNS_IS_OK(err)) return err;

	err = dns_create_name_not_in_use_record(req, host, QTYPE_CNAME,	&rec);
	if (!ERR_DNS_IS_OK(err)) goto error;

	err = dns_add_rrec(req, rec, &req->num_preqs, &req->preqs);
	if (!ERR_DNS_IS_OK(err)) goto error;

	for (i=0; i<num_ips; i++) {
		err = dns_create_name_in_use_record(req, host,
						    &sslist[i], &rec);
		if (!ERR_DNS_IS_OK(err)) goto error;

		err = dns_add_rrec(req, rec, &req->num_preqs, &req->preqs);
		if (!ERR_DNS_IS_OK(err)) goto error;
	}

	*preq = req;
	return ERROR_DNS_SUCCESS;

 error:
	TALLOC_FREE(req);
	return err;
}
			   
DNS_ERROR dns_create_update_request(TALLOC_CTX *mem_ctx,
				    const char *domainname,
				    const char *hostname,
				    const struct sockaddr_storage *ss_addrs,
				    size_t num_addrs,
				    struct dns_update_request **preq)
{
	struct dns_update_request *req = NULL;
	struct dns_rrec *rec = NULL;
	DNS_ERROR err;
	size_t i;

	err = dns_create_update(mem_ctx, domainname, &req);
	if (!ERR_DNS_IS_OK(err)) return err;

	/*
	 * Use the same prereq as WinXP -- No CNAME records for this host.
	 */

	err = dns_create_rrec(req, hostname, QTYPE_CNAME, DNS_CLASS_NONE,
			      0, 0, NULL, &rec);
	if (!ERR_DNS_IS_OK(err)) goto error;

	err = dns_add_rrec(req, rec, &req->num_preqs, &req->preqs);
	if (!ERR_DNS_IS_OK(err)) goto error;

	/*
	 * Delete any existing A records
	 */

	err = dns_create_delete_record(req, hostname, QTYPE_A, DNS_CLASS_ANY,
				       &rec);
	if (!ERR_DNS_IS_OK(err)) goto error;

	err = dns_add_rrec(req, rec, &req->num_updates, &req->updates);
	if (!ERR_DNS_IS_OK(err)) goto error;

	/*
	 * .. and add our IPs
	 */

	for ( i=0; i<num_addrs; i++ ) {

		switch(ss_addrs[i].ss_family) {
		case AF_INET:
			err = dns_create_a_record(req, hostname, 3600, &ss_addrs[i], &rec);
			break;
#ifdef HAVE_IPV6
		case AF_INET6:
			err = dns_create_aaaa_record(req, hostname, 3600, &ss_addrs[i], &rec);
			break;
#endif
		default:
			continue;
		}
		if (!ERR_DNS_IS_OK(err))
			goto error;

		err = dns_add_rrec(req, rec, &req->num_updates, &req->updates);
		if (!ERR_DNS_IS_OK(err))
			goto error;
	}

	*preq = req;
	return ERROR_DNS_SUCCESS;

 error:
	TALLOC_FREE(req);
	return err;
}
