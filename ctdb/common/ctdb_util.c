/* 
   ctdb utility code

   Copyright (C) Andrew Tridgell  2006

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

#include "replace.h"
#include "system/network.h"
#include "system/filesys.h"
#include "system/wait.h"
#include "lib/util/util_file.h"

#include <tdb.h>

#include "lib/util/debug.h"
#include "lib/util/samba_util.h"

#include "ctdb_private.h"

#include "protocol/protocol_util.h"

#include "common/reqid.h"
#include "common/system.h"
#include "common/common.h"
#include "common/logging.h"

/*
  return error string for last error
*/
const char *ctdb_errstr(struct ctdb_context *ctdb)
{
	return ctdb->err_msg;
}


/*
  remember an error message
*/
void ctdb_set_error(struct ctdb_context *ctdb, const char *fmt, ...)
{
	va_list ap;
	talloc_free(ctdb->err_msg);
	va_start(ap, fmt);
	ctdb->err_msg = talloc_vasprintf(ctdb, fmt, ap);
	DEBUG(DEBUG_ERR,("ctdb error: %s\n", ctdb->err_msg));
	va_end(ap);
}

/*
  a fatal internal error occurred - no hope for recovery
*/
void ctdb_fatal(struct ctdb_context *ctdb, const char *msg)
{
	DEBUG(DEBUG_ALERT,("ctdb fatal error: %s\n", msg));
	abort();
}

/*
  like ctdb_fatal() but a core/backtrace would not be useful
*/
void ctdb_die(struct ctdb_context *ctdb, const char *msg)
{
	DEBUG(DEBUG_ALERT,("ctdb exiting with error: %s\n", msg));
	exit(1);
}

/* Set the path of a helper program from envvar, falling back to
 * dir/file if envvar unset. type is a string to print in log
 * messages.  helper is assumed to point to a statically allocated
 * array of size bytes, initialised to "".  If file is NULL don't fall
 * back if envvar is unset.  If dir is NULL and envvar is unset (but
 * file is not NULL) then this is an error.  Returns true if helper is
 * set, either previously or this time. */
bool ctdb_set_helper(const char *type, char *helper, size_t size,
		     const char *envvar,
		     const char *dir, const char *file)
{
	const char *t;
	struct stat st;

	if (helper[0] != '\0') {
		/* Already set */
		return true;
	}

	t = getenv(envvar);
	if (t != NULL) {
		if (strlen(t) >= size) {
			DEBUG(DEBUG_ERR,
			      ("Unable to set %s - path too long\n", type));
			return false;
		}

		strncpy(helper, t, size);
	} else if (file == NULL) {
		return false;
	} else if (dir == NULL) {
			DEBUG(DEBUG_ERR,
			      ("Unable to set %s - dir is NULL\n", type));
		return false;
	} else {
		int ret;

		ret = snprintf(helper, size, "%s/%s", dir, file);
		if (ret < 0 || (size_t)ret >= size) {
			DEBUG(DEBUG_ERR,
			      ("Unable to set %s - path too long\n", type));
			return false;
		}
	}

	if (stat(helper, &st) != 0) {
		DEBUG(DEBUG_ERR,
		      ("Unable to set %s \"%s\" - %s\n",
		       type, helper, strerror(errno)));
		return false;
	}
	if (!(st.st_mode & S_IXUSR)) {
		DEBUG(DEBUG_ERR,
		      ("Unable to set %s \"%s\" - not executable\n",
		       type, helper));
		return false;
	}

	DEBUG(DEBUG_NOTICE,
	      ("Set %s to \"%s\"\n", type, helper));
	return true;
}

/*
  check if two addresses are the same
*/
bool ctdb_same_address(ctdb_sock_addr *a1, ctdb_sock_addr *a2)
{
	return ctdb_same_ip(a1, a2) &&
		ctdb_addr_to_port(a1) == ctdb_addr_to_port(a2);
}


/*
  hash function for mapping data to a VNN - taken from tdb
*/
uint32_t ctdb_hash(const TDB_DATA *key)
{
	return tdb_jenkins_hash(discard_const(key));
}


static uint32_t ctdb_marshall_record_size(TDB_DATA key,
					  struct ctdb_ltdb_header *header,
					  TDB_DATA data)
{
	return offsetof(struct ctdb_rec_data_old, data) + key.dsize +
	       data.dsize + (header ? sizeof(*header) : 0);
}

static void ctdb_marshall_record_copy(struct ctdb_rec_data_old *rec,
				      uint32_t reqid,
				      TDB_DATA key,
				      struct ctdb_ltdb_header *header,
				      TDB_DATA data,
				      uint32_t length)
{
	uint32_t offset;

	rec->length = length;
	rec->reqid = reqid;
	rec->keylen = key.dsize;
	memcpy(&rec->data[0], key.dptr, key.dsize);
	offset = key.dsize;

	if (header) {
		rec->datalen = data.dsize + sizeof(*header);
		memcpy(&rec->data[offset], header, sizeof(*header));
		offset += sizeof(*header);
	} else {
		rec->datalen = data.dsize;
	}
	memcpy(&rec->data[offset], data.dptr, data.dsize);
}

/*
  form a ctdb_rec_data record from a key/data pair
  
  note that header may be NULL. If not NULL then it is included in the data portion
  of the record
 */
struct ctdb_rec_data_old *ctdb_marshall_record(TALLOC_CTX *mem_ctx,
					       uint32_t reqid,
					       TDB_DATA key,
					       struct ctdb_ltdb_header *header,
					       TDB_DATA data)
{
	size_t length;
	struct ctdb_rec_data_old *d;

	length = ctdb_marshall_record_size(key, header, data);

	d = (struct ctdb_rec_data_old *)talloc_size(mem_ctx, length);
	if (d == NULL) {
		return NULL;
	}

	ctdb_marshall_record_copy(d, reqid, key, header, data, length);
	return d;
}


/* helper function for marshalling multiple records */
struct ctdb_marshall_buffer *ctdb_marshall_add(TALLOC_CTX *mem_ctx,
					       struct ctdb_marshall_buffer *m,
					       uint32_t db_id,
					       uint32_t reqid,
					       TDB_DATA key,
					       struct ctdb_ltdb_header *header,
					       TDB_DATA data)
{
	struct ctdb_rec_data_old *r;
	struct ctdb_marshall_buffer *m2;
	uint32_t length, offset;

	length = ctdb_marshall_record_size(key, header, data);

	if (m == NULL) {
		offset = offsetof(struct ctdb_marshall_buffer, data);
		m2 = talloc_zero_size(mem_ctx, offset + length);
	} else {
		offset = talloc_get_size(m);
		m2 = talloc_realloc_size(mem_ctx, m, offset + length);
	}
	if (m2 == NULL) {
		TALLOC_FREE(m);
		return NULL;
	}

	if (m == NULL) {
		m2->db_id = db_id;
	}

	r = (struct ctdb_rec_data_old *)((uint8_t *)m2 + offset);
	ctdb_marshall_record_copy(r, reqid, key, header, data, length);
	m2->count++;

	return m2;
}

/* we've finished marshalling, return a data blob with the marshalled records */
TDB_DATA ctdb_marshall_finish(struct ctdb_marshall_buffer *m)
{
	TDB_DATA data;
	data.dptr = (uint8_t *)m;
	data.dsize = talloc_get_size(m);
	return data;
}

/* 
   loop over a marshalling buffer 
   
     - pass r==NULL to start
     - loop the number of times indicated by m->count
*/
struct ctdb_rec_data_old *ctdb_marshall_loop_next(
				struct ctdb_marshall_buffer *m,
				struct ctdb_rec_data_old *r,
				uint32_t *reqid,
				struct ctdb_ltdb_header *header,
				TDB_DATA *key, TDB_DATA *data)
{
	if (r == NULL) {
		r = (struct ctdb_rec_data_old *)&m->data[0];
	} else {
		r = (struct ctdb_rec_data_old *)(r->length + (uint8_t *)r);
	}

	if (reqid != NULL) {
		*reqid = r->reqid;
	}
	
	if (key != NULL) {
		key->dptr   = &r->data[0];
		key->dsize  = r->keylen;
	}
	if (data != NULL) {
		data->dptr  = &r->data[r->keylen];
		data->dsize = r->datalen;
		if (header != NULL) {
			data->dptr += sizeof(*header);
			data->dsize -= sizeof(*header);
		}
	}

	if (header != NULL) {
		if (r->datalen < sizeof(*header)) {
			return NULL;
		}
		memcpy(header, &r->data[r->keylen], sizeof(*header));
	}

	return r;
}

/*
   This is used to canonicalize a ctdb_sock_addr structure.
*/
void ctdb_canonicalize_ip(const ctdb_sock_addr *ip, ctdb_sock_addr *cip)
{
	ZERO_STRUCTP(cip);

	if (ip->sa.sa_family == AF_INET6) {
		const char prefix[12] = { 0,0,0,0,0,0,0,0,0,0,0xff,0xff };
		if (memcmp(&ip->ip6.sin6_addr, prefix, sizeof(prefix)) == 0) {
			/* Copy IPv4-mapped IPv6 addresses as IPv4 */
			cip->ip.sin_family = AF_INET;
#ifdef HAVE_SOCK_SIN_LEN
			cip->ip.sin_len = sizeof(ctdb_sock_addr);
#endif
			cip->ip.sin_port   = ip->ip6.sin6_port;
			memcpy(&cip->ip.sin_addr,
			       &ip->ip6.sin6_addr.s6_addr[12],
			       sizeof(cip->ip.sin_addr));
		} else {
			cip->ip6.sin6_family = AF_INET6;
#ifdef HAVE_SOCK_SIN6_LEN
			cip->ip6.sin6_len = sizeof(ctdb_sock_addr);
#endif
			cip->ip6.sin6_port   = ip->ip6.sin6_port;
			memcpy(&cip->ip6.sin6_addr,
			       &ip->ip6.sin6_addr,
			       sizeof(cip->ip6.sin6_addr));
		}

		return;
	}

	if (ip->sa.sa_family == AF_INET) {
		cip->ip.sin_family = AF_INET;
#ifdef HAVE_SOCK_SIN_LEN
		cip->ip.sin_len = sizeof(ctdb_sock_addr);
#endif
		cip->ip.sin_port = ip->ip.sin_port;
		memcpy(&cip->ip.sin_addr,
		       &ip->ip.sin_addr,
		       sizeof(ip->ip.sin_addr));

		return;
	}
}

void ctdb_canonicalize_ip_inplace(ctdb_sock_addr *ip)
{
	ctdb_sock_addr tmp;
	ctdb_canonicalize_ip(ip, &tmp);
	memcpy(ip, &tmp, sizeof(tmp));
}

bool ctdb_same_ip(const ctdb_sock_addr *tip1, const ctdb_sock_addr *tip2)
{
	ctdb_sock_addr ip1, ip2;

	ctdb_canonicalize_ip(tip1, &ip1);
	ctdb_canonicalize_ip(tip2, &ip2);
	
	if (ip1.sa.sa_family != ip2.sa.sa_family) {
		return false;
	}

	switch (ip1.sa.sa_family) {
	case AF_INET:
		return ip1.ip.sin_addr.s_addr == ip2.ip.sin_addr.s_addr;
	case AF_INET6:
		return !memcmp(&ip1.ip6.sin6_addr.s6_addr[0],
				&ip2.ip6.sin6_addr.s6_addr[0],
				16);
	default:
		DEBUG(DEBUG_ERR, (__location__ " CRITICAL Can not compare sockaddr structures of type %u\n", ip1.sa.sa_family));
		return false;
	}

	return true;
}

/*
  compare two ctdb_sock_addr structures
 */
bool ctdb_same_sockaddr(const ctdb_sock_addr *ip1, const ctdb_sock_addr *ip2)
{
	return ctdb_same_ip(ip1, ip2) && ip1->ip.sin_port == ip2->ip.sin_port;
}

char *ctdb_addr_to_str(ctdb_sock_addr *addr)
{
	static char cip[128] = "";

	switch (addr->sa.sa_family) {
	case AF_INET:
		inet_ntop(addr->ip.sin_family, &addr->ip.sin_addr, cip, sizeof(cip));
		break;
	case AF_INET6:
		inet_ntop(addr->ip6.sin6_family, &addr->ip6.sin6_addr, cip, sizeof(cip));
		break;
	default:
		DEBUG(DEBUG_ERR, (__location__ " ERROR, unknown family %u\n", addr->sa.sa_family));
	}

	return cip;
}

unsigned ctdb_addr_to_port(ctdb_sock_addr *addr)
{
	switch (addr->sa.sa_family) {
	case AF_INET:
		return ntohs(addr->ip.sin_port);
		break;
	case AF_INET6:
		return ntohs(addr->ip6.sin6_port);
		break;
	default:
		DEBUG(DEBUG_ERR, (__location__ " ERROR, unknown family %u\n", addr->sa.sa_family));
	}

	return 0;
}

struct ctdb_node_map_old *
ctdb_node_list_to_map(struct ctdb_node **nodes, uint32_t num_nodes,
		      TALLOC_CTX *mem_ctx)
{
	uint32_t i;
	size_t size;
	struct ctdb_node_map_old *node_map;

	size = offsetof(struct ctdb_node_map_old, nodes) +
		num_nodes * sizeof(struct ctdb_node_and_flags);
	node_map  = (struct ctdb_node_map_old *)talloc_zero_size(mem_ctx, size);
	if (node_map == NULL) {
		DEBUG(DEBUG_ERR,
		      (__location__ " Failed to allocate nodemap array\n"));
		return NULL;
	}

	node_map->num = num_nodes;
	for (i=0; i<num_nodes; i++) {
		node_map->nodes[i].addr  = nodes[i]->address;
		node_map->nodes[i].pnn   = nodes[i]->pnn;
		node_map->nodes[i].flags = nodes[i]->flags;
	}

	return node_map;
}

/* Runstate handling */
void ctdb_set_runstate(struct ctdb_context *ctdb, enum ctdb_runstate runstate)
{
	DEBUG(DEBUG_NOTICE,("Set runstate to %s (%d)\n",
			    ctdb_runstate_to_string(runstate), runstate));

	if (runstate <= ctdb->runstate) {
		ctdb_fatal(ctdb, "runstate must always increase");
	}

	ctdb->runstate = runstate;
}

/* Convert arbitrary data to 4-byte boundary padded uint32 array */
uint32_t *ctdb_key_to_idkey(TALLOC_CTX *mem_ctx, TDB_DATA key)
{
	uint32_t idkey_size, *k;

	idkey_size = 1 + (key.dsize + sizeof(uint32_t)-1) / sizeof(uint32_t);

	k = talloc_zero_array(mem_ctx, uint32_t, idkey_size);
	if (k == NULL) {
		return NULL;
	}

	k[0] = idkey_size;
	memcpy(&k[1], key.dptr, key.dsize);

	return k;
}
