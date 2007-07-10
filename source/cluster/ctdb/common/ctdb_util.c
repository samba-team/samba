/* 
   ctdb utility code

   Copyright (C) Andrew Tridgell  2006

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "includes.h"
#include "lib/events/events.h"
#include "lib/tdb/include/tdb.h"
#include "system/network.h"
#include "system/filesys.h"
#include "../include/ctdb_private.h"

int LogLevel;

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
	DEBUG(0,("ctdb error: %s\n", ctdb->err_msg));
	va_end(ap);
}

/*
  a fatal internal error occurred - no hope for recovery
*/
_NORETURN_ void ctdb_fatal(struct ctdb_context *ctdb, const char *msg)
{
	DEBUG(0,("ctdb fatal error: %s\n", msg));
	fprintf(stderr, "ctdb fatal error: '%s'\n", msg);
	abort();
}

/*
  parse a IP:port pair
*/
int ctdb_parse_address(struct ctdb_context *ctdb,
		       TALLOC_CTX *mem_ctx, const char *str,
		       struct ctdb_address *address)
{
	char *p;
	p = strchr(str, ':');
	if (p == NULL) {
		ctdb_set_error(ctdb, "Badly formed node '%s'\n", str);
		return -1;
	}
	
	address->address = talloc_strndup(mem_ctx, str, p-str);
	address->port = strtoul(p+1, NULL, 0);
	return 0;
}


/*
  check if two addresses are the same
*/
bool ctdb_same_address(struct ctdb_address *a1, struct ctdb_address *a2)
{
	return strcmp(a1->address, a2->address) == 0 && a1->port == a2->port;
}


/*
  hash function for mapping data to a VNN - taken from tdb
*/
uint32_t ctdb_hash(const TDB_DATA *key)
{
	uint32_t value;	/* Used to compute the hash value.  */
	uint32_t i;	/* Used to cycle through random values. */

	/* Set the initial value from the key size. */
	for (value = 0x238F13AF * key->dsize, i=0; i < key->dsize; i++)
		value = (value + (key->dptr[i] << (i*5 % 24)));

	return (1103515243 * value + 12345);  
}

/*
  a type checking varient of idr_find
 */
void *_idr_find_type(struct idr_context *idp, int id, const char *type, const char *location)
{
	void *p = idr_find(idp, id);
	if (p && talloc_check_name(p, type) == NULL) {
		DEBUG(0,("%s idr_find_type expected type %s  but got %s\n",
			 location, type, talloc_get_name(p)));
		return NULL;
	}
	return p;
}


/*
  update a max latency number
 */
void ctdb_latency(double *latency, struct timeval t)
{
	double l = timeval_elapsed(&t);
	if (l > *latency) {
		*latency = l;
	}
}
