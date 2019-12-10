/*
   Unix SMB/CIFS implementation.

   DNS Server

   Copyright (C) Amitay Isaacs 2011

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "dnsserver.h"
#include "dns_server/dnsserver_common.h"
#include "lib/replace/system/network.h"
#include "librpc/gen_ndr/ndr_dnsp.h"
#include "librpc/gen_ndr/ndr_dnsserver.h"


struct IP4_ARRAY *ip4_array_copy(TALLOC_CTX *mem_ctx, struct IP4_ARRAY *ip4)
{
	struct IP4_ARRAY *ret;

	if (!ip4) {
		return NULL;
	}

	ret = talloc_zero(mem_ctx, struct IP4_ARRAY);
	if (!ret) {
		return ret;
	}

	ret->AddrCount = ip4->AddrCount;
	if (ip4->AddrCount > 0) {
		ret->AddrArray = talloc_zero_array(mem_ctx, unsigned int, ip4->AddrCount);
		if (ret->AddrArray) {
			memcpy(ret->AddrArray, ip4->AddrArray,
				sizeof(unsigned int) * ip4->AddrCount);
		} else {
			talloc_free(ret);
			return NULL;
		}
	}
	return ret;
}


struct DNS_ADDR_ARRAY *ip4_array_to_dns_addr_array(TALLOC_CTX *mem_ctx,
							struct IP4_ARRAY *ip4)
{
	struct DNS_ADDR_ARRAY *ret;
	int i;

	if (!ip4) {
		return NULL;
	}

	ret = talloc_zero(mem_ctx, struct DNS_ADDR_ARRAY);
	if (!ret) {
		return ret;
	}

	ret->MaxCount = ip4->AddrCount;
	ret->AddrCount = ip4->AddrCount;
	ret->Family = AF_INET;
	if (ip4->AddrCount > 0) {
		ret->AddrArray = talloc_zero_array(mem_ctx, struct DNS_ADDR, ip4->AddrCount);
		if (ret->AddrArray) {
			for (i=0; i<ip4->AddrCount; i++) {
				ret->AddrArray[i].MaxSa[0] = 0x02;
				ret->AddrArray[i].MaxSa[3] = 53;
				memcpy(&ret->AddrArray[i].MaxSa[4], ip4->AddrArray,
					sizeof(unsigned int));
				ret->AddrArray[i].DnsAddrUserDword[0] = 6;
			}

		} else {
			talloc_free(ret);
			return NULL;
		}
	}
	return ret;
}

struct IP4_ARRAY *dns_addr_array_to_ip4_array(TALLOC_CTX *mem_ctx,
					      struct DNS_ADDR_ARRAY *ip)
{
	struct IP4_ARRAY *ret;
	size_t i, count, curr;

	if (ip == NULL) {
		return NULL;
	}
	/* We must only return IPv4 addresses.
	   The passed DNS_ADDR_ARRAY may contain:
	   - only ipv4 addresses
	   - only ipv6 addresses
	   - a mixture of both
	   - an empty array
	*/
	ret = talloc_zero(mem_ctx, struct IP4_ARRAY);
	if (!ret) {
		return ret;
	}
	if (ip->AddrCount == 0 || ip->Family == AF_INET6) {
		ret->AddrCount = 0;
		return ret;
	}
	/* Now only ipv4 addresses or a mixture are left */
	count = 0;
	for (i = 0; i < ip->AddrCount; i++) {
		if (ip->AddrArray[i].MaxSa[0] == 0x02) {
			/* Is ipv4 */
			count++;
		}
	}
	if (count == 0) {
		/* should not happen */
		ret->AddrCount = 0;
		return ret;
	}
	ret->AddrArray = talloc_zero_array(mem_ctx, uint32_t, count);
	if (ret->AddrArray) {
		curr = 0;
		for (i = 0; i < ip->AddrCount; i++) {
			if (ip->AddrArray[i].MaxSa[0] == 0x02) {
				/* Is ipv4 */
				memcpy(&ret->AddrArray[curr],
				       &ip->AddrArray[i].MaxSa[4],
				       sizeof(uint32_t));
				curr++;
			}
		}
	} else {
		talloc_free(ret);
		return NULL;
	}
	ret->AddrCount = curr;
	return ret;
}

struct DNS_ADDR_ARRAY *dns_addr_array_copy(TALLOC_CTX *mem_ctx,
						struct DNS_ADDR_ARRAY *addr)
{
	struct DNS_ADDR_ARRAY *ret;

	if (!addr) {
		return NULL;
	}

	ret = talloc_zero(mem_ctx, struct DNS_ADDR_ARRAY);
	if (!ret) {
		return ret;
	}

	ret->MaxCount = addr->MaxCount;
	ret->AddrCount = addr->AddrCount;
	ret->Family = addr->Family;
	if (addr->AddrCount > 0) {
		ret->AddrArray = talloc_zero_array(mem_ctx, struct DNS_ADDR, addr->AddrCount);
		if (ret->AddrArray) {
			memcpy(ret->AddrArray, addr->AddrArray,
				sizeof(struct DNS_ADDR) * addr->AddrCount);
		} else {
			talloc_free(ret);
			return NULL;
		}
	}
	return ret;
}


int dns_split_name_components(TALLOC_CTX *tmp_ctx, const char *name, char ***components)
{
	char *str = NULL, *ptr, **list;
	int count = 0;

	if (name == NULL) {
		return 0;
	}

	str = talloc_strdup(tmp_ctx, name);
	if (!str) {
		goto failed;
	}

	list = talloc_zero_array(tmp_ctx, char *, 0);
	if (!list) {
		goto failed;
	}

	ptr = strtok(str, ".");
	while (ptr != NULL) {
		count++;
		list = talloc_realloc(tmp_ctx, list, char *, count);
		if (!list) {
			goto failed;
		}
		list[count-1] = talloc_strdup(tmp_ctx, ptr);
		if (list[count-1] == NULL) {
			goto failed;
		}
		ptr = strtok(NULL, ".");
	}

	talloc_free(str);

	*components = list;
	return count;

failed:
	TALLOC_FREE(str);
	return -1;
}


char *dns_split_node_name(TALLOC_CTX *tmp_ctx, const char *node_name, const char *zone_name)
{
	char **nlist, **zlist;
	char *prefix;
	int ncount, zcount, i, match;

	/*
	 * If node_name is "@", return the zone_name
	 * If node_name is ".", return NULL
	 * If there is no '.' in node_name, return the node_name as is.
	 *
	 * If node_name does not have zone_name in it, return the node_name as is.
	 *
	 * If node_name has additional components as compared to zone_name
	 *  return only the additional components as a prefix.
	 *
	 */
	if (strcmp(node_name, "@") == 0) {
		prefix = talloc_strdup(tmp_ctx, zone_name);
	} else if (strcmp(node_name, ".") == 0) {
		prefix = NULL;
	} else if (strchr(node_name, '.') == NULL) {
		prefix = talloc_strdup(tmp_ctx, node_name);
	} else {
		zcount = dns_split_name_components(tmp_ctx, zone_name, &zlist);
		ncount = dns_split_name_components(tmp_ctx, node_name, &nlist);
		if (zcount < 0 || ncount < 0) {
			return NULL;
		}

		if (ncount < zcount) {
			prefix = talloc_strdup(tmp_ctx, node_name);
		} else {
			match = 0;
			for (i=1; i<=zcount; i++) {
				if (strcasecmp(nlist[ncount-i], zlist[zcount-i]) != 0) {
					break;
				}
				match++;
			}

			if (match == ncount) {
				prefix = talloc_strdup(tmp_ctx, zone_name);
			} else {
				prefix = talloc_strdup(tmp_ctx, nlist[0]);
				if (prefix != NULL) {
					for (i=1; i<ncount-match; i++) {
						prefix = talloc_asprintf_append(prefix, ".%s", nlist[i]);
						if (prefix == NULL) {
							break;
						}
					}
				}
			}
		}

		talloc_free(zlist);
		talloc_free(nlist);
	}

	return prefix;
}


void dnsp_to_dns_copy(TALLOC_CTX *mem_ctx, struct dnsp_DnssrvRpcRecord *dnsp,
				struct DNS_RPC_RECORD *dns)
{
	int i, len;

	ZERO_STRUCTP(dns);

	dns->wDataLength = dnsp->wDataLength;
	dns->wType = dnsp->wType;
	dns->dwFlags = dnsp->rank;
	dns->dwSerial = dnsp->dwSerial;
	dns->dwTtlSeconds = dnsp->dwTtlSeconds;
	dns->dwTimeStamp = dnsp->dwTimeStamp;

	switch (dnsp->wType) {

	case DNS_TYPE_TOMBSTONE:
		dns->data.timestamp = dnsp->data.timestamp;
		break;

	case DNS_TYPE_A:
		dns->data.ipv4 = talloc_strdup(mem_ctx, dnsp->data.ipv4);
		break;

	case DNS_TYPE_NS:
		len = strlen(dnsp->data.ns);
		if (dnsp->data.ns[len-1] == '.') {
			dns->data.name.len = len;
			dns->data.name.str = talloc_strdup(mem_ctx, dnsp->data.ns);
		} else {
			dns->data.name.len = len+1;
			dns->data.name.str = talloc_asprintf(mem_ctx, "%s.", dnsp->data.ns);
		}
		break;

	case DNS_TYPE_CNAME:
		len = strlen(dnsp->data.cname);
		if (dnsp->data.cname[len-1] == '.') {
			dns->data.name.len = len;
			dns->data.name.str = talloc_strdup(mem_ctx, dnsp->data.cname);
		} else {
			dns->data.name.len = len+1;
			dns->data.name.str = talloc_asprintf(mem_ctx, "%s.", dnsp->data.cname);
		}
		break;

	case DNS_TYPE_SOA:
		dns->data.soa.dwSerialNo = dnsp->data.soa.serial;
		dns->data.soa.dwRefresh = dnsp->data.soa.refresh;
		dns->data.soa.dwRetry = dnsp->data.soa.retry;
		dns->data.soa.dwExpire = dnsp->data.soa.expire;
		dns->data.soa.dwMinimumTtl = dnsp->data.soa.minimum;

		len = strlen(dnsp->data.soa.mname);
		if (dnsp->data.soa.mname[len-1] == '.') {
			dns->data.soa.NamePrimaryServer.len = len;
			dns->data.soa.NamePrimaryServer.str = talloc_strdup(mem_ctx, dnsp->data.soa.mname);
		} else {
			dns->data.soa.NamePrimaryServer.len = len+1;
			dns->data.soa.NamePrimaryServer.str = talloc_asprintf(mem_ctx, "%s.", dnsp->data.soa.mname);
		}

		len = strlen(dnsp->data.soa.rname);
		if (dnsp->data.soa.rname[len-1] == '.') {
			dns->data.soa.ZoneAdministratorEmail.len = len;
			dns->data.soa.ZoneAdministratorEmail.str = talloc_strdup(mem_ctx, dnsp->data.soa.rname);
		} else {
			dns->data.soa.ZoneAdministratorEmail.len = len+1;
			dns->data.soa.ZoneAdministratorEmail.str = talloc_asprintf(mem_ctx, "%s.", dnsp->data.soa.rname);
		}
		break;

	case DNS_TYPE_PTR:
		dns->data.ptr.len = strlen(dnsp->data.ptr);
		dns->data.ptr.str = talloc_strdup(mem_ctx, dnsp->data.ptr);
		break;

	case DNS_TYPE_MX:
		dns->data.mx.wPreference = dnsp->data.mx.wPriority;
		len = strlen(dnsp->data.mx.nameTarget);
		if (dnsp->data.mx.nameTarget[len-1] == '.') {
			dns->data.mx.nameExchange.len = len;
			dns->data.mx.nameExchange.str = talloc_strdup(mem_ctx, dnsp->data.mx.nameTarget);
		} else {
			dns->data.mx.nameExchange.len = len+1;
			dns->data.mx.nameExchange.str = talloc_asprintf(mem_ctx, "%s.", dnsp->data.mx.nameTarget);
		}
		break;

	case DNS_TYPE_TXT:
		dns->data.txt.count = dnsp->data.txt.count;
		dns->data.txt.str = talloc_array(mem_ctx, struct DNS_RPC_NAME, dnsp->data.txt.count);
		for (i=0; i<dnsp->data.txt.count; i++) {
			dns->data.txt.str[i].str = talloc_strdup(mem_ctx, dnsp->data.txt.str[i]);
			dns->data.txt.str[i].len = strlen(dnsp->data.txt.str[i]);
		}
		break;

	case DNS_TYPE_AAAA:
		dns->data.ipv6 = talloc_strdup(mem_ctx, dnsp->data.ipv6);
		break;

	case DNS_TYPE_SRV:
		dns->data.srv.wPriority = dnsp->data.srv.wPriority;
		dns->data.srv.wWeight = dnsp->data.srv.wWeight;
		dns->data.srv.wPort = dnsp->data.srv.wPort;
		len = strlen(dnsp->data.srv.nameTarget);
		if (dnsp->data.srv.nameTarget[len-1] == '.') {
			dns->data.srv.nameTarget.len = len;
			dns->data.srv.nameTarget.str = talloc_strdup(mem_ctx, dnsp->data.srv.nameTarget);
		} else {
			dns->data.srv.nameTarget.len = len+1;
			dns->data.srv.nameTarget.str = talloc_asprintf(mem_ctx, "%s.", dnsp->data.srv.nameTarget);
		}
		break;

	default:
		memcpy(&dns->data, &dnsp->data, sizeof(union DNS_RPC_DATA));
		DEBUG(0, ("dnsserver: Found Unhandled DNS record type=%d", dnsp->wType));
	}

}

WERROR dns_to_dnsp_convert(TALLOC_CTX *mem_ctx, struct DNS_RPC_RECORD *dns,
			   struct dnsp_DnssrvRpcRecord **out_dnsp, bool check_name)
{
	WERROR res;
	int i, len;
	const char *name;
	char *talloc_res = NULL;
	struct dnsp_DnssrvRpcRecord *dnsp = NULL;

	dnsp = talloc_zero(mem_ctx, struct dnsp_DnssrvRpcRecord);
	if (dnsp == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	dnsp->wDataLength = dns->wDataLength;
	dnsp->wType = dns->wType;
	dnsp->version = 5;
	dnsp->rank = dns->dwFlags & 0x000000FF;
	dnsp->dwSerial = dns->dwSerial;
	dnsp->dwTtlSeconds = dns->dwTtlSeconds;
	dnsp->dwTimeStamp = dns->dwTimeStamp;

	switch (dns->wType) {

	case DNS_TYPE_TOMBSTONE:
		dnsp->data.timestamp = dns->data.timestamp;
		break;

	case DNS_TYPE_A:
		talloc_res = talloc_strdup(mem_ctx, dns->data.ipv4);
		if (talloc_res == NULL) {
			goto fail_nomemory;
		}
		dnsp->data.ipv4 = talloc_res;
		break;

	case DNS_TYPE_NS:
		name = dns->data.name.str;
		len = dns->data.name.len;

		if (check_name) {
			res = dns_name_check(mem_ctx, len, name);
			if (!W_ERROR_IS_OK(res)) {
				return res;
			}
		}

		if (len > 0 && name[len-1] == '.') {
			talloc_res = talloc_strndup(mem_ctx, name, len-1);
			if (talloc_res == NULL) {
				goto fail_nomemory;
			}
			dnsp->data.ns = talloc_res;
		} else {
			talloc_res = talloc_strdup(mem_ctx, name);
			if (talloc_res == NULL) {
				goto fail_nomemory;
			}
			dnsp->data.ns = talloc_res;
		}

		break;

	case DNS_TYPE_CNAME:
		name = dns->data.name.str;
		len = dns->data.name.len;

		if (check_name) {
			res = dns_name_check(mem_ctx, len, name);
			if (!W_ERROR_IS_OK(res)) {
				return res;
			}
		}

		if (len > 0 && name[len-1] == '.') {
			talloc_res = talloc_strndup(mem_ctx, name, len-1);
			if (talloc_res == NULL) {
				goto fail_nomemory;
			}
			dnsp->data.cname = talloc_res;
		} else {
			talloc_res = talloc_strdup(mem_ctx, name);
			if (talloc_res == NULL) {
				goto fail_nomemory;
			}
			dnsp->data.cname = talloc_res;
		}

		break;

	case DNS_TYPE_SOA:
		dnsp->data.soa.serial = dns->data.soa.dwSerialNo;
		dnsp->data.soa.refresh = dns->data.soa.dwRefresh;
		dnsp->data.soa.retry = dns->data.soa.dwRetry;
		dnsp->data.soa.expire = dns->data.soa.dwExpire;
		dnsp->data.soa.minimum = dns->data.soa.dwMinimumTtl;

		name = dns->data.soa.NamePrimaryServer.str;
		len = dns->data.soa.NamePrimaryServer.len;

		if (check_name) {
			res = dns_name_check(mem_ctx, len, name);
			if (!W_ERROR_IS_OK(res)) {
				return res;
			}
		}

		if (len > 0 && name[len-1] == '.') {
			talloc_res = talloc_strndup(mem_ctx, name, len-1);
			if (talloc_res == NULL) {
				goto fail_nomemory;
			}
			dnsp->data.soa.mname = talloc_res;
		} else {
			talloc_res = talloc_strdup(mem_ctx, name);
			if (talloc_res == NULL) {
				goto fail_nomemory;
			}
			dnsp->data.soa.mname = talloc_res;
		}

		name = dns->data.soa.ZoneAdministratorEmail.str;
		len = dns->data.soa.ZoneAdministratorEmail.len;

		res = dns_name_check(mem_ctx, len, name);
		if (!W_ERROR_IS_OK(res)) {
			return res;
		}

		if (len > 0 && name[len-1] == '.') {
			talloc_res = talloc_strndup(mem_ctx, name, len-1);
			if (talloc_res == NULL) {
				goto fail_nomemory;
			}
			dnsp->data.soa.rname = talloc_res;
		} else {
			talloc_res = talloc_strdup(mem_ctx, name);
			if (talloc_res == NULL) {
				goto fail_nomemory;
			}
			dnsp->data.soa.rname = talloc_res;
		}

		break;

	case DNS_TYPE_PTR:
		name = dns->data.ptr.str;
		len = dns->data.ptr.len;

		if (check_name) {
			res = dns_name_check(mem_ctx, len, name);
			if (!W_ERROR_IS_OK(res)) {
				return res;
			}
		}

		talloc_res = talloc_strdup(mem_ctx, name);
		if (talloc_res == NULL) {
			goto fail_nomemory;
		}
		dnsp->data.ptr = talloc_res;

		break;

	case DNS_TYPE_MX:
		dnsp->data.mx.wPriority = dns->data.mx.wPreference;

		name = dns->data.mx.nameExchange.str;
		len = dns->data.mx.nameExchange.len;

		if (check_name) {
			res = dns_name_check(mem_ctx, len, name);
			if (!W_ERROR_IS_OK(res)) {
				return res;
			}
		}

		if (len > 0 && name[len-1] == '.') {
			talloc_res = talloc_strndup(mem_ctx, name, len-1);
			if (talloc_res == NULL) {
				goto fail_nomemory;
			}
			dnsp->data.mx.nameTarget = talloc_res;
		} else {
			talloc_res = talloc_strdup(mem_ctx, name);
			if (talloc_res == NULL) {
				goto fail_nomemory;
			}
			dnsp->data.mx.nameTarget = talloc_res;
		}

		break;

	case DNS_TYPE_TXT:
		dnsp->data.txt.count = dns->data.txt.count;
		dnsp->data.txt.str = talloc_array(mem_ctx, const char *, dns->data.txt.count);
		for (i=0; i<dns->data.txt.count; i++) {
			talloc_res = talloc_strdup(mem_ctx, dns->data.txt.str[i].str);
			if (talloc_res == NULL) {
				goto fail_nomemory;
			}
			dnsp->data.txt.str[i] = talloc_res;
		}
		break;

	case DNS_TYPE_AAAA:
		dnsp->data.ipv6 = talloc_strdup(mem_ctx, dns->data.ipv6);
		break;

	case DNS_TYPE_SRV:
		dnsp->data.srv.wPriority = dns->data.srv.wPriority;
		dnsp->data.srv.wWeight = dns->data.srv.wWeight;
		dnsp->data.srv.wPort = dns->data.srv.wPort;

		name = dns->data.srv.nameTarget.str;
		len = dns->data.srv.nameTarget.len;

		if (check_name) {
			res = dns_name_check(mem_ctx, len, name);
			if (!W_ERROR_IS_OK(res)) {
				return res;
			}
		}

		if (len > 0 && name[len-1] == '.') {
			talloc_res = talloc_strndup(mem_ctx, name, len-1);
			if (talloc_res == NULL) {
				goto fail_nomemory;
			}
			dnsp->data.srv.nameTarget = talloc_res;
		} else {
			talloc_res = talloc_strdup(mem_ctx, name);
			if (talloc_res == NULL) {
				goto fail_nomemory;
			}
			dnsp->data.srv.nameTarget = talloc_res;
		}

		break;

	default:
		memcpy(&dnsp->data, &dns->data, sizeof(union dnsRecordData));
		DEBUG(0, ("dnsserver: Found Unhandled DNS record type=%d", dns->wType));
	}

	*out_dnsp = dnsp;
	return WERR_OK;

fail_nomemory:
	return WERR_NOT_ENOUGH_MEMORY;
}

/* Intialize tree with given name as the root */
static struct dns_tree *dns_tree_init(TALLOC_CTX *mem_ctx, const char *name, void *data)
{
	struct dns_tree *tree;

	tree = talloc_zero(mem_ctx, struct dns_tree);
	if (tree == NULL) {
		return NULL;
	}

	tree->name = talloc_strdup(tree, name);
	if (tree->name == NULL) {
		talloc_free(tree);
		return NULL;
	}

	tree->data = data;

	return tree;
}


/* Add a child one level below */
static struct dns_tree *dns_tree_add(struct dns_tree *tree, const char *name, void *data)
{
	struct dns_tree *node;

	node = talloc_zero(tree, struct dns_tree);
	if (node == NULL) {
		return NULL;
	}

	node->name = talloc_strdup(tree, name);
	if (node->name == NULL) {
		talloc_free(node);
		return NULL;
	}
	node->level = tree->level + 1;
	node->num_children = 0;
	node->children = NULL;
	node->data = data;

	if (tree->num_children == 0) {
		tree->children = talloc_zero(tree, struct dns_tree *);
	} else {
		tree->children = talloc_realloc(tree, tree->children, struct dns_tree *,
						tree->num_children+1);
	}
	if (tree->children == NULL) {
		talloc_free(node);
		return NULL;
	}
	tree->children[tree->num_children] = node;
	tree->num_children++;

	return node;
}

/* Find a node that matches the name components */
static struct dns_tree *dns_tree_find(struct dns_tree *tree, int ncount, char **nlist, int *match_count)
{
	struct dns_tree *node, *next;
	int i, j, start;

	*match_count = -1;

	if (strcmp(tree->name, "@") == 0) {
		start = 0;
	} else {
		if (strcasecmp(tree->name, nlist[ncount-1]) != 0) {
			return NULL;
		}
		start = 1;
		*match_count = 0;
	}

	node = tree;
	for (i=start; i<ncount; i++) {
		if (node->num_children == 0) {
			break;
		}
		next = NULL;
		for (j=0; j<node->num_children; j++) {
			if (strcasecmp(nlist[(ncount-1)-i], node->children[j]->name) == 0) {
				next = node->children[j];
				*match_count = i;
				break;
			}
		}
		if (next == NULL) {
			break;
		} else {
			node = next;
		}
	}

	return node;
}

/* Build a 2-level tree for resulting dns names */
struct dns_tree *dns_build_tree(TALLOC_CTX *mem_ctx, const char *name, struct ldb_result *res)
{
	struct dns_tree *root, *base, *tree, *node;
	const char *ptr;
	int rootcount, ncount;
	char **nlist;
	int i, level, match_count;

	rootcount = dns_split_name_components(mem_ctx, name, &nlist);
	if (rootcount <= 0) {
		return NULL;
	}

	root = dns_tree_init(mem_ctx, nlist[rootcount-1], NULL);
	if (root == NULL) {
		talloc_free(nlist);
		return NULL;
	}

	tree = root;
	for (i=rootcount-2; i>=0; i--) {
		tree = dns_tree_add(tree, nlist[i], NULL);
		if (tree == NULL) {
			goto failed;
		}
	}

	base = tree;

	/* Add all names in the result in a tree */
	for (i=0; i<res->count; i++) {
		ptr = ldb_msg_find_attr_as_string(res->msgs[i], "name", NULL);
		if (ptr == NULL) {
			DBG_ERR("dnsserver: dns record has no name (%s)",
				ldb_dn_get_linearized(res->msgs[i]->dn));
			goto failed;
		}

		/*
		 * This might be the sub-domain in the zone being
		 * requested, or @ for the root of the zone
		 */
		if (strcasecmp(ptr, name) == 0) {
			base->data = res->msgs[i];
			continue;
		}

		ncount = dns_split_name_components(root, ptr, &nlist);
		if (ncount < 0) {
			goto failed;
		}

		/* Find matching node */
		tree = dns_tree_find(root, ncount, nlist, &match_count);
		if (tree == NULL) {
			goto failed;
		}

		/* If the node is on leaf, then add record data */
		if (match_count+1 == ncount) {
			tree->data = res->msgs[i];
		}

		/* Add missing name components */
		for (level=match_count+1; level<ncount; level++) {
			if (tree->level == rootcount+1) {
				break;
			}
			if (level == ncount-1) {
				node = dns_tree_add(tree, nlist[(ncount-1)-level], res->msgs[i]);
			} else {
				node = dns_tree_add(tree, nlist[(ncount-1)-level], NULL);
			}
			if (node == NULL) {
				goto failed;
			}
			tree = node;
		}

		talloc_free(nlist);
	}

	/* Mark the base record, so it can be found easily */
	base->level = -1;

	return root;

failed:
	talloc_free(nlist);
	talloc_free(root);
	return NULL;
}


static void _dns_add_name(TALLOC_CTX *mem_ctx, const char *name, char ***add_names, int *add_count)
{
	int i;
	char **ptr = *add_names;
	int count = *add_count;

	for (i=0; i<count; i++) {
		if (strcasecmp(ptr[i], name) == 0) {
			return;
		}
	}

	ptr = talloc_realloc(mem_ctx, ptr, char *, count+1);
	if (ptr == NULL) {
		return;
	}

	ptr[count] = talloc_strdup(mem_ctx, name);
	if (ptr[count] == NULL) {
		talloc_free(ptr);
		return;
	}

	*add_names = ptr;
	*add_count = count+1;
}


static void dns_find_additional_names(TALLOC_CTX *mem_ctx, struct dnsp_DnssrvRpcRecord *rec, char ***add_names, int *add_count)
{
	if (add_names == NULL) {
		return;
	}

	switch (rec->wType) {

	case DNS_TYPE_NS:
		_dns_add_name(mem_ctx, rec->data.ns, add_names, add_count);
		break;

	case DNS_TYPE_CNAME:
		_dns_add_name(mem_ctx, rec->data.cname, add_names, add_count);
		break;

	case DNS_TYPE_SOA:
		_dns_add_name(mem_ctx, rec->data.soa.mname, add_names, add_count);
		break;

	case DNS_TYPE_MX:
		_dns_add_name(mem_ctx, rec->data.mx.nameTarget, add_names, add_count);
		break;

	case DNS_TYPE_SRV:
		_dns_add_name(mem_ctx, rec->data.srv.nameTarget, add_names, add_count);
		break;

	default:
		break;
	}
}


WERROR dns_fill_records_array(TALLOC_CTX *mem_ctx,
				struct dnsserver_zone *z,
				enum dns_record_type record_type,
				unsigned int select_flag,
				const char *branch_name,
				struct ldb_message *msg,
				int num_children,
				struct DNS_RPC_RECORDS_ARRAY *recs,
				char ***add_names,
				int *add_count)
{
	struct ldb_message_element *el;
	const char *ptr;
	int i, j;
	bool found;

	if (recs->count == 0) {
		recs->rec = talloc_zero(recs, struct DNS_RPC_RECORDS);
	} else {
		recs->rec = talloc_realloc(recs, recs->rec, struct DNS_RPC_RECORDS, recs->count+1);
	}
	if (recs->rec == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}
	i = recs->count;
	recs->rec[i].wLength = 0;
	recs->rec[i].wRecordCount = 0;
	recs->rec[i].dwChildCount = num_children;
	recs->rec[i].dwFlags = 0;

	/* The base records returned with empty name */
	/* Children records returned with names */
	if (branch_name == NULL) {
		recs->rec[i].dnsNodeName.str = talloc_strdup(recs, "");
		recs->rec[i].dnsNodeName.len = 0;
	} else {
		recs->rec[i].dnsNodeName.str = talloc_strdup(recs, branch_name);
		recs->rec[i].dnsNodeName.len = strlen(branch_name);
	}
	recs->rec[i].records = talloc_zero_array(recs, struct DNS_RPC_RECORD, 0);
	recs->count++;

	/* Allow empty records */
	if (msg == NULL) {
		return WERR_OK;
	}

	/* Do not return RR records, if the node has children */
	if (branch_name != NULL && num_children > 0) {
		return WERR_OK;
	}

	ptr = ldb_msg_find_attr_as_string(msg, "name", NULL);
	if (ptr == NULL) {
		DBG_ERR("dnsserver: dns record has no name (%s)",
			ldb_dn_get_linearized(msg->dn));
		return WERR_INTERNAL_DB_ERROR;
	}

	el = ldb_msg_find_element(msg, "dnsRecord");
	if (el == NULL || el->values == 0) {
		return WERR_OK;
	}

	/* Add RR records */
	for (j=0; j<el->num_values; j++) {
		struct dnsp_DnssrvRpcRecord dnsp_rec;
		struct DNS_RPC_RECORD *dns_rec;
		enum ndr_err_code ndr_err;

		ndr_err = ndr_pull_struct_blob(&el->values[j], mem_ctx, &dnsp_rec,
					(ndr_pull_flags_fn_t)ndr_pull_dnsp_DnssrvRpcRecord);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			DEBUG(0, ("dnsserver: Unable to parse dns record (%s)", ldb_dn_get_linearized(msg->dn)));
			return WERR_INTERNAL_DB_ERROR;
		}

		/* Match the records based on search criteria */
		if (record_type == DNS_TYPE_ALL || dnsp_rec.wType == record_type) {
			found = false;

			if (select_flag & DNS_RPC_VIEW_AUTHORITY_DATA) {
				if (dnsp_rec.rank == DNS_RANK_ZONE) {
					found = true;
				} else if (dnsp_rec.rank == DNS_RANK_NS_GLUE) {
					/*
					 * If branch_name is NULL, we're
					 * explicitly asked to also return
					 * DNS_RANK_NS_GLUE records
					 */
					if (branch_name == NULL) {
						found = true;
					}
				}
			}
			if (select_flag & DNS_RPC_VIEW_CACHE_DATA) {
				if (dnsp_rec.rank == DNS_RANK_ZONE) {
					found = true;
				}
			}
			if (select_flag & DNS_RPC_VIEW_GLUE_DATA) {
				if (dnsp_rec.rank == DNS_RANK_GLUE) {
					found = true;
				}
			}
			if (select_flag & DNS_RPC_VIEW_ROOT_HINT_DATA) {
				if (dnsp_rec.rank == DNS_RANK_ROOT_HINT) {
					found = true;
				}
			}

			if (found) {
				recs->rec[i].records = talloc_realloc(recs,
							recs->rec[i].records,
							struct DNS_RPC_RECORD,
							recs->rec[i].wRecordCount+1);
				if (recs->rec[i].records == NULL) {
					return WERR_NOT_ENOUGH_MEMORY;
				}

				dns_rec = &recs->rec[i].records[recs->rec[i].wRecordCount];
				dnsp_to_dns_copy(recs, &dnsp_rec, dns_rec);

				/* Fix record flags */
				if (strcmp(ptr, "@") == 0) {
					dns_rec->dwFlags |= DNS_RPC_FLAG_ZONE_ROOT;

					if (dnsp_rec.rank == DNS_RANK_ZONE) {
						dns_rec->dwFlags |= DNS_RPC_FLAG_AUTH_ZONE_ROOT;
					}
				}

				if (dns_rec->dwFlags == DNS_RANK_NS_GLUE) {
					dns_rec->dwFlags |= DNS_RPC_FLAG_ZONE_ROOT;
				}

				recs->rec[i].wRecordCount++;

				dns_find_additional_names(mem_ctx, &dnsp_rec, add_names, add_count);
			}
		}
	}

	return WERR_OK;
}


int dns_name_compare(struct ldb_message * const *m1, struct ldb_message * const *m2,
		     const char *search_name)
{
	const char *name1, *name2;
	const char *ptr1, *ptr2;

	name1 = ldb_msg_find_attr_as_string(*m1, "name", NULL);
	name2 = ldb_msg_find_attr_as_string(*m2, "name", NULL);
	if (name1 == NULL || name2 == NULL) {
		return 0;
	}

	/* Compare the last components of names.
	 * If search_name is not NULL, compare the second last components of names */
	ptr1 = strrchr(name1, '.');
	if (ptr1 == NULL) {
		ptr1 = name1;
	} else {
		if (search_name && strcasecmp(ptr1+1, search_name) == 0) {
			ptr1--;
			while (ptr1 != name1) {
				ptr1--;
				if (*ptr1 == '.') {
					break;
				}
			}
		}
		if (*ptr1 == '.') {
			ptr1 = &ptr1[1];
		}
	}

	ptr2 = strrchr(name2, '.');
	if (ptr2 == NULL) {
		ptr2 = name2;
	} else {
		if (search_name && strcasecmp(ptr2+1, search_name) == 0) {
			ptr2--;
			while (ptr2 != name2) {
				ptr2--;
				if (*ptr2 == '.') {
					break;
				}
			}
		}
		if (*ptr2 == '.') {
			ptr2 = &ptr2[1];
		}
	}

	return strcasecmp(ptr1, ptr2);
}

bool dns_record_match(struct dnsp_DnssrvRpcRecord *rec1, struct dnsp_DnssrvRpcRecord *rec2)
{
	bool status;
	int i;

	if (rec1->wType != rec2->wType) {
		return false;
	}

	switch(rec1->wType) {
	case DNS_TYPE_TOMBSTONE:
		return true;

	case DNS_TYPE_A:
		return strcmp(rec1->data.ipv4, rec2->data.ipv4) == 0;

	case DNS_TYPE_NS:
		return dns_name_equal(rec1->data.ns, rec2->data.ns);

	case DNS_TYPE_CNAME:
		return dns_name_equal(rec1->data.cname, rec2->data.cname);

	case DNS_TYPE_SOA:
		return dns_name_equal(rec1->data.soa.mname, rec2->data.soa.mname) &&
			dns_name_equal(rec1->data.soa.rname, rec2->data.soa.rname) &&
			rec1->data.soa.serial == rec2->data.soa.serial &&
			rec1->data.soa.refresh == rec2->data.soa.refresh &&
			rec1->data.soa.retry == rec2->data.soa.retry &&
			rec1->data.soa.expire == rec2->data.soa.expire &&
			rec1->data.soa.minimum == rec2->data.soa.minimum;

	case DNS_TYPE_PTR:
		return dns_name_equal(rec1->data.ptr, rec2->data.ptr);

	case DNS_TYPE_MX:
		return rec1->data.mx.wPriority == rec2->data.mx.wPriority &&
			dns_name_equal(rec1->data.mx.nameTarget, rec2->data.mx.nameTarget);

	case DNS_TYPE_TXT:
		if (rec1->data.txt.count != rec2->data.txt.count) {
			return false;
		}
		status = true;
		for (i=0; i<rec1->data.txt.count; i++) {
			status = status && (strcmp(rec1->data.txt.str[i],
						   rec2->data.txt.str[i]) == 0);
		}
		return status;

	case DNS_TYPE_AAAA:
		return strcmp(rec1->data.ipv6, rec2->data.ipv6) == 0;

	case DNS_TYPE_SRV:
		return rec1->data.srv.wPriority == rec2->data.srv.wPriority &&
			rec1->data.srv.wWeight == rec2->data.srv.wWeight &&
			rec1->data.srv.wPort == rec2->data.srv.wPort &&
			dns_name_equal(rec1->data.srv.nameTarget, rec2->data.srv.nameTarget);

	default:
		DEBUG(0, ("dnsserver: unhandled record type %u", rec1->wType));
		break;
	}

	return false;
}
