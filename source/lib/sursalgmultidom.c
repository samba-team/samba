/* 
   Unix SMB/Netbios implementation.
   Version 2.0
   Winbind daemon for ntdom nss module
   Copyright (C) Tim Potter 2000
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"
#include "rpc_client.h"
#include "sids.h"
#include "nterr.h"

/* Globals for domain list stuff */

struct dom_range
{
	struct dom_range *prev, *next;

	fstring name;
	fstring got_domain_sid;
	DOM_SID sid;

	uint32 uid_high;
	uint32 uid_low;
	uint32 gid_high;
	uint32 gid_low;

};

static BOOL get_domain_info(struct dom_range *tmp)
{
	uint32 type;
	if (lookup_lsa_name("\\\\.", tmp->name, &tmp->sid, &type) !=
	    NT_STATUS_NOPROBLEMO)
	{
		DEBUG(2, ("surs_multidom: lookup of %s failed\n", tmp->name));
		return False;
	}
	if (type != SID_NAME_DOMAIN)
	{
		DEBUG(2, ("surs_multidom: %s is not a domain\n", tmp->name));
		return False;
	}
	return True;
}

static struct dom_range *domain_list = NULL;

/* Given a domain name, return the struct domrange domain info for it */

static struct dom_range *find_domain_from_name(const char *domain_name)
{
	struct dom_range *tmp;

	/* Search through list */

	for (tmp = domain_list; tmp != NULL; tmp = tmp->next)
	{
		if (strcmp(domain_name, tmp->name) == 0)
		{
			if (!tmp->got_domain_sid)
			{
			}
			/* Get domain info for this domain */

			if (!tmp->got_domain_sid && !get_domain_info(tmp))
			{
				return NULL;
			}

			return tmp;
		}
	}

	/* Not found */

	return NULL;
}

static BOOL create_domain(const char *domain_name,
			  uint32 id_low, uint32 id_high, BOOL is_user)
{
	struct dom_range *domain;
	/* Find domain record */

	domain = find_domain_from_name(domain_name);
	if (domain == NULL)
	{
		/* Create new domain record */

		domain = g_new(struct dom_range, 1);

		if (domain == NULL)
		{
			return False;
		}

		ZERO_STRUCTP(domain);
		fstrcpy(domain->name, domain_name);

		DLIST_ADD(domain_list, domain);
	}

	/* Store domain id info */

	if (is_user)
	{
		/* Store user info */

		domain->uid_low = id_low;

		if (id_high == 0)
		{
			domain->uid_high = -1;
		}
		else
		{
			domain->uid_high = id_high;
		}

	}
	else
	{
		/* Store group info */

		domain->gid_low = id_low;

		if (id_high == 0)
		{
			domain->gid_high = -1;
		}
		else
		{
			domain->gid_high = id_high;
		}
	}

	return True;
}



/* Parse list of arguments to domrange uid or domrange gid parameters */

static BOOL parse_id_list(char *paramstr, BOOL is_user)
{
	uint32 id_low, id_high = 0;
	fstring domain_name;
	fstring p;

	while (next_token(&paramstr, p, LIST_SEP, sizeof(fstring) - 1))
	{
		/* Parse domain entry */

		if ((sscanf(p, "%[^/]/%u-%u", domain_name, &id_low,
			    &id_high) != 3) &&
		    (sscanf(p, "%[^/]/%u", domain_name, &id_low) != 2))
		{
			DEBUG(0, ("parse_id_list(): %s parameter "
				  "invalid\n", is_user ? "uid" : "gid"));
			return False;
		}

		/* Find domain record */

		if (!create_domain(domain_name, id_low, id_high, is_user))
		{
			return False;
		}
	}

	return True;
}


static BOOL check_ranges(const struct dom_range *temp,
			 const struct dom_range *temp2)
{
	/* Check for duplicate domain names */

	if ((temp != temp2) && strequal(temp->name, temp2->name))
	{
		DEBUG(0, ("found duplicate domain %s in domrange "
			  "domain list\n", temp->name));
		return False;
	}

	/* Check for overlapping uid ranges */

	if (
	    ((temp->uid_low >= temp2->uid_low)
	     && (temp->uid_low <= temp2->uid_high))
	    || ((temp->uid_high >= temp2->uid_low)
		&& (temp->uid_high <= temp2->uid_high)))
	{
		DEBUG(0, ("uid ranges for domains %s and %s overlap\n",
			  temp->name, temp2->name));
		return False;
	}

	/* Check for overlapping gid ranges */

	if (
	    ((temp->gid_low >= temp2->gid_low)
	     && (temp->gid_low <= temp2->gid_high))
	    || ((temp->gid_high >= temp2->gid_low)
		&& (temp->gid_high <= temp2->gid_high)))
	{
		DEBUG(0, ("gid ranges for domains %s and %s overlap\n",
			  temp->name, temp2->name));
		return False;
	}
	return True;
}

/* Initialise trusted domain info */

static BOOL initialised;
static BOOL domrange_param_init(void)
{
	struct dom_range *temp, *temp2;

	if (initialised != 0)
	{
		return True;
	}

	initialised = 1;

	/* Parse domrange uid and domrange_gid parameters */

	if (!parse_id_list(lp_surs_domainrange_uid(), True) ||
	    !parse_id_list(lp_surs_domainrange_gid(), False))
	{
		return False;
	}

	/*
	 * create default "surs [ug]id map" options.
	 */

	if (domain_list == NULL)
	{
		create_domain(global_sam_name, 0, -1, True);
		create_domain(global_sam_name, 0, -1, False);
	}

	/* Perform other sanity checks on results.
	 * The only fields we have filled
	 * in at the moment are name and [ug]id_{low,high} */

	/* Check for duplicate domain names */

	for (temp = domain_list; temp; temp = temp->next)
	{
		/* Check for reversed uid and gid ranges */

		if (temp->uid_low > temp->uid_high)
		{
			DEBUG(0, ("uid range for domain %s invalid\n",
				  temp->name));
			return False;
		}

		if (temp->gid_low > temp->gid_high)
		{
			DEBUG(0, ("gid range for domain %s invalid\n",
				  temp->name));
			return False;
		}

		for (temp2 = domain_list; temp2; temp2 = temp2->next)
		{
			if (temp != temp2 && !check_ranges(temp, temp2))
			{
				return False;
			}
		}
	}
	return True;
}

static BOOL domalg_sam_rid_to_unixid(struct dom_range *domain,
				     uint32 rid, SURS_POSIX_ID * id)
{
	/* Check users */

	if (id->type == SURS_POSIX_UID)
	{
		if ((domain->uid_low + rid) > domain->uid_high)
		{
			DEBUG(0, ("uid range (%d-%d) too small "
				  "for rid %d\n",
				  domain->uid_low, domain->uid_high, rid));
			return False;
		}

		id->id = domain->uid_low + rid;

		return True;
	}

	/* Check groups */

	if (id->type == SURS_POSIX_GID)
	{
		if ((domain->gid_low + rid) > domain->gid_high)
		{
			DEBUG(0, ("gid range (%d-%d) too small "
				  "for rid %d\n",
				  domain->gid_low, domain->gid_high, rid));
			return False;
		}

		id->id = domain->gid_low + rid;

		return True;
	}

	return False;
}

static BOOL domalg_unixid_to_sam_sid(struct dom_range *domain,
				     const SURS_POSIX_ID * id,
				     SURS_SID_ID * sid)
{
	/* Process user id */

	if (id->type == SURS_POSIX_UID)
	{
		if ((id->id >= domain->uid_low)
		    && (id->id <= domain->uid_high))
		{
			/* uid falls within range for this domain */

			if (sid != NULL)
			{
				sid_copy(sid, &domain->sid);
				sid_append_rid(sid, id->id - domain->uid_low);
			}

			return True;
		}
	}

	/* Process group id */

	if (id->type == SURS_POSIX_GID)
	{
		if ((id->id >= domain->gid_low)
		    && (id->id <= domain->gid_high))
		{
			/* gid falls within range for this domain */

			if (sid != NULL)
			{
				sid_copy(sid, &domain->sid);
				sid_append_rid(sid, id->id - domain->gid_low);
			}

			return True;
		}
	}

	return False;
}

BOOL surs_multidomalg_sam_sid_to_unixid(const SURS_SID_ID * sid,
					SURS_POSIX_ID * id, BOOL create)
{
	struct dom_range *tmp;
	SURS_SID_ID tmp_sid;
	uint32 rid;

	sid_copy(&tmp_sid, sid);
	sid_split_rid(&tmp_sid, &rid);

	if (!domrange_param_init())
	{
		DEBUG(2, ("domrange_param_init: failed\n"));
		return False;
	}

	/*
	 * Search through list
	 */

	for (tmp = domain_list; tmp != NULL; tmp = tmp->next)
	{
		if (domalg_sam_rid_to_unixid(tmp, rid, id))
		{
			return True;
		}
	}

	/* Not found */
	return False;
}

BOOL surs_multidomalg_unixid_to_sam_sid(const SURS_POSIX_ID * id,
					SURS_SID_ID * sid, BOOL create)
{
	struct dom_range *tmp;

	if (!domrange_param_init())
	{
		DEBUG(2, ("domrange_param_init: failed\n"));
		return False;
	}

	/*
	 * Search through list
	 */

	for (tmp = domain_list; tmp != NULL; tmp = tmp->next)
	{
		if (domalg_unixid_to_sam_sid(tmp, id, sid))
		{
			return True;
		}
	}

	/* Not found */
	return False;
}
