/* 
   Unix SMB/Netbios implementation.
   Version 2.0.
   LDAP protocol helper functions for SAMBA
   Copyright (C) Jean François Micouleau 1998
   Copyright (C) Matthew Chapman 1998
   Copyright (C) Luke Howard (PADL Software Pty Ltd) 2000

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

#ifdef WITH_NT5LDAP

#include <lber.h>
#include <ldap.h>
#include "ldapdb.h"
#include "sids.h"

extern int DEBUGLEVEL;

/* LDAP password */
static pstring ldap_secret;

/* Internal search func */
static BOOL __ldapdb_search (LDAPDB * hds, const char *dn, int scope, const char *filter, char *const *attrs, int sizelimit);
/* Step through to next entry from a synchronous search result */
static BOOL ldapdb_next_s (LDAPDB * hds);
/* Step through to next entry from an asynchronous search result */
static BOOL ldapdb_next (LDAPDB * hds);

/* Use the synchronous API. This must be set for the life of the handle! */
#define LDAPDB_RETRIEVE_SYNCHRONOUSLY       0x00000001

struct ldapdb_conn_info
{
	LDAP *ld;
	int refs;
};

typedef struct ldapdb_conn_info LDAPDBCONN, *PLDAPDBCONN;

/* we should eventually use this to make things reentrant. globals are bad */
struct ldapdb_handle_info
{
	LDAPDBCONN *conn;
	union
	{
		int msgid;	/* msgid of request */
		LDAPMessage *chain;	/* chain, for LDAPDB_RETRIEVE_SYNCHRONOUSLY */
	}
	res;
	LDAPMessage *entry;	/* entry */
	uint32 flags;
};

BOOL ldapdb_init(void)
{
        FILE *pwdfile;
        char *pwdfilename;
        char *p;

        pwdfilename = lp_ldap_passwd_file();

        if (pwdfilename[0])
        {
                if((pwdfile = sys_fopen(pwdfilename, "r")))
                {
                        fgets(ldap_secret, sizeof(ldap_secret), pwdfile);
                        if((p = strchr(ldap_secret, '\n')))
                                *p = 0;
                        fclose(pwdfile);
			return True;
                }
                else
                {
                        DEBUG(0,("Failed to open LDAP passwd file\n"));
			return False;
                }
        }

#if 0
	if (!pwdb_initialise(True))
	{
		return False;
	}
#endif

	return True;
}

/*******************************************************************
  Create a handle sharing the same session as another handle
 ******************************************************************/
BOOL 
ldapdb_dup (LDAPDB * in, LDAPDB ** out)
{
	*out = calloc (1, sizeof (LDAPDB));
	if (*out == NULL)
	{
		return False;
	}
	if (in)
	{
		/* struct copy */
		(*out)->conn = in->conn;
		in->conn->refs++;
		if (in->flags & LDAPDB_RETRIEVE_SYNCHRONOUSLY)
		{
			(*out)->res.chain = NULL;	/* clone? */
			(*out)->entry = NULL;	/* in->entry; */
		}
		else
		{
			(*out)->res.msgid = -1;		/* in->res.msgid; */
			(*out)->entry = NULL;
		}
		(*out)->flags = in->flags;
	}
	else
	{
		(*out)->conn = calloc (1, sizeof (LDAPDBCONN));
		if ((*out)->conn == NULL)
		{
			free (*out);
			return False;
		}
		(*out)->conn->ld = NULL;
		(*out)->conn->refs = 1;
		(*out)->res.msgid = -1;
		(*out)->flags = 0;
		(*out)->entry = NULL;
	}

	return True;
}

/*******************************************************************
  Create a new connection to the LDAP server (or return a cached
  one)
 ******************************************************************/
BOOL 
ldapdb_open (LDAPDB ** phds)
{
	int err, version = lp_ldap_protocol_version ();
	LDAPDB *hds;
	static LDAPDB *__ldapdb_handle = NULL;
	static pid_t __ldapdb_pid = -1;
	pid_t pid;

	DEBUG(3,("ldapdb_open\n"));

	if (*phds != NULL)
	{
		/* we've got a handle, so let's just use it! */
		hds = *phds;
	}
	else
	{
		/* try and use the cached handle, otherwise alloc one which we will cache */
		if (!ldapdb_dup (__ldapdb_handle, &hds))
		{
			DEBUG (0, ("ldapdb_dup failed"));
			return False;	/* malloc failed */
		}
	}

	/* If we've forked, close the connection but don't send an unbind. */
	pid = getpid ();
	if (__ldapdb_pid != pid && __ldapdb_handle != NULL)
	{
		int sd = -1;
		if (ldap_get_option (__ldapdb_handle->conn->ld, LDAP_OPT_DESC, &sd) == 0)
		{
			close (sd);
			sd = -1;
			(void) ldap_set_option (__ldapdb_handle->conn->ld, LDAP_OPT_DESC, &sd);
		}
		ldap_unbind (__ldapdb_handle->conn->ld);
		__ldapdb_handle->conn->ld = NULL;
	}

	/* only try to open the connection if it's not already opened */
	if (hds->conn->ld == NULL)
	{
#if defined(LDAP_API_FEATURE_X_OPENLDAP) && (LDAP_API_VERSION > 2000)
		/* can support LDAP URLs. */
		char *url = lp_ldap_url ();

		if (url != NULL && url[0] != '\0' &&
			((err = ldap_initialize (&hds->conn->ld, url)) != LDAP_SUCCESS))
		{
			DEBUG (0, ("ldap_initialize: %s\n", ldap_err2string (err)));
			ldapdb_close (&hds);
			return False;
		}
		else
#endif
		if (!(hds->conn->ld = ldap_open (lp_ldap_server (), lp_ldap_port ())))
		{
			DEBUG (0, ("ldap_open: %s\n", strerror (errno)));
			ldapdb_close (&hds);
			return False;
		}

		ldap_set_option (hds->conn->ld, LDAP_OPT_PROTOCOL_VERSION, &version);

		if (strcmp (lp_ldap_bind_as (), "") != 0 || version < 3)
		{
			err = ldap_simple_bind_s (hds->conn->ld, lp_ldap_bind_as (), ldap_secret);
			if (err != LDAP_SUCCESS)
			{
				DEBUG (0, ("ldap_simple_bind_s: %s\n", ldap_err2string (err)));
				ldapdb_close (&hds);
				return False;
			}
		}		/* otherwise, using V3 and anonymous credentials; avoid binding at all */

		DEBUG (2, ("Connected to LDAP server\n"));
	}

	if (__ldapdb_handle == NULL)
	{
		/* we created a handle, cache it */
		__ldapdb_handle = hds;
		return ldapdb_dup (__ldapdb_handle, phds);
	}
	else
	{
		/* return the dupped handle */
		*phds = hds;
	}

	return True;
}

/*******************************************************************
  close connections to the LDAP server.
 ******************************************************************/

void 
ldapdb_close (LDAPDB ** phds)
{
	LDAPDB *hds;

	DEBUG(3,("ldapdb_close\n"));

	if (*phds == NULL)
	{
		return;
	}

	hds = *phds;

	if (hds->flags & LDAPDB_RETRIEVE_SYNCHRONOUSLY)
	{
		if (hds->res.chain != NULL)
		{
			ldap_msgfree (hds->res.chain);
		}
	}
	else
	{
		if (hds->res.msgid > -1)
		{
			ldap_abandon (hds->conn->ld, hds->res.msgid);
		}
		if (hds->entry != NULL)
		{
			ldap_msgfree (hds->entry);
		}
	}

	hds->conn->refs--;
	if (hds->conn->refs < 1)
	{
		ldap_unbind (hds->conn->ld);
		free (hds->conn);
		DEBUG (2, ("LDAP connection closed\n"));
	}

	free (hds);
	*phds = NULL;

	DEBUG (2, ("LDAPDB handle deallocated\n"));
	return;
}

/*******************************************************************
  Fetch the next result from the server
 ******************************************************************/
static BOOL 
ldapdb_next (LDAPDB * hds)
{
	int rc, parserc;
	BOOL ret = False;
	LDAPMessage *entry;

	DEBUG(3,("ldapdb_next\n"));

	if (hds->res.msgid < 0)
	{
		return False;
	}

	do
	{
		rc = ldap_result (hds->conn->ld, hds->res.msgid, LDAP_MSG_ONE, NULL, &entry);
		switch (rc)
		{
		case LDAP_RES_SEARCH_ENTRY:
			ret = True;
			break;
		case LDAP_RES_SEARCH_RESULT:
			parserc = ldap_parse_result (hds->conn->ld, entry, NULL, NULL, NULL, NULL, NULL, 1);
			if (parserc != LDAP_SUCCESS)
			{
				ldap_abandon (hds->conn->ld, hds->res.msgid);
				DEBUG (2, ("ldap_parse_result: %s\n", ldap_err2string (parserc)));
				hds->res.msgid = -1;
			}
			ret = False;
			break;
		case 0:
		case -1:
			/* here perhaps we should reopen the conn? */
		default:
			ldap_msgfree (entry);
			ldap_abandon (hds->conn->ld, hds->res.msgid);
			hds->res.msgid = -1;
			ret = False;
			break;
		}
	}
#ifdef LDAP_RES_SEARCH_REFERENCE
	while (rc == LDAP_RES_SEARCH_REFERENCE);
#else
	while (0);
#endif

	if (hds->entry != NULL)
	{
		ldap_msgfree (hds->entry);
		hds->entry = NULL;
	}

	if (ret == True)
	{
		hds->entry = entry;
	}

	return ret;
}

/*******************************************************************
  Fetch the next result off an already-fetched result chain
 ******************************************************************/
static BOOL 
ldapdb_next_s (LDAPDB * hds)
{
	DEBUG(3,("ldapdb_next_s\n"));

	if (hds->res.chain == NULL)
	{
		return False;
	}

	if (hds->entry == NULL)
	{
		hds->entry = ldap_first_entry (hds->conn->ld, hds->res.chain);
	}
	else
	{
		hds->entry = ldap_next_entry (hds->conn->ld, hds->entry);
	}

	if (hds->entry == NULL)
	{
		/* No more data. */
		ldap_msgfree (hds->res.chain);
		hds->res.chain = NULL;
		return False;
	}

	return True;
}

/*******************************************************************
  Fetch the next result as appropriate to the search method
 ******************************************************************/
BOOL 
ldapdb_seq (LDAPDB * hds)
{
	DEBUG(3,("ldapdb_seq flags=[%08x]\n", hds->flags));

	if (hds->flags & LDAPDB_RETRIEVE_SYNCHRONOUSLY)
	{
		return ldapdb_next_s (hds);
	}
	else
	{
		return ldapdb_next (hds);
	}
}

/*******************************************************************
  Count search results, if we retrieved them all
 ******************************************************************/
BOOL 
ldapdb_count_entries (LDAPDB * hds, int *n)
{
	DEBUG(3,("ldapdb_count_entries flags=[%08x]\n", hds->flags));

	if (hds->flags & LDAPDB_RETRIEVE_SYNCHRONOUSLY && hds->res.chain)
	{
		*n = ldap_count_entries (hds->conn->ld, hds->res.chain);
		return True;
	}
	return False;
}

/*******************************************************************
  Set synchronous flag
 ******************************************************************/
BOOL 
ldapdb_set_synchronous (LDAPDB * hds, BOOL how)
{
	BOOL old;

	old = (hds->flags & LDAPDB_RETRIEVE_SYNCHRONOUSLY);
	if (how)
	{
		hds->flags |= LDAPDB_RETRIEVE_SYNCHRONOUSLY;
	}
	else
	{
		hds->flags &= ~LDAPDB_RETRIEVE_SYNCHRONOUSLY;
	}

	return old;
}

/*******************************************************************
  Check whether we have an entry waiting
 ******************************************************************/
BOOL 
ldapdb_peek (LDAPDB * hds)
{
	return (hds->entry == NULL) ? False : True;
}

/*******************************************************************
  Delete an entry from the directory
 ******************************************************************/
BOOL 
ldapdb_delete (LDAPDB * hds, const char *dn)
{
	DEBUG(3,("ldapdb_delete dn=[%s]\n", dn));

	return (ldap_delete_s (hds->conn->ld, dn) == LDAP_SUCCESS) ? True : False;
}

/*******************************************************************
  Wrapper around dn
 ******************************************************************/

BOOL 
ldapdb_get_dn (LDAPDB * hds, char **dn)
{
	*dn = ldap_get_dn (hds->conn->ld, hds->entry);
	if (*dn == NULL)
	{
		return False;
	}
	return True;
}

/*******************************************************************
  Read an entry from the directory
 ******************************************************************/
BOOL 
ldapdb_read (LDAPDB * hds, const char *dn, char *const *attrs)
{
	return __ldapdb_search (hds, dn, LDAP_SCOPE_BASE, "(objectClass=*)", attrs, 1);
}

/*******************************************************************
  Compose a DN from the global suffix + relative DN
 ******************************************************************/
const char *
__ldapdb_compose_dn (const char *context, pstring out_str)
{
	if (context != NULL)
	{
		pstrcpy (out_str, context);
		if (context[strlen (context) - 1] == ',')
		{
			pstrcat (out_str, lp_ldap_suffix ());
		}
		return out_str;
	}
	else
	{
		return lp_ldap_suffix ();
	}
}

/*******************************************************************
  Search in the directory
 ******************************************************************/
BOOL 
ldapdb_search (LDAPDB * hds, const char *context, const char *filter, char *const *attrs, int sizelimit)
{
	pstring base;
	int scope;

	if (context != NULL)
	{
		if (context[0] != '\0')
		{
			scope = LDAP_SCOPE_ONELEVEL;
		}
		else
		{
			scope = LDAP_SCOPE_BASE;
		}
	}
	else
	{
		scope = LDAP_SCOPE_SUBTREE;
	}

	return __ldapdb_search (hds, __ldapdb_compose_dn (context, base), scope, filter, attrs, sizelimit);
}

/*******************************************************************
  Search implementation
 ******************************************************************/
static BOOL 
__ldapdb_search (LDAPDB * hds, const char *dn, int scope, const char *filter, char *const *attrs, int sizelimit)
{
	int err;

	ldap_set_option (hds->conn->ld, LDAP_OPT_SIZELIMIT, &sizelimit);

	DEBUG (2, ("Searching in [%s] for [%s], scope [%d], sizelimit [%d]\n", dn, filter, scope, sizelimit));

	if (hds->flags & LDAPDB_RETRIEVE_SYNCHRONOUSLY)
	{
		if (hds->res.chain != NULL)
		{
			ldap_msgfree (hds->res.chain);
			hds->res.chain = NULL;
		}
		hds->entry = NULL;
		err = ldap_search_s (hds->conn->ld, dn, scope, filter, (char **) attrs, 0, &hds->res.chain);
		if (err != LDAP_SUCCESS)
		{
			DEBUG (0, ("ldap_search_s: %s\n", ldap_err2string (err)));
			return False;
		}
	}
	else
	{
		if (hds->res.msgid > 0)
		{
			ldap_abandon (hds->conn->ld, hds->res.msgid);
		}
		if (hds->entry != NULL)
		{
			ldap_msgfree (hds->entry);
			hds->entry = NULL;
		}
		hds->res.msgid = ldap_search (hds->conn->ld, dn, scope, filter, (char **) attrs, 0);
		if (hds->res.msgid < 0)
		{
			int err2 = ldap_get_option (hds->conn->ld, LDAP_OPT_ERROR_NUMBER, &err);
			if (err2 != LDAP_SUCCESS)
			{
				err = err2;
			}
			DEBUG (0, ("ldap_search: %s\n", ldap_err2string (err)));
			return False;
		}
	}

	return ldapdb_seq (hds);
}

/*******************************************************************
  Get the entry
 ******************************************************************/
BOOL 
ldapdb_get_entry (LDAPDB * hds, LDAPMessage ** res)
{
	if (hds->entry)
	{
		*res = hds->entry;
		return True;
	}

	return False;
}

/*******************************************************************
  Copy an attribute single value into a user supplied buffer
 ******************************************************************/
BOOL 
ldapdb_get_value (LDAPDB * hds, const char *attribute, char *buf, size_t len)
{
	char **values;

	values = ldap_get_values (hds->conn->ld, hds->entry, attribute);
	if (values == NULL)
	{
		return False;
	}
	if (values[0] == NULL)
	{
		ldap_value_free (values);
		return False;
	}

	safe_strcpy (buf, values[0], len);
	DEBUG (3, ("ldapdb_get_value: [%s] = [%s]\n", attribute, buf));

	ldap_value_free (values);

	return True;
}

BOOL ldapdb_get_uint32(LDAPDB *hds, const char *attribute, uint32 *val)
{
	fstring temp;
	BOOL ret;

	ret = ldapdb_get_value(hds, attribute, temp, sizeof(temp)-1);
	if (ret)
	{
		*val = strtol(temp, NULL, 10);
		if ((*val == LONG_MAX || *val == LONG_MIN) && errno == ERANGE)
			ret = False;
		else
			ret = True;
	}

	return ret;
}

BOOL ldapdb_get_unistr_value(LDAPDB *hds, const char *attribute, UNISTR2 *buf)
{
	char **values;

	values = ldap_get_values (hds->conn->ld, hds->entry, attribute);
	if (values == NULL)
	{
		return False;
	}
	if (values[0] == NULL)
	{
		ldap_value_free (values);
		return False;
	}

	utf8_to_unistr2(buf, values[0]);
	DEBUG (3, ("ldapdb_get_unistr_value: [%s] = [%s]\n", attribute, values[0]));

	ldap_value_free (values);

	return True;	
}

/*******************************************************************
  Get values for an attribute, caller frees data
 ******************************************************************/
BOOL 
ldapdb_get_values (LDAPDB * hds, const char *attribute, char ***valuesp)
{
	char **values;

	values = ldap_get_values (hds->conn->ld, hds->entry, attribute);
	if (values == NULL)
	{
		return False;
	}

	if (values[0] == NULL)
	{
		ldap_value_free (values);
		return False;
	}

	DEBUG (3, ("ldap_get_values: [%s] = [%s] ... \n", attribute, values[0]));
	*valuesp = values;

	return True;
}

BOOL ldapdb_oc_check(LDAPDB *hds, const char *ocname)
{
	char **values;
	char **p;

	if (!ldapdb_get_values(hds, "objectClass", &values))
	{
		return False;
	}

	for (p = values; *p != NULL; p++)
	{
		if (!strcasecmp(*p, ocname))
		{
			ldap_value_free(values);
			return True;
		}
	}

	ldap_value_free(values);
	return False;
}

BOOL 
ldapdb_get_value_len (LDAPDB * hds, const char *attribute, struct berval ** value)
{
	struct berval **values;

	values = ldap_get_values_len (hds->conn->ld, hds->entry, attribute);
	if (values == NULL)
	{
		return False;
	}

	if (values[0] == NULL)
	{
		ldap_value_free_len (values);
		return False;
	}

	*value = ber_bvdup (values[0]);
	if (*value == NULL)
	{
		ldap_value_free_len (values);
		return False;
	}

	ldap_value_free_len (values);

	return True;
}


BOOL 
ldapdb_get_values_len (LDAPDB * hds, const char *attribute, struct berval *** valuep)
{
	struct berval **values;

	values = ldap_get_values_len (hds->conn->ld, hds->entry, attribute);
	if (values == NULL)
	{
		return False;
	}

	if (values[0] == NULL)
	{
		ldap_value_free_len (values);
		return False;
	}

	*valuep = values;

	return True;
}

/*******************************************************************
  Get the "objectSid" attribute and decode into a DOM_SID
 ******************************************************************/
BOOL 
ldapdb_get_sid (LDAPDB * hds, const char *attribute, DOM_SID * sid)
{
	struct berval **bv;
	BOOL ret;

	bv = ldap_get_values_len (hds->conn->ld, hds->entry, attribute);
	if (bv == NULL)
	{
		return False;
	}

	ret = berval_to_sid (bv[0], sid);
	ldap_value_free_len (bv);

	return ret;
}

BOOL 
ldapdb_get_sids (LDAPDB * hds, const char *attribute, DOM_SID *** sid)
{
	struct berval **bv;
	int i, nsids;

	bv = ldap_get_values_len (hds->conn->ld, hds->entry, attribute);
	if (bv == NULL)
	{
		return False;
	}

	nsids = ldap_count_values_len (bv);
	*sid = calloc (nsids, sizeof (DOM_SID *));
	if (*sid == NULL)
	{
		ldap_value_free_len (bv);
		return False;
	}

	for (i = 0; i < nsids; i++)
	{
		(*sid)[i] = malloc (sizeof (DOM_SID));
		if ((*sid)[i] == NULL)
		{
			ldap_value_free_len (bv);
			return False;
		}
		if (!berval_to_sid (bv[i], (*sid)[i]))
		{
			ldap_value_free_len (bv);
			/* leaks */
			return False;
		}
	}

	ldap_value_free_len (bv);
	return True;
}

/*******************************************************************
  Get the "objectSid" attribute and decode into a RID
 ******************************************************************/
BOOL 
ldapdb_get_rid (LDAPDB * hds, const char *attribute, uint32 * rid)
{
	struct berval **bv;
	BOOL ret;

	bv = ldap_get_values_len (hds->conn->ld, hds->entry, attribute);
	if (bv == NULL)
	{
		return False;
	}

	ret = berval_to_rid (bv[0], rid);
	ldap_value_free_len (bv);

	return ret;
}

/************************************************************************
Adds a binary modification to a LDAPMod queue.
************************************************************************/

BOOL 
ldapdb_queue_mod_len (LDAPMod *** modlist, int modop, const char *attribute, struct berval * value)
{
	LDAPMod **mods;
	int i;
	int j;

	mods = *modlist;

	if (mods == NULL)
	{
		mods = (LDAPMod **) malloc (sizeof (LDAPMod *));
		if (mods == NULL)
		{
			return False;
		}
		mods[0] = NULL;
	}

	for (i = 0; mods[i] != NULL; ++i)
	{
		if ((mods[i]->mod_op & (~LDAP_MOD_BVALUES)) == modop &&
		    !strcasecmp (mods[i]->mod_type, attribute))
		{
			break;
		}
	}

	if (mods[i] == NULL)
	{
		mods = (LDAPMod **) realloc (mods, (i + 2) * sizeof (LDAPMod *));
		if (mods == NULL)
		{
			if (*modlist)
			{
				ldap_mods_free(*modlist, 1);
				*modlist = NULL;
			}
			return False;
		}
		mods[i] = (LDAPMod *) malloc (sizeof (LDAPMod));
		if (mods[i] == NULL)
		{
			if (*modlist)
			{
				ldap_mods_free(*modlist, 1);
				*modlist = NULL;
			}
			return False;
		}
		mods[i]->mod_op = modop | LDAP_MOD_BVALUES;
		mods[i]->mod_bvalues = NULL;
		mods[i]->mod_type = strdup (attribute);
		mods[i + 1] = NULL;
	}

	if (value)
	{
		j = 0;
		if (mods[i]->mod_values)
		{
			for (; mods[i]->mod_values[j]; j++);
		}
		mods[i]->mod_bvalues = (struct berval **) realloc (mods[i]->mod_values,
					(j + 2) * sizeof (struct berval *));
		if (mods[i]->mod_bvalues == NULL)
		{
			if (*modlist)
			{
				ldap_mods_free(*modlist, 1);
				*modlist = NULL;
			}
			return False;
		}
		/* caller relinquishes ownership of value */
		mods[i]->mod_bvalues[j] = value;
		mods[i]->mod_bvalues[j + 1] = NULL;
	}

	*modlist = mods;
	return True;
}

/************************************************************************
Adds a modification to a LDAPMod queue.
************************************************************************/
BOOL 
ldapdb_queue_mod (LDAPMod *** modlist, int modop, const char *attribute, const char *value)
{
	LDAPMod **mods;
	int i;
	int j;

	DEBUG (3, ("set: [%s] = [%s]\n", attribute, value));

	mods = *modlist;

	if (mods == NULL)
	{
		mods = (LDAPMod **) malloc (sizeof (LDAPMod *));
		if (mods == NULL)
		{
			return False;
		}
		mods[0] = NULL;
	}

	for (i = 0; mods[i] != NULL; ++i)
	{
		if (mods[i]->mod_op == modop &&
		    !strcasecmp (mods[i]->mod_type, attribute))
		{
			break;
		}
	}

	if (mods[i] == NULL)
	{
		mods = (LDAPMod **) realloc (mods, (i + 2) * sizeof (LDAPMod *));
		if (mods == NULL)
		{
			if (*modlist)
			{
				ldap_mods_free(*modlist, 1);
				*modlist = NULL;
			}
			return False;
		}
		mods[i] = (LDAPMod *) malloc (sizeof (LDAPMod));
		if (mods[i] == NULL)
		{
			if (*modlist)
			{
				ldap_mods_free(*modlist, 1);
				*modlist = NULL;
			}
			return False;
		}
		mods[i]->mod_op = modop;
		mods[i]->mod_values = NULL;
		mods[i]->mod_type = strdup (attribute);
		mods[i + 1] = NULL;
	}

	if (value)
	{
		j = 0;
		if (mods[i]->mod_values)
		{
			for (; mods[i]->mod_values[j]; j++);
		}
		mods[i]->mod_values = (char **) realloc (mods[i]->mod_values,
						 (j + 2) * sizeof (char *));
		if (mods[i]->mod_values == NULL)
		{
			if (*modlist)
			{
				ldap_mods_free(*modlist, 1);
				*modlist = NULL;
			}
			return False;
		}
		mods[i]->mod_values[j] = strdup (value);
		if (mods[i]->mod_values[j] == NULL)
		{
			if (*modlist)
			{
				ldap_mods_free(*modlist, 1);
				*modlist = NULL;
			}
			return False;
		}
		mods[i]->mod_values[j + 1] = NULL;
	}

	*modlist = mods;

	return True;
}

BOOL ldapdb_queue_unistr_mod(LDAPMod ***modlist,int modop, const char *attribute, const UNISTR2 *value)
{
	pstring buffer;
	
	if (value == NULL)
	{
		/* silently fail */
		return True;
	}

	unistr2_to_utf8(buffer, value, sizeof(buffer)-1);

	return ldapdb_queue_mod(modlist, modop, attribute, buffer);
}

BOOL ldapdb_queue_uint32_mod(LDAPMod ***modlist, int modop, const char *attribute, uint32 value)
{
	fstring buffer;

	slprintf(buffer, sizeof(buffer)-1, "%u", value);

	return ldapdb_queue_mod(modlist, modop, attribute, buffer);
}

/************************************************************************
  Update a directory entry, creating if needed / desired. Creates
  the DN based on the supplied attribute/value, if we're creating an
  entry.
*************************************************************************/
BOOL 
ldapdb_update (PLDAPDB _hds, const char *where, const char *rdnattr, const char *rdnvalue, LDAPMod ** mods, BOOL isadd)
{
	pstring filter;
	LDAPDB *hds;
	BOOL ret;
	BOOL create;
	char *dn;
	pstring pdn;

	if (!LDAPDB_OPEN (_hds, &hds))
	{
		return False;
	}

	slprintf (filter, sizeof (filter) - 1, "(%s=%s)", rdnattr, rdnvalue);
	if (!ldapdb_search (hds, where, filter, NULL, 1))
	{
		pstring dnbuf;

		if (isadd == False)
		{
			/* The entry doesn't exist, we don't want to create it. */
			DEBUG (3, ("update: [%s] in [%s] doesn't exist, isadd=[%d]\n", filter, where, isadd));
			ldapdb_close (&hds);
			return False;
		}

		/* create */
		slprintf (pdn, sizeof (pdn) - 1, "%s=%s,%s", rdnattr, rdnvalue, __ldapdb_compose_dn (where, dnbuf));
		DEBUG (3, ("update: composed dn [%s]\n", pdn));
		create = True;
		dn = pdn;
	}
	else
	{
		create = False;
		dn = ldap_get_dn (hds->conn->ld, hds->entry);
		DEBUG (3, ("update: using dn [%s]", dn));
	}

	ret = ldapdb_commit (hds, dn, mods, create);
	if (!create)
	{
		free (dn);
	}

	ldapdb_close (&hds);

	return ret;
}

/************************************************************************
  Update/create an entry in the directory
*************************************************************************/
BOOL 
ldapdb_commit (LDAPDB * hds, const char *dn, LDAPMod ** mods, BOOL add)
{
	int err;
	BOOL ret;

	if (add)
	{
		/* Generate a GUID. */
		struct berval *uuid;
	
		uuid = (struct berval *)malloc(sizeof(*uuid));
		if (uuid == NULL)
		{
			free(uuid);
		}

		/* this isn't strictly correct, it will have to do for now */
		uuid->bv_len = 16;
		uuid->bv_val = malloc(uuid->bv_len);
		if (uuid->bv_val == NULL)
		{
			free(uuid);
			return False;
		}

		generate_random_buffer(uuid->bv_val, uuid->bv_len, False);
		if (!ldapdb_queue_mod_len(&mods, LDAP_MOD_ADD, "objectGuid", uuid))
		{
			ber_bvfree(uuid);
			return False;
		}

		err = ldap_add_s (hds->conn->ld, dn, mods);
	}
	else
	{
		err = ldap_modify_s (hds->conn->ld, dn, mods);
	}

	if (err == LDAP_SUCCESS)
	{
		DEBUG (2, ("%s entry [%s]\n", (add ? "Added" : "Modified"), dn));
		ret = True;
	}
	else
	{
		DEBUG (0, ("%s: %s\n", (add ? "ldap_add_s" : "ldap_modify_s"), ldap_err2string (err)));
		ret = False;
	}

	ldap_mods_free (mods, 1);

	return ret;
}

/************************************************************************
Return next available RID, starting from 1000
************************************************************************/

BOOL 
ldapdb_allocate_rid (PLDAPDB _hds, uint32 * rid)
{
	fstring rid_str;
	LDAPMod **mods = NULL;
	LDAPDB *hds;
	char *attrs[] =
	{"nextRid", NULL};
	BOOL newdomain, ret;

	DEBUG (2, ("Allocating new RID\n"));

	if (!LDAPDB_OPEN (_hds, &hds))
	{
		return False;
	}

	if (__ldapdb_search (hds, lp_ldap_suffix (), LDAP_SCOPE_BASE, "(objectClass=domain)", attrs, 1) &&
	    ldapdb_get_fvalue (hds, "nextRid", rid_str))
	{
		*rid = strtol (rid_str, NULL, 10);
		newdomain = False;
	}
	else
	{
		*rid = 1000;
		newdomain = True;
	}

	if (newdomain)
	{
		if (!ldapdb_queue_mod (&mods, LDAP_MOD_ADD, "objectClass", "top") ||
		    !ldapdb_queue_mod (&mods, LDAP_MOD_ADD, "objectClass", "samDomain"))
		{
			ldapdb_close (&hds);
			return False;
		}
	}

	slprintf (rid_str, sizeof (fstring) - 1, "%u", (*rid) + 1);
	if (!ldapdb_queue_mod (&mods, LDAP_MOD_REPLACE, "nextRid", rid_str))
	{
		ldapdb_close (&hds);
		return False;
	}

	ret = ldapdb_commit (hds, lp_ldap_suffix (), mods, newdomain);

	ldapdb_close (&hds);

	return ret;
}

/*******************************************************************
  Decode an objectSid attribute
 ******************************************************************/

BOOL 
berval_to_sid (const struct berval * bv, DOM_SID * sid)
{

	prs_struct ps;
	BOOL ret;

	if (bv == NULL)
	{
		return False;
	}

	memset (sid, 0, sizeof(*sid));

	/* True for reading */
	prs_create (&ps, bv->bv_val, bv->bv_len, 4, True);

	ret = smb_io_dom_sid ("berval_to_sid", sid, &ps, 0);

	if (ret)
	{
		fstring sid_str;
		sid_to_string (sid_str, sid);
		DEBUG (3, ("berval_to_sid: bv->len = [%ld] SID = [%s]\n", bv->bv_len, sid_str));
	}
	else
	{
		DEBUG (3, ("berval_to_sid: smb_io_dom_sid failed\n"));
	}

	return ret;
}

BOOL 
sid_to_berval (const DOM_SID * sid, struct berval ** siddata)
{
	prs_struct ps;
	struct berval *bv;
	BOOL ret;

	bv = (struct berval *) malloc (sizeof (struct berval));
	if (bv == NULL)
	{
		return False;
	}

	prs_init (&ps, 0, 4, False);
	ret = smb_io_dom_sid ("sid_to_berval", (DOM_SID *) sid, &ps, 0);
	if (ret == False)
	{
		prs_free_data(&ps);
		free (bv);
		return False;
	}

	bv->bv_val = prs_data (&ps, 0);
	bv->bv_len = prs_buf_len (&ps);		/* ps.offset */

	*siddata = bv;

	return True;
}

BOOL 
berval_to_rid (struct berval * siddata, uint32 * rid)
{
	DOM_SID sid;

	if (berval_to_sid (siddata, &sid) == False)
	{
		return False;
	}

	if (!sid_front_equal (&global_sam_sid, &sid))
	{
		fstring sid_str;
		sid_to_string (sid_str, &sid);
		DEBUG (0, ("berval_to_rid: SID %s is in the wrong domain\n", sid_str));
		return False;
	}


	sid_split_rid (&sid, rid);

	return True;
}

BOOL 
rid_to_berval (uint32 rid, struct berval ** siddata)
{
	DOM_SID sid;

	sid_copy (&sid, &global_sam_sid);
	if (sid_append_rid (&sid, rid) == False)
	{
		return False;
	}

	return sid_to_berval (&sid, siddata);
}

/*
 * XXX This is most likely VERY broken
 */
BOOL 
berval_to_unicodepwd (const struct berval * bv, uint8 smbntpwd[16])
{
	if (bv->bv_len != 16)
	{
		return False;
	}

	memcpy (smbntpwd, bv->bv_val, bv->bv_len);

	return True;
}

BOOL 
berval_to_dbcspwd (const struct berval * bv, uint8 smblmpwd[16])
{
	return berval_to_unicodepwd (bv, smblmpwd);
}

BOOL 
unicodepwd_to_berval (const uint8 smbntpwd[16], struct berval ** bvp)
{
	struct berval *bv = (struct berval *) malloc (sizeof (struct berval));
	if (bv == NULL)
	{
		return False;
	}

	bv->bv_len = 16;
	bv->bv_val = malloc (16);
	if (bv->bv_val == NULL)
	{
		free (bv);
		return False;
	}

	memcpy (bv->bv_val, smbntpwd, 16);
	*bvp = bv;

	return True;
}

BOOL 
dbcspwd_to_berval (const uint8 smblmpwd[16], struct berval ** bvp)
{
	return unicodepwd_to_berval (smblmpwd, bvp);
}

/*******************************************************************
  dc=foo,dc=tld to foo.tld mapping
 ******************************************************************/
BOOL 
ldapdb_dnsdomain_to_dn (const char *domain_in, pstring dn)
{
	char *domain, *s;
	BOOL comma;

	if (domain_in == NULL)
	{
		return False;
	}

	domain = strdup (domain_in);
	if (domain == NULL)
	{
		return False;
	}

	dn = NULL;
	comma = False;

	for (s = strtok (domain, "."); s != NULL; s = strtok (NULL, "."))
	{
		if (comma)
		{
			pstrcat (dn, ",");
		}
		else
		{
			comma = True;
		}

		pstrcat (dn, "dc=");
		pstrcat (dn, s);
	}

	free (domain);

	DEBUG (3, ("ldapdb_dnsdomain_to_dn [%s] -> [%s]\n", domain_in, dn));

	return True;
}

BOOL 
ldapdb_dn_to_dnsdomain (const char *dn, pstring dnsdomain)
{
	char **dnc, **p;
	BOOL dot = False;

	dnc = ldap_explode_dn (dn, 0);
	if (dnc == NULL)
	{
		return False;
	}

	dnsdomain[0] = '\0';

	for (p = dnc; *p != NULL; p++)
	{
		if (!strncasecmp (*p, "dc=", 3))
		{
			if (dot)
			{
				pstrcat (dnsdomain, ".");
			}
			else
			{
				dot = True;
			}
			pstrcat (dnsdomain, *p + 3);
		}
	}

	ldap_value_free (dnc);

	DEBUG (3, ("ldapdb_dn_to_dnsdomain [%s] -> [%s]\n", dn, dnsdomain));

	return True;
}

/*******************************************************************
  Lookup the SAM account name for a DN
 ******************************************************************/
BOOL 
ldapdb_dn_to_ntname (PLDAPDB _hds, const char *dn, pstring ntname)
{
	char *attrs[] =
	{"sAMAccountName", NULL};
	LDAPDB *hds;
	BOOL ret;

	if (!LDAPDB_OPEN (_hds, &hds))
	{
		return False;
	}

	if (!ldapdb_read (hds, dn, attrs))
	{
		ldapdb_close (&hds);
		return False;
	}

	ret = ldapdb_get_pvalue (hds, "sAMAccountName", ntname);

	ldapdb_close (&hds);

	return ret;
}


/*******************************************************************
  Lookup the domain SID and NetBIOS name
 ******************************************************************/
BOOL ldapdb_get_domain_info(PLDAPDB _hds, const char *realm, DOM_SID *sid, fstring nbname)
{
	LDAPDB *hds;
	char *attrs[] = {"objectSid", NULL};
	BOOL ret;

	if (!LDAPDB_OPEN (_hds, &hds))
	{
		return False;
	}

	if (!__ldapdb_search (hds, realm, LDAP_SCOPE_BASE, "(objectClass=samDomain)", attrs, 1))
	{
		ldapdb_close (&hds);
		return False;
	}

	ret = True;
	if ( sid )
	{
		ret = ldapdb_get_sid (hds, "objectSid", sid);
	}
	if ( ret )
	{
		ret = ldapdb_get_pvalue (hds, "nETBIOSName", nbname );
	}

	ldapdb_close (&hds);

	return ret;
}

/*******************************************************************
  Lookup DN for a filter
 ******************************************************************/
BOOL 
ldapdb_lookup_name (PLDAPDB _hds, const char *context, const char *filter, pstring dn)
{
	char *tdn;
	LDAPDB *hds;
	char *const *nothing =
	{NULL};

	if (!LDAPDB_OPEN (_hds, &hds))
	{
		return False;
	}

	if (!ldapdb_search (hds, context, filter, nothing, 1))
	{
		ldapdb_close (&hds);
		return False;
	}

	if (!ldapdb_get_dn (hds, &tdn))
	{
		ldapdb_close (&hds);
		return False;
	}

	pstrcpy (dn, tdn);
	free (tdn);
	ldapdb_close (&hds);

	return True;
}

/*******************************************************************
  Lookup DN for a SAM accoun
 ******************************************************************/
BOOL 
ldapdb_ntname_to_dn (PLDAPDB hds, const char *ntname, pstring dn)
{
	pstring filter;

	slprintf (filter, sizeof (filter) - 1, "(sAMAccountName=%s)", ntname);

	return ldapdb_lookup_name (hds, NULL, filter, dn);
}

/*******************************************************************
  Lookup DN for a SID
 ******************************************************************/
static void
berval_to_filter(struct berval *bv, pstring data_out)
{
	int i;

	for (i = 0; i < bv->bv_len; i++)
	{
		slprintf (&data_out[3 * i], sizeof (data_out) - 1 - 3 * (bv->bv_len - i), "\\%02x", bv->bv_val[i]);
	}
}

BOOL 
ldapdb_make_sid_filter (const char *attribute, const DOM_SID * sid, fstring filter)
{
	struct berval *bv;
	pstring binsid;

	if (!sid_to_berval (sid, &bv))
	{
		return False;
	}

	berval_to_filter(bv, binsid);

	slprintf (filter, sizeof (fstring) - 1, "%s=%s", attribute, binsid);
	ber_bvfree (bv);

	return True;
}

BOOL 
ldapdb_make_rid_filter (const char *attribute, uint32 rid, fstring filter)
{
	DOM_SID sid;

	sid_copy (&sid, &global_sam_sid);
	if (sid_append_rid (&sid, rid) == False)
	{
		return False;
	}

	return ldapdb_make_sid_filter (attribute, &sid, filter);
}

BOOL 
ldapdb_sid_to_dn (PLDAPDB hds, const DOM_SID * sid, pstring dn)
{
	pstring filter;

	if (ldapdb_make_sid_filter ("objectSid", sid, filter))
	{
		return False;
	}

	return ldapdb_lookup_name (hds, NULL, filter, dn);
}

BOOL 
ldapdb_rid_to_dn (PLDAPDB hds, uint32 rid, pstring dn)
{
	DOM_SID sid;

	sid_copy (&sid, &global_sam_sid);
	if (sid_append_rid (&sid, rid) == False)
	{
		return False;
	}

	return ldapdb_sid_to_dn (hds, &sid, dn);
}

const char *
ldapdb_get_realm_name (void)
{
	static pstring dnsRealm;
	static char *cachedRealm = NULL;
	char *lpRealm;
	char *ret = NULL;

	if (cachedRealm)
	{
		ret = cachedRealm;
	}
	else if ((lpRealm = lp_ldap_realm ()) && lpRealm[0] != '\0')
	{
		ret = (cachedRealm = lpRealm);
	}
	else if (ldapdb_dn_to_dnsdomain (lp_ldap_suffix (), dnsRealm))
	{
		ret = (cachedRealm = dnsRealm);
	}

	if (ret)
	{
		DEBUG (3, ("ldapdb_get_realm_name() [%s]\n", ret));
	}

	return ret;
}

BOOL 
ldapdb_lookup_by_sid (LDAPDB * hds, const DOM_SID * sid)
{
	/* hmm. how do we do this? */
	fstring filter, sidfilter;

	if (!ldapdb_make_sid_filter ("objectSid", sid, sidfilter))
	{
		return False;
	}

	slprintf (filter, sizeof (filter) - 1, "(%s)", sidfilter);

	return ldapdb_search (hds, NULL, filter, NULL, 1);
}

BOOL 
ldapdb_lookup_by_rid (LDAPDB * hds, uint32 rid)
{
	DOM_SID sid;

	sid_copy (&sid, &global_sam_sid);
	if (sid_append_rid (&sid, rid) == False)
	{
		return False;
	}

	return ldapdb_lookup_by_sid(hds, &sid);
}

BOOL
ldapdb_lookup_by_netbiosname (LDAPDB *hds, const char *nbname)
{
	fstring filter;

	slprintf (filter, sizeof (filter) - 1, "(nETBIOSName=%s)", nbname);

	return ldapdb_search (hds, NULL, filter, NULL, 1);
}

BOOL 
ldapdb_lookup_by_ntname (LDAPDB * hds, const char *ntname)
{
	fstring filter;

	slprintf (filter, sizeof (filter) - 1, "(sAMAccountName=%s)", ntname);

	return ldapdb_search (hds, NULL, filter, NULL, 1);
}

BOOL 
ldapdb_lookup_by_posix_name (LDAPDB * hds, const char *user)
{
	fstring filter;

	slprintf (filter, sizeof (filter) - 1, "(&(objectClass=User)(|(mSSFUName=%s)(uid=%s)))", user, user);

	return ldapdb_search (hds, NULL, filter, NULL, 1);
}

BOOL 
ldapdb_lookup_by_posix_uid (LDAPDB * hds, uid_t uid)
{
	fstring filter;

	slprintf (filter, sizeof (filter) - 1, "(&(objectClass=User)(uidNumber=%d))", uid);

	return ldapdb_search (hds, NULL, filter, NULL, 1);
}

BOOL 
ldapdb_lookup_by_posix_gid (LDAPDB * hds, gid_t gid)
{
	fstring filter;

	slprintf (filter, sizeof (filter) - 1, "(&(objectClass=User)(gidNumber=%d))", gid);

	return ldapdb_search (hds, NULL, filter, NULL, 1);
}
BOOL 
ldapdb_queue_time (LDAPMod *** modlist, int modop, const char *attribute,
		   NTTIME * nttime)
{
	SMB_BIG_UINT tval;
	fstring tstr;
	NTTIME tmp;
	size_t len;

	if (nttime == NULL)
	{
		unix_to_nt_time (&tmp, time (NULL));
		nttime = &tmp;
	}

	/* XXX needs fixing */
	len = (sizeof (SMB_BIG_UINT) < sizeof (NTTIME)) ? sizeof (SMB_BIG_UINT) : sizeof (NTTIME);
	memcpy (&tval, nttime, len);

	/* XXX non portable */
	slprintf (tstr, sizeof (tstr) - 1, "%Lu", tval);

	return ldapdb_queue_mod (modlist, modop, attribute, tstr);
}

BOOL 
ldapdb_parse_time (const char *timestr, NTTIME * nttime)
{
	SMB_BIG_UINT tval;
	size_t len;

	/* set it to some reasonable value */
	init_nt_time (nttime);

	len = (sizeof (SMB_BIG_UINT) < sizeof (NTTIME)) ? sizeof (SMB_BIG_UINT) : sizeof (NTTIME);

	tval = strtouq (timestr, NULL, 10);
	memcpy (nttime, &tval, len);

	return True;
}

BOOL 
ldapdb_get_time (LDAPDB * hds, const char *attr, NTTIME * nttime)
{
	fstring timestr;

	if (!ldapdb_get_fvalue (hds, attr, timestr))
	{
		return False;
	}

	return ldapdb_parse_time (timestr, nttime);
}

void unistr2_to_utf8(char *dest, const UNISTR2 *str, size_t maxlen)
{
#ifdef LDAP_UNICODE
	char *end = dest + maxlen;
	uint16 *ubuf;

	ubuf = str->buffer;

	while (dest < end)
	{
		if (*ubuf < 0x100)
		{
			/* ASCII */
			*(dest++) =
		}
		else
		{
			/* Not ASCII */
		}
		++ubuf;
	}

#else
	unistr2_to_ascii(dest, str, maxlen);
#endif /* LDAP_UNICODE */
}

void utf8_to_unistr2(UNISTR2 *unistr, const char *str)
{
#ifdef LDAP_UNICODE
	extern unsigned long ldap_utf8_chars(const char *);
	extern int ldap_utf8_charlen(const char *);
	ZERO_STRUCTP(str);
	char *dest, *end;
	size_t maxlen = ldap_utf8_chars(str);

	if (maxlen > MAX_UNISTRLEN - 1)
	{
		maxlen = MAX_UNISTRLEN - 1;
	}

	unistr->uni_max_len = maxlen;
	unistr->undoc = 0;
	unistr->uni_str_len = maxlen;

	dest = unistr->buffer;
	end = dest + unistr->uni_max_len;

	while (dest < end)
	{
		switch ( ldap_utf8_charlen(utf) )
		{
			case 0:
				break;
			case 1:
				*(dest++) = *utf;
				*(dest++) = 0;
				break;
			case 2:
				*(dest++) = *utf;
				*(dest++) = *(utf + 1);
				break;
			default
				break;
		}
		utf = ldap_utf8_next(utf);
	}

	*dest++ = 0;
	*dest++ = 0;
#else
	ascii_to_unistr(unistr->buffer, str, sizeof(unistr->buffer)-1);
#endif /* LDAP_UNICODE */
}

#else
void ldapdb_dummy_function (void);
void 
ldapdb_dummy_function (void)
{
}				/* stop some compilers complaining */
#endif
