/* 
   Unix SMB/CIFS implementation.
   Samba utility functions
   Copyright (C) Andrew Tridgell 		1992-1998
   Copyright (C) Luke Kenneth Caseson Leighton 	1998-1999
   Copyright (C) Jeremy Allison  		1999
   Copyright (C) Stefan (metze) Metzmacher 	2002
      
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

extern pstring global_myname;
extern fstring global_myworkgroup;

/*
 * Some useful sids
 */

DOM_SID global_sid_Builtin; 				/* Local well-known domain */
DOM_SID global_sid_World_Domain;	    	/* Everyone domain */
DOM_SID global_sid_World;    				/* Everyone */
DOM_SID global_sid_Creator_Owner_Domain;    /* Creator Owner domain */
DOM_SID global_sid_NT_Authority;    		/* NT Authority */
DOM_SID global_sid_NULL;            		/* NULL sid */
DOM_SID global_sid_Builtin_Guests;			/* Builtin guest users */
DOM_SID global_sid_Authenticated_Users;		/* All authenticated rids */
DOM_SID global_sid_Network;					/* Network rids */

static DOM_SID global_sid_Creator_Owner;    		/* Creator Owner */
static DOM_SID global_sid_Creator_Group;              /* Creator Group */
static DOM_SID global_sid_Anonymous;				/* Anonymous login */

/*
 * An NT compatible anonymous token.
 */

static DOM_SID anon_sid_array[3];

NT_USER_TOKEN anonymous_token = {
    3,
    anon_sid_array
};

/****************************************************************************
 Lookup string names for SID types.
****************************************************************************/

const static struct {
	enum SID_NAME_USE sid_type;
	char *string;
} sid_name_type[] = {
	{SID_NAME_USER, "user"},
	{SID_NAME_DOM_GRP, "domain group"},
	{SID_NAME_DOMAIN, "domain"},
	{SID_NAME_ALIAS, "local group"},
	{SID_NAME_WKN_GRP, "well-known group"},
	{SID_NAME_DELETED, "deleted account"},
	{SID_NAME_INVALID, "invalid account"},
	{SID_NAME_UNKNOWN, "UNKNOWN"},

 	{SID_NAME_USE_NONE, NULL}
};

const char *sid_type_lookup(uint32 sid_type) 
{
	int i = 0;

	/* Look through list */
	while(sid_name_type[i].sid_type != 0) {
		if (sid_name_type[i].sid_type == sid_type)
			return sid_name_type[i].string;
		i++;
	}

	/* Default return */
	return "SID *TYPE* is INVALID";
	
}


/****************************************************************************
 Creates some useful well known sids
****************************************************************************/

void generate_wellknown_sids(void)
{
	string_to_sid(&global_sid_Builtin, "S-1-5-32");
	string_to_sid(&global_sid_Builtin_Guests, "S-1-5-32-546");
	string_to_sid(&global_sid_World_Domain, "S-1-1");
	string_to_sid(&global_sid_World, "S-1-1-0");
	string_to_sid(&global_sid_Creator_Owner_Domain, "S-1-3");
	string_to_sid(&global_sid_Creator_Owner, "S-1-3-0");
	string_to_sid(&global_sid_Creator_Group, "S-1-3-1");
	string_to_sid(&global_sid_NT_Authority, "S-1-5");
	string_to_sid(&global_sid_NULL, "S-1-0-0");
	string_to_sid(&global_sid_Authenticated_Users, "S-1-5-11");
	string_to_sid(&global_sid_Network, "S-1-5-2");
	string_to_sid(&global_sid_Anonymous, "S-1-5-7");

	/* Create the anon token. */
	sid_copy( &anonymous_token.user_sids[0], &global_sid_World);
	sid_copy( &anonymous_token.user_sids[1], &global_sid_Network);
	sid_copy( &anonymous_token.user_sids[2], &global_sid_Anonymous);
}

/**************************************************************************
 Splits a name of format \DOMAIN\name or name into its two components.
 Sets the DOMAIN name to global_myname if it has not been specified.
***************************************************************************/

void split_domain_name(const char *fullname, char *domain, char *name)
{
	pstring full_name;
	char *p, *sep;

	sep = lp_winbind_separator();

	*domain = *name = '\0';

	if (fullname[0] == sep[0] || fullname[0] == '\\')
		fullname++;

	pstrcpy(full_name, fullname);
	p = strchr_m(full_name+1, '\\');
	if (!p) p = strchr_m(full_name+1, sep[0]);

	if (p != NULL) {
		*p = 0;
		fstrcpy(domain, full_name);
		fstrcpy(name, p+1);
	} else {
		fstrcpy(domain, global_myname);
		fstrcpy(name, full_name);
	}

	DEBUG(10,("split_domain_name:name '%s' split into domain :'%s' and user :'%s'\n",
			fullname, domain, name));
}

/*****************************************************************
 Convert a SID to an ascii string.
*****************************************************************/

char *sid_to_string(fstring sidstr_out, const DOM_SID *sid)
{
  char subauth[16];
  int i;
  uint32 ia;
  
  if (!sid) {
	  fstrcpy(sidstr_out, "(NULL SID)");
	  return sidstr_out;
  }

  /* BIG NOTE: this function only does SIDS where the identauth is not >= 2^32 */
  ia = (sid->id_auth[5]) +
	  (sid->id_auth[4] << 8 ) +
	  (sid->id_auth[3] << 16) +
	  (sid->id_auth[2] << 24);

  slprintf(sidstr_out, sizeof(fstring) - 1, "S-%u-%lu", (unsigned int)sid->sid_rev_num, (unsigned long)ia);

  for (i = 0; i < sid->num_auths; i++) {
    slprintf(subauth, sizeof(subauth)-1, "-%lu", (unsigned long)sid->sub_auths[i]);
    fstrcat(sidstr_out, subauth);
  }

  return sidstr_out;
}

/*
  useful function for debug lines
*/
const char *sid_string_static(const DOM_SID *sid)
{
	static fstring sid_str;
	sid_to_string(sid_str, sid);
	return sid_str;
}

/*****************************************************************
 Convert a string to a SID. Returns True on success, False on fail.
*****************************************************************/  
   
BOOL string_to_sid(DOM_SID *sidout, const char *sidstr)
{
  pstring tok;
  char *p, *q;
  /* BIG NOTE: this function only does SIDS where the identauth is not >= 2^32 */
  uint32 ia;
  
  if (StrnCaseCmp( sidstr, "S-", 2)) {
    DEBUG(0,("string_to_sid: Sid %s does not start with 'S-'.\n", sidstr));
    return False;
  }

  memset((char *)sidout, '\0', sizeof(DOM_SID));

  q = p = strdup(sidstr + 2);
  if (p == NULL) {
    DEBUG(0, ("string_to_sid: out of memory!\n"));
    return False;
  }

  if (!next_token(&p, tok, "-", sizeof(tok))) {
    DEBUG(0,("string_to_sid: Sid %s is not in a valid format.\n", sidstr));
    SAFE_FREE(q);
    return False;
  }

  /* Get the revision number. */
  sidout->sid_rev_num = (uint8)strtoul(tok, NULL, 10);

  if (!next_token(&p, tok, "-", sizeof(tok))) {
    DEBUG(0,("string_to_sid: Sid %s is not in a valid format.\n", sidstr));
    SAFE_FREE(q);
    return False;
  }

  /* identauth in decimal should be <  2^32 */
  ia = (uint32)strtoul(tok, NULL, 10);

  /* NOTE - the ia value is in big-endian format. */
  sidout->id_auth[0] = 0;
  sidout->id_auth[1] = 0;
  sidout->id_auth[2] = (ia & 0xff000000) >> 24;
  sidout->id_auth[3] = (ia & 0x00ff0000) >> 16;
  sidout->id_auth[4] = (ia & 0x0000ff00) >> 8;
  sidout->id_auth[5] = (ia & 0x000000ff);

  sidout->num_auths = 0;

  while(next_token(&p, tok, "-", sizeof(tok)) && 
	sidout->num_auths < MAXSUBAUTHS) {
    /* 
     * NOTE - the subauths are in native machine-endian format. They
     * are converted to little-endian when linearized onto the wire.
     */
	sid_append_rid(sidout, (uint32)strtoul(tok, NULL, 10));
  }

  SAFE_FREE(q);
  return True;
}

/*****************************************************************
 Add a rid to the end of a sid
*****************************************************************/  

BOOL sid_append_rid(DOM_SID *sid, uint32 rid)
{
	if (sid->num_auths < MAXSUBAUTHS) {
		sid->sub_auths[sid->num_auths++] = rid;
		return True;
	}
	return False;
}

/*****************************************************************
 Removes the last rid from the end of a sid
*****************************************************************/  

BOOL sid_split_rid(DOM_SID *sid, uint32 *rid)
{
	if (sid->num_auths > 0) {
		sid->num_auths--;
		*rid = sid->sub_auths[sid->num_auths];
		return True;
	}
	return False;
}

/*****************************************************************
 Return the last rid from the end of a sid
*****************************************************************/  

BOOL sid_peek_rid(const DOM_SID *sid, uint32 *rid)
{
	if (!sid || !rid)
		return False;		
	
	if (sid->num_auths > 0) {
		*rid = sid->sub_auths[sid->num_auths - 1];
		return True;
	}
	return False;
}

/*****************************************************************
 Return the last rid from the end of a sid
 and check the sid against the exp_dom_sid  
*****************************************************************/  

BOOL sid_peek_check_rid(const DOM_SID *exp_dom_sid, const DOM_SID *sid, uint32 *rid)
{
	if (!exp_dom_sid || !sid || !rid)
		return False;
			

	if (sid_compare_domain(exp_dom_sid, sid)!=0){
		*rid=(-1);
		return False;
	}
	
	return sid_peek_rid(sid, rid);
}

/*****************************************************************
 Copies a sid
*****************************************************************/  

void sid_copy(DOM_SID *dst, const DOM_SID *src)
{
	int i;

	ZERO_STRUCTP(dst);

	dst->sid_rev_num = src->sid_rev_num;
	dst->num_auths = src->num_auths;

	memcpy(&dst->id_auth[0], &src->id_auth[0], sizeof(src->id_auth));

	for (i = 0; i < src->num_auths; i++)
		dst->sub_auths[i] = src->sub_auths[i];
}


/*****************************************************************
 Write a sid out into on-the-wire format.
*****************************************************************/  
BOOL sid_linearize(char *outbuf, size_t len, DOM_SID *sid)
{
	size_t i;

	if (len < sid_size(sid))
		return False;

	SCVAL(outbuf,0,sid->sid_rev_num);
	SCVAL(outbuf,1,sid->num_auths);
	memcpy(&outbuf[2], sid->id_auth, 6);
	for(i = 0; i < sid->num_auths; i++)
		SIVAL(outbuf, 8 + (i*4), sid->sub_auths[i]);

	return True;
}

/*****************************************************************
 parse a on-the-wire SID to a DOM_SID
*****************************************************************/  
BOOL sid_parse(char *inbuf, size_t len, DOM_SID *sid)
{
	int i;
	if (len < 8) return False;

	ZERO_STRUCTP(sid);

	sid->sid_rev_num = CVAL(inbuf, 0);
	sid->num_auths = CVAL(inbuf, 1);
	memcpy(sid->id_auth, inbuf+2, 6);
	if (len < 8 + sid->num_auths*4) return False;
	for (i=0;i<sid->num_auths;i++) {
		sid->sub_auths[i] = IVAL(inbuf, 8+i*4);
	}
	return True;
}


/*****************************************************************
 Compare the auth portion of two sids.
*****************************************************************/  
static int sid_compare_auth(const DOM_SID *sid1, const DOM_SID *sid2)
{
	int i;

	if (sid1 == sid2) return 0;
	if (!sid1) return -1;
	if (!sid2) return 1;

	if (sid1->sid_rev_num != sid2->sid_rev_num)
		return sid1->sid_rev_num - sid2->sid_rev_num;

	for (i = 0; i < 6; i++)
		if (sid1->id_auth[i] != sid2->id_auth[i])
			return sid1->id_auth[i] - sid2->id_auth[i];

	return 0;
}

/*****************************************************************
 Compare two sids.
*****************************************************************/  
int sid_compare(const DOM_SID *sid1, const DOM_SID *sid2)
{
	int i;

	if (sid1 == sid2) return 0;
	if (!sid1) return -1;
	if (!sid2) return 1;

	/* compare most likely different rids, first: i.e start at end */
	if (sid1->num_auths != sid2->num_auths)
		return sid1->num_auths - sid2->num_auths;

	for (i = sid1->num_auths-1; i >= 0; --i)
		if (sid1->sub_auths[i] != sid2->sub_auths[i])
			return sid1->sub_auths[i] - sid2->sub_auths[i];

	return sid_compare_auth(sid1, sid2);
}

/*****************************************************************
see if 2 SIDs are in the same domain
this just compares the leading sub-auths
*****************************************************************/  
int sid_compare_domain(const DOM_SID *sid1, const DOM_SID *sid2)
{
	int n, i;

	n = MIN(sid1->num_auths, sid2->num_auths);

	for (i = n-1; i >= 0; --i)
		if (sid1->sub_auths[i] != sid2->sub_auths[i])
			return sid1->sub_auths[i] - sid2->sub_auths[i];

	return sid_compare_auth(sid1, sid2);
}

/*****************************************************************
 Compare two sids.
*****************************************************************/  
BOOL sid_equal(const DOM_SID *sid1, const DOM_SID *sid2)
{
	return sid_compare(sid1, sid2) == 0;
}



/*****************************************************************
 Check if the SID is the builtin SID (S-1-5-32).
*****************************************************************/  
BOOL sid_check_is_builtin(const DOM_SID *sid)
{
	return sid_equal(sid, &global_sid_Builtin);
}


/*****************************************************************
 Check if the SID is our domain SID (S-1-5-21-x-y-z).
*****************************************************************/  
BOOL sid_check_is_in_builtin(const DOM_SID *sid)
{
	DOM_SID dom_sid;
	uint32 rid;

	sid_copy(&dom_sid, sid);
	sid_split_rid(&dom_sid, &rid);
	
	return sid_equal(&dom_sid, &global_sid_Builtin);
}


/*****************************************************************
 Calculates size of a sid.
*****************************************************************/  

size_t sid_size(DOM_SID *sid)
{
	if (sid == NULL)
		return 0;

	return sid->num_auths * sizeof(uint32) + 8;
}

/*****************************************************************
 Returns true if SID is internal (and non-mappable).
*****************************************************************/

BOOL non_mappable_sid(DOM_SID *sid)
{
	DOM_SID dom;
	uint32 rid;

	sid_copy(&dom, sid);
	sid_split_rid(&dom, &rid);

	if (sid_equal(&dom, &global_sid_Builtin))
		return True;

	if (sid_equal(&dom, &global_sid_Creator_Owner_Domain))
		return True;
 
	if (sid_equal(&dom, &global_sid_NT_Authority))
		return True;

	return False;
}

/*
  return the binary string representation of a DOM_SID
  caller must free
*/
char *sid_binstring(DOM_SID *sid)
{
	char *buf, *s;
	int len = sid_size(sid);
	buf = malloc(len);
	if (!buf) return NULL;
	sid_linearize(buf, len, sid);
	s = binary_string(buf, len);
	free(buf);
	return s;
}

