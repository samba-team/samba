/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Samba utility functions
   Copyright (C) Andrew Tridgell 1992-1998
   
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


extern int DEBUGLEVEL;


/*****************************************************************
 Convert a SID to an ascii string.
*****************************************************************/

char *sid_to_string(pstring sidstr_out, DOM_SID *sid)
{
  char subauth[16];
  int i;
  /* BIG NOTE: this function only does SIDS where the identauth is not >= 2^32 */
  uint32 ia = (sid->id_auth[5]) +
              (sid->id_auth[4] << 8 ) +
              (sid->id_auth[3] << 16) +
              (sid->id_auth[2] << 24);

  slprintf(sidstr_out, sizeof(pstring) - 1, "S-%d-%d", sid->sid_rev_num, ia);

  for (i = 0; i < sid->num_auths; i++)
  {
    slprintf(subauth, sizeof(subauth)-1, "-%u", sid->sub_auths[i]);
    pstrcat(sidstr_out, subauth);
  }

  DEBUG(7,("sid_to_string returning %s\n", sidstr_out));
  return sidstr_out;
}

/*****************************************************************
 Convert a string to a SID. Returns True on success, False on fail.
*****************************************************************/  
   
BOOL string_to_sid(DOM_SID *sidout, char *sidstr)
{
  pstring tok;
  char *p = sidstr;
  /* BIG NOTE: this function only does SIDS where the identauth is not >= 2^32 */
  uint32 ia;

  memset((char *)sidout, '\0', sizeof(DOM_SID));

  if (StrnCaseCmp( sidstr, "S-", 2)) {
    DEBUG(0,("string_to_sid: Sid %s does not start with 'S-'.\n", sidstr));
    return False;
  }

  p += 2;
  if (!next_token(&p, tok, "-", sizeof(tok))) {
    DEBUG(0,("string_to_sid: Sid %s is not in a valid format.\n", sidstr));
    return False;
  }

  /* Get the revision number. */
  sidout->sid_rev_num = atoi(tok);

  if (!next_token(&p, tok, "-", sizeof(tok))) {
    DEBUG(0,("string_to_sid: Sid %s is not in a valid format.\n", sidstr));
    return False;
  }

  /* identauth in decimal should be <  2^32 */
  ia = atoi(tok);

  /* NOTE - the ia value is in big-endian format. */
  sidout->id_auth[0] = 0;
  sidout->id_auth[1] = 0;
  sidout->id_auth[2] = (ia & 0xff000000) >> 24;
  sidout->id_auth[3] = (ia & 0x00ff0000) >> 16;
  sidout->id_auth[4] = (ia & 0x0000ff00) >> 8;
  sidout->id_auth[5] = (ia & 0x000000ff);

  sidout->num_auths = 0;

  while(next_token(&p, tok, "-", sizeof(tok)) && 
	sidout->num_auths < MAXSUBAUTHS)
  {
    /* 
     * NOTE - the subauths are in native machine-endian format. They
     * are converted to little-endian when linearized onto the wire.
     */
	uint32 rid = (uint32)strtoul(tok, NULL, 10);
	DEBUG(50,("string_to_sid: tok: %s rid 0x%x\n", tok, rid));
	sid_append_rid(sidout, rid);
  }

  DEBUG(7,("string_to_sid: converted SID %s ok\n", sidstr));

  return True;
}

/*****************************************************************
 add a rid to the end of a sid
*****************************************************************/  
BOOL sid_append_rid(DOM_SID *sid, uint32 rid)
{
	if (sid->num_auths < MAXSUBAUTHS)
	{
		sid->sub_auths[sid->num_auths++] = rid;
		return True;
	}
	return False;
}

/*****************************************************************
 removes the last rid from the end of a sid
*****************************************************************/  
BOOL sid_split_rid(DOM_SID *sid, uint32 *rid)
{
	if (sid->num_auths > 0)
	{
		sid->num_auths--;
		if (rid != NULL)
		{
			(*rid) = sid->sub_auths[sid->num_auths];
		}
		return True;
	}
	return False;
}

/*****************************************************************
 copies a sid
*****************************************************************/  
void sid_copy(DOM_SID *sid1, DOM_SID *sid2)
{
	int i;

	for (i = 0; i < 6; i++)
	{
		sid1->id_auth[i] = sid2->id_auth[i];
	}

	for (i = 0; i < sid2->num_auths; i++)
	{
		sid1->sub_auths[i] = sid2->sub_auths[i];
	}

	sid1->num_auths   = sid2->num_auths;
	sid1->sid_rev_num = sid2->sid_rev_num;
}
/*****************************************************************
 compare two sids
*****************************************************************/  
BOOL sid_equal(DOM_SID *sid1, DOM_SID *sid2)
{
	int i;

	/* compare most likely different rids, first: i.e start at end */
	for (i = sid1->num_auths-1; i >= 0; --i)
	{
		if (sid1->sub_auths[i] != sid2->sub_auths[i]) return False;
	}

	if (sid1->num_auths   != sid2->num_auths  ) return False;
	if (sid1->sid_rev_num != sid2->sid_rev_num) return False;

	for (i = 0; i < 6; i++)
	{
		if (sid1->id_auth[i] != sid2->id_auth[i]) return False;
	}

	return True;
}


/*****************************************************************
 calculates size of a sid
*****************************************************************/  
int sid_size(DOM_SID *sid)
{
	if (sid == NULL)
	{
		return 0;
	}
	return sid->num_auths * sizeof(uint32) + 8;
}
