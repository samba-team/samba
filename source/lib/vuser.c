/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Password and authentication handling
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

/* this holds info on user ids that are already validated for this VC */
static user_struct *validated_users = NULL;
static int num_validated_users = 0;

/****************************************************************************
check if a uid has been validated, and return an pointer to the user_struct
if it has. NULL if not. vuid is biased by an offset. This allows us to
tell random client vuid's (normally zero) from valid vuids.
****************************************************************************/
user_struct *get_valid_user_struct(uint16 vuid)
{
  if (vuid == UID_FIELD_INVALID)
    return NULL;
  vuid -= VUID_OFFSET;
  if ((vuid >= (uint16)num_validated_users) || 
     (validated_users[vuid].uid == (uid_t)-1) || (validated_users[vuid].gid == (gid_t)-1))
    return NULL;
  return &validated_users[vuid];
}

/****************************************************************************
invalidate a uid
****************************************************************************/
void invalidate_vuid(uint16 vuid)
{
  user_struct *vuser = get_valid_user_struct(vuid);

  if (vuser == NULL) return;

  vuser->uid = (uid_t)-1;
  vuser->gid = (gid_t)-1;

  /* same number of igroups as groups */
  vuser->n_groups = 0;

  if (vuser->groups)
    free((char *)vuser->groups);

  vuser->groups  = NULL;
}


/****************************************************************************
return a validated username
****************************************************************************/
char *validated_username(uint16 vuid)
{
  user_struct *vuser = get_valid_user_struct(vuid);
  if (vuser == NULL)
    return 0;
  return(vuser->name);
}



/****************************************************************************
register a uid/name pair as being valid and that a valid password
has been given. vuid is biased by an offset. This allows us to
tell random client vuid's (normally zero) from valid vuids.
****************************************************************************/
uint16 create_vuid(uid_t uid, gid_t gid, int n_groups, gid_t *groups,
				char *unix_name, char *requested_name,
				char *real_name,
				BOOL guest, uchar user_sess_key[16])
{
  user_struct *vuser;
	uint16 vuid;

  validated_users = (user_struct *)Realloc(validated_users,
			   sizeof(user_struct)*
			   (num_validated_users+1));
  
  if (!validated_users)
    {
      DEBUG(0,("Failed to realloc users struct!\n"));
      num_validated_users = 0;
      return UID_FIELD_INVALID;
    }

  vuser = &validated_users[num_validated_users];
  num_validated_users++;

  vuser->uid = uid;
  vuser->gid = gid;
  vuser->guest = guest;
  fstrcpy(vuser->name,unix_name);
  fstrcpy(vuser->requested_name,requested_name);
  fstrcpy(vuser->real_name,real_name);
  memcpy(vuser->user_sess_key, user_sess_key, sizeof(vuser->user_sess_key));

  vuser->n_groups = n_groups;
	vuser->groups = groups;

  vuid = (uint16)((num_validated_users - 1) + VUID_OFFSET);
  DEBUG(3,("uid %d vuid %d registered to name %s\n",(int)uid, vuid, unix_name));
  dump_data_pw("vuid usr sess key:\n", vuser->user_sess_key,
               sizeof(vuser->user_sess_key));

  return vuid;
}

/****************************************************************************
register a uid/name pair as being valid and that a valid password
has been given. vuid is biased by an offset. This allows us to
tell random client vuid's (normally zero) from valid vuids.
****************************************************************************/
uint16 register_vuid(uid_t uid,gid_t gid, char *unix_name, char *requested_name, BOOL guest, uchar user_sess_key[16])
{
	int n_groups;
	gid_t *groups;
	fstring real_name;
  struct passwd *pwfile; /* for getting real name from passwd file */

  /* Ensure no vuid gets registered in share level security. */
  if(lp_security() == SEC_SHARE)
    return UID_FIELD_INVALID;

#if 0
  /*
   * After observing MS-Exchange services writing to a Samba share
   * I belive this code is incorrect. Each service does its own
   * sessionsetup_and_X for the same user, and as each service shuts
   * down, it does a user_logoff_and_X. As we are consolidating multiple
   * sessionsetup_and_X's onto the same vuid here, when the first service
   * shuts down, it invalidates all the open files for the other services.
   * Hence I am removing this code and forcing each sessionsetup_and_X
   * to get a new vuid.
   * Jeremy Allison. (jallison@whistle.com).
   */

  int i;
  for(i = 0; i < num_validated_users; i++) {
    vuser = &validated_users[i];
    if ( vuser->uid == uid )
      return (uint16)(i + VUID_OFFSET); /* User already validated */
  }
#endif

  validated_users = (user_struct *)Realloc(validated_users,
			   sizeof(user_struct)*
			   (num_validated_users+1));
  
  if (!validated_users)
    {
      DEBUG(0,("Failed to realloc users struct!\n"));
      num_validated_users = 0;
      return UID_FIELD_INVALID;
    }

  /* Find all the groups this uid is in and store them. 
     Used by become_user() */
  get_unixgroups(unix_name,uid,gid,
	       &n_groups,
	       &groups);

  DEBUG(3,("uid %d registered to name %s\n",(int)uid,unix_name));

  DEBUG(3, ("Clearing default real name\n"));
  fstrcpy(real_name, "<Full Name>\0");
  if (lp_unix_realname())
	{
    if ((pwfile=hashed_getpwnam(unix_name))!= NULL)
      {
      DEBUG(3, ("User name: %s\tReal name: %s\n",unix_name,pwfile->pw_gecos));
      fstrcpy(real_name, pwfile->pw_gecos);
      }
  }

  return create_vuid(uid, gid, n_groups, groups,
				unix_name, requested_name,
				real_name,
				guest, user_sess_key);
}

/*******************************************************************
check if a username is OK
********************************************************************/
BOOL check_vuser_ok(struct uid_cache *cache, user_struct *vuser,int snum)
{
  int i;
  for (i=0;i<cache->entries;i++)
    if (cache->list[i] == vuser->uid) return(True);

  if (!user_ok(vuser->name,snum)) return(False);

  i = cache->entries % UID_CACHE_SIZE;
  cache->list[i] = vuser->uid;

  if (cache->entries < UID_CACHE_SIZE)
    cache->entries++;

  return(True);
}

