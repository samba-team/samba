/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Username handling
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

/* internal functions */
static struct passwd *uname_string_combinations(char *s, struct passwd * (*fn) (char *), int N);
static struct passwd *uname_string_combinations2(char *s, int offset, struct passwd * (*fn) (char *), int N);

/****************************************************************************
  Since getpwnam() makes samba really slow with the NT-domain code
  (reading /etc/passwd again and again and again), here is an implementation
  of very simple passwd cache
****************************************************************************/
#define PASSWD_HASH_SIZE 1009
/* The hashtable is rebuild every 15 seconds */
#define PASSWD_HASH_AGE 15
struct passwd_hash_entry {
  int entry;
  int next;
};

struct passwd_hash_table_s {
  struct passwd *passwds;
  int passwds_size;  
  int *names;
  int *uids;
  struct passwd_hash_entry *entries;
  int entries_size;
  struct timeval build_time;
} passwd_hash_table = {
  NULL,0,NULL,NULL,NULL,0,{0,0}
};

static int name_hash_function(const char *name) 
{
  /* I guess that there must be better hash functions. This one was the
   * first to come into mind :) */
  unsigned int value=0;
  while (*name) {
    value=(value<<8)|(unsigned char)(*name);
    if (value>1048576) value=value%PASSWD_HASH_SIZE;
    name++;
  }
  value=value%PASSWD_HASH_SIZE;
  return value;
}
    
static int uid_hash_function(uid_t uid) 
{
  return uid%PASSWD_HASH_SIZE;
}


static BOOL build_passwd_hash_table(void) 
{
  struct passwd_hash_table_s *pht=&passwd_hash_table; /* Convenience */
  int num_passwds=0;
  int num_entries=0;
  struct passwd *pass;
  int i;
  int name_i,uid_i;

  DEBUG(3,("Building passwd hash table\n"));
  /* Free the allocated strings in old hash table */
  for (i=0;i<pht->passwds_size;i++) {
    free(pht->passwds[i].pw_name); 
    free(pht->passwds[i].pw_passwd);
    free(pht->passwds[i].pw_gecos);
    free(pht->passwds[i].pw_dir);
    free(pht->passwds[i].pw_shell);    
  }

  /* Initialize hash table if first table build */
  if (pht->passwds_size==0) {
    DEBUG(3,("Building passwd hash table for the first time\n"));
    pht->passwds=malloc(sizeof(struct passwd)*64); /* A reasonable default */
    pht->passwds_size=64;
  }
  if (pht->names==NULL) {
    pht->names=malloc(sizeof(struct passwd_hash_entry *)*PASSWD_HASH_SIZE);
  }
  if (pht->uids==NULL) {
    pht->uids=malloc(sizeof(struct passwd_hash_entry *)*PASSWD_HASH_SIZE);
  }
  if (pht->entries==NULL) {
    pht->entries=malloc(sizeof(struct passwd_hash_entry)*128);
    pht->entries_size=128;
  }
  if (pht->passwds==NULL || pht->names==NULL || 
      pht->uids==NULL || pht->entries==NULL) {
    goto fail;
  }
  
  /* Clear out the hash table */
  for(i=0;i<PASSWD_HASH_SIZE;i++) pht->uids[i]=-1;
  for(i=0;i<PASSWD_HASH_SIZE;i++) pht->names[i]=-1;

  /* Now do the build */
  setpwent();

  while((pass=getpwent())) {

    /* Check that we have enough space */
    if (num_passwds==pht->passwds_size) {
      struct passwd *new_passwds=NULL;
      pht->passwds_size+=pht->passwds_size/2;
      new_passwds=realloc(pht->passwds,
			   sizeof(struct passwd)*pht->passwds_size);
      if (new_passwds==NULL) goto fail;
      pht->passwds=new_passwds;
    }
    if (num_entries+1>=pht->entries_size) {
      pht->entries_size+=pht->entries_size/2;
      pht->entries=realloc(pht->entries,
			   sizeof(struct passwd_hash_entry)*pht->entries_size);
      if (pht->entries==NULL) goto fail;
    }

    /* Copy the passwd struct */
    memset(&pht->passwds[num_passwds],0,sizeof(struct passwd));
    pht->passwds[num_passwds].pw_uid=pass->pw_uid;
    pht->passwds[num_passwds].pw_gid=pass->pw_gid;  
    if (
	(pht->passwds[num_passwds].pw_name=strdup(pass->pw_name))==NULL ||
	(pht->passwds[num_passwds].pw_passwd=strdup(pass->pw_passwd))==NULL ||
	(pht->passwds[num_passwds].pw_gecos=strdup(pass->pw_gecos))==NULL ||
	(pht->passwds[num_passwds].pw_dir=strdup(pass->pw_dir))==NULL ||
	(pht->passwds[num_passwds].pw_shell=strdup(pass->pw_shell))==NULL ) {
      num_passwds++;
      goto fail;
    }
    
    /* Add to the hash table */
    /* Add the name */
    pht->entries[num_entries].entry=num_passwds;
    name_i=name_hash_function(pass->pw_name);
    pht->entries[num_entries].next=pht->names[name_i];
    pht->names[name_i]=num_entries;
    num_entries++;
    /* Add the uid */
    pht->entries[num_entries].entry=num_passwds;
    uid_i=uid_hash_function(pass->pw_uid);
    pht->entries[num_entries].next=pht->uids[uid_i];
    pht->uids[uid_i]=num_entries;
    num_entries++;

    /* This entry has been done */
    num_passwds++;
  }    
  endpwent();
  
  if (pht->passwds_size>num_passwds) {
    struct passwd *passwds;
    passwds=realloc(pht->passwds,sizeof(pht->passwds[0])*num_passwds);
    if (passwds==NULL) goto fail;
    pht->passwds=passwds;
    pht->passwds_size=num_passwds;
  }
  if (pht->entries_size>num_entries) {
    struct passwd_hash_entry *entries;
    entries=realloc(pht->entries,sizeof(pht->entries[0])*num_entries);
    if (entries==NULL) goto fail;
    pht->entries=entries;
    pht->entries_size=num_entries;
  }

  /* Mark the creation time */
  GetTimeOfDay(&pht->build_time);
  /* Everything went smoothly. */
  return True;

 fail:
  DEBUG(0,("Failed to create passwd hash table: %s",strerror(errno)));
  /* OK: now the untested part. Normally this should never happen:
   * Only running out of memory could cause this and even then
   * we have enough trouble already. */
  while (num_passwds>0) {
    num_passwds--;
    free(pht->passwds[num_passwds].pw_name);
    free(pht->passwds[num_passwds].pw_passwd);
    free(pht->passwds[num_passwds].pw_gecos);
    free(pht->passwds[num_passwds].pw_dir);
    free(pht->passwds[num_passwds].pw_shell);    
  }
  free(pht->entries);
  free(pht->uids);
  free(pht->names);
  free(pht->passwds);
  pht->passwds_size=0;
  pht->entries_size=0;    
  /* Also mark fail time, so that retry will happen after PASSWD_HASH_AGE */
  GetTimeOfDay(&pht->build_time);
  return False;
}

static BOOL have_passwd_hash(void)
{
  struct passwd_hash_table_s *pht=&passwd_hash_table;
  struct timeval tv;
  GetTimeOfDay(&tv);
  /* I'm ignoring microseconds. If you think they matter, go ahead
   * and implement them */
  if (tv.tv_sec - pht->build_time.tv_sec > PASSWD_HASH_AGE) {
    return build_passwd_hash_table();
  }
  return pht->passwds_size>0;
}

struct passwd *hashed_getpwnam(const char *name)
{
  struct passwd_hash_table_s *pht=&passwd_hash_table;

  DEBUG(5,("getpwnam(%s)\n", name));

  if (have_passwd_hash())
  {
    int name_i=name_hash_function(name);
    int hash_index=pht->names[name_i];
    while(hash_index!=-1) {
      struct passwd *pass=&pht->passwds[pht->entries[hash_index].entry];
      if (strcmp(name,pass->pw_name)==0) {
	DEBUG(5,("Found: %s:%s:%d:%d:%s:%s:%s\n",
		 pass->pw_name,
		 pass->pw_passwd,
		 pass->pw_uid,
		 pass->pw_gid,
		 pass->pw_gecos,
		 pass->pw_dir,
		 pass->pw_shell));
	return copy_passwd_struct(pass);      
      }
      hash_index=pht->entries[hash_index].next;
    }

    /* Not found */
    DEBUG(5,("%s not found\n",name));
    return NULL;
  } 

  /* Fall back to real getpwnam() */
  return sys_getpwnam(name);
}

/*******************************************************************
turn a uid into a user name
********************************************************************/
char *uidtoname(uid_t uid)
{
  static char name[40];
  struct passwd_hash_table_s *pht=&passwd_hash_table;
  struct passwd *pass=NULL;

  DEBUG(5,("uidtoname(%d)\n",uid));
  if (have_passwd_hash()) {
    int hash_index=pht->uids[uid_hash_function(uid)];
    while(hash_index!=-1) {
      pass=&pht->passwds[pht->entries[hash_index].entry];
      if (pass->pw_uid==uid) {
	DEBUG(5,("Found: %s:%s:%d:%d:%s:%s:%s\n",
		 pass->pw_name,
		 pass->pw_passwd,
		 pass->pw_uid,
		 pass->pw_gid,
		 pass->pw_gecos,
		 pass->pw_dir,
		 pass->pw_shell));
	return pass->pw_name;      
      }
      hash_index=pht->entries[hash_index].next;
    }
    DEBUG(5,("Hash miss"));
    pass=NULL;
  } else {
    /* No hash table, fall back to getpwuid */
    pass = getpwuid(uid);
  }
  if (pass) return(pass->pw_name);
  slprintf(name, sizeof(name) - 1, "%d",(int)uid);
  return(name);
}

/****************************************************************************
get a users home directory.
****************************************************************************/
char *get_unixhome_dir(char *user)
{
	const struct passwd *pass;
	static pstring home_dir;

	pass = Get_Pwnam(user, False);

	if (pass == NULL || pass->pw_dir == NULL) return(NULL);

	pstrcpy(home_dir, pass->pw_dir);
	DEBUG(10,("get_smbhome_dir: returning %s for user %s\n", home_dir, user));
	return home_dir;
}


/*******************************************************************
map a username from a dos name to a unix name by looking in the username
map. Note that this modifies the name in place.
This is the main function that should be called *once* on
any incoming or new username - in order to canonicalize the name.
This is being done to de-couple the case conversions from the user mapping
function. Previously, the map_username was being called
every time Get_Pwnam was called.
Returns True if username was changed, false otherwise.
********************************************************************/
BOOL map_username(char *user)
{
  static BOOL initialised=False;
  static fstring last_from,last_to;
  FILE *f;
  char *mapfile = lp_username_map();
  char *s;
  pstring buf;
  BOOL mapped_user = False;

  if (!*user)
    return False;

  if (!*mapfile)
    return False;

  if (!initialised) {
    *last_from = *last_to = 0;
    initialised = True;
  }

  if (strequal(user,last_to))
    return False;

  if (strequal(user,last_from)) {
    DEBUG(3,("Mapped user %s to %s\n",user,last_to));
    fstrcpy(user,last_to);
    return True;
  }
  
  f = sys_fopen(mapfile,"r");
  if (!f) {
    DEBUG(0,("can't open username map %s\n",mapfile));
    return False;
  }

  DEBUG(4,("Scanning username map %s\n",mapfile));

  while((s=fgets_slash(buf,sizeof(buf),f))!=NULL) {
    char *unixname = s;
    char *dosname = strchr(unixname,'=');
    BOOL return_if_mapped = False;

    if (!dosname)
      continue;

    *dosname++ = 0;

    while (isspace(*unixname))
      unixname++;
    if ('!' == *unixname) {
      return_if_mapped = True;
      unixname++;
      while (*unixname && isspace(*unixname))
        unixname++;
    }
    
    if (!*unixname || strchr("#;",*unixname))
      continue;

    {
      int l = strlen(unixname);
      while (l && isspace(unixname[l-1])) {
        unixname[l-1] = 0;
        l--;
      }
    }

    if (strchr(dosname,'*') || user_in_list(user,dosname)) {
      DEBUG(3,("Mapped user %s to %s\n",user,unixname));
      mapped_user = True;
      fstrcpy(last_from,user);
      sscanf(unixname,"%s",user);
      fstrcpy(last_to,user);
      if(return_if_mapped) { 
        fclose(f);
        return True;
      }
    }
  }

  fclose(f);

  /*
   * Setup the last_from and last_to as an optimization so 
   * that we don't scan the file again for the same user.
   */
  fstrcpy(last_from,user);
  fstrcpy(last_to,user);

  return mapped_user;
}


/****************************************************************************
 Get_Pwnam wrapper
****************************************************************************/
static struct passwd *_Get_Pwnam(char *s)
{
	struct passwd *ret;

	ret = hashed_getpwnam(s);
#ifdef HAVE_GETPWANAM
	if (ret)
	{
		struct passwd_adjunct *pwret;
		pwret = getpwanam(s);
		if (pwret != NULL && pwret->pwa_passwd != NULL)
		{
			pstrcpy(ret->pw_passwd, pwret->pwa_passwd);
		}
	}
#endif

	return ret;
}

/****************************************************************************
a wrapper for getpwnam() that tries with all lower and all upper case 
if the initial name fails. Also tried with first letter capitalised
Note that this can change user!  Function returns const to emphasise
the fact that most of the members of the struct passwd * returned are
dynamically allocated.
****************************************************************************/
const struct passwd *Get_Pwnam(char *user,BOOL allow_change)
{
  fstring user2;
  int last_char;
  int usernamelevel = lp_usernamelevel();

  struct passwd *ret;  

  if (!user || !(*user))
    return(NULL);

  StrnCpy(user2,user,sizeof(user2)-1);

  if (!allow_change) {
    user = &user2[0];
  }

  ret = _Get_Pwnam(user);
  if (ret) return(ret);

  strlower(user);
  ret = _Get_Pwnam(user);
  if (ret)  return(ret);

  strupper(user);
  ret = _Get_Pwnam(user);
  if (ret) return(ret);

  /* try with first letter capitalised */
  if (strlen(user) > 1)
    strlower(user+1);  
  ret = _Get_Pwnam(user);
  if (ret) return(ret);

  /* try with last letter capitalised */
  strlower(user);
  last_char = strlen(user)-1;
  user[last_char] = toupper(user[last_char]);
  ret = _Get_Pwnam(user);
  if (ret) return(ret);

  /* try all combinations up to usernamelevel */
  strlower(user);
  ret = uname_string_combinations(user, _Get_Pwnam, usernamelevel);
  if (ret) return(ret);

  if (allow_change)
    fstrcpy(user,user2);

  return(NULL);
}

/****************************************************************************
check if a user is in a netgroup user list
****************************************************************************/
static BOOL user_in_netgroup_list(char *user,char *ngname)
{
#ifdef HAVE_NETGROUP
  static char *mydomain = NULL;
  if (mydomain == NULL)
    yp_get_default_domain(&mydomain);

  if(mydomain == NULL)
  {
    DEBUG(5,("Unable to get default yp domain\n"));
  }
  else
  {
    DEBUG(5,("looking for user %s of domain %s in netgroup %s\n",
          user, mydomain, ngname));
    DEBUG(5,("innetgr is %s\n",
          innetgr(ngname, NULL, user, mydomain)
          ? "TRUE" : "FALSE"));

    if (innetgr(ngname, NULL, user, mydomain))
      return (True);
  }
#endif /* HAVE_NETGROUP */
  return False;
}

/****************************************************************************
check if a user is in a UNIX user list
****************************************************************************/
static BOOL user_in_group_list(char *user,char *gname)
{
#ifdef HAVE_GETGRNAM 
  struct group *gptr;
  char **member;  
  const struct passwd *pass = Get_Pwnam(user,False);

  if (pass)
  { 
    gptr = getgrgid(pass->pw_gid);
    if (gptr && strequal(gptr->gr_name,gname))
      return(True); 
  } 

  gptr = (struct group *)getgrnam(gname);

  if (gptr)
  {
    member = gptr->gr_mem;
    while (member && *member)
    {
      if (strequal(*member,user))
        return(True);
      member++;
    }
  }
#endif /* HAVE_GETGRNAM */
  return False;
}	      

/****************************************************************************
check if a username is valid
****************************************************************************/
BOOL user_ok(char *user,int snum)
{
	pstring valid, invalid;
	BOOL ret;

	StrnCpy(valid, lp_valid_users(snum), sizeof(pstring));
	StrnCpy(invalid, lp_invalid_users(snum), sizeof(pstring));

	string_sub(valid,"%S",lp_servicename(snum));
	string_sub(invalid,"%S",lp_servicename(snum));
	
	ret = !user_in_list(user,invalid);
	
	if (ret && valid && *valid) {
		ret = user_in_list(user,valid);
	}

	if (ret && lp_onlyuser(snum)) {
		char *user_list = lp_username(snum);
		string_sub(user_list,"%S",lp_servicename(snum));
		ret = user_in_list(user,user_list);
	}

	return(ret);
}

/****************************************************************************
check if a user is in a user list - can check combinations of UNIX
and netgroup lists.
****************************************************************************/
BOOL user_in_list(char *user,char *list)
{
  pstring tok;
  char *p=list;

  while (next_token(&p,tok,LIST_SEP, sizeof(tok)))
  {
    /*
     * Check raw username.
     */
    if (strequal(user,tok))
      return(True);

    /*
     * Now check to see if any combination
     * of UNIX and netgroups has been specified.
     */

    if(*tok == '@')
    {
      /*
       * Old behaviour. Check netgroup list
       * followed by UNIX list.
       */
      if(user_in_netgroup_list(user,&tok[1]))
        return True;
      if(user_in_group_list(user,&tok[1]))
        return True;
    }
    else if (*tok == '+')
    {
      if(tok[1] == '&')
      {
        /*
         * Search UNIX list followed by netgroup.
         */
        if(user_in_group_list(user,&tok[2]))
          return True;
        if(user_in_netgroup_list(user,&tok[2]))
          return True;
      }
      else
      {
        /*
         * Just search UNIX list.
         */
        if(user_in_group_list(user,&tok[1]))
          return True;
      }
    }
    else if (*tok == '&')
    {
      if(tok[1] == '&')
      {
        /*
         * Search netgroup list followed by UNIX list.
         */
        if(user_in_netgroup_list(user,&tok[2]))
          return True;
        if(user_in_group_list(user,&tok[2]))
          return True;
      }
      else
      {
        /*
         * Just search netgroup list.
         */
        if(user_in_netgroup_list(user,&tok[1]))
          return True;
      }
    }
  }
  return(False);
}

/* The functions below have been taken from password.c and slightly modified */
/****************************************************************************
apply a function to upper/lower case combinations
of a string and return true if one of them returns true.
try all combinations with N uppercase letters.
offset is the first char to try and change (start with 0)
it assumes the string starts lowercased
****************************************************************************/
static struct passwd *uname_string_combinations2(char *s,int offset,struct passwd *(*fn)(char *),int N)
{
  int len = strlen(s);
  int i;
  struct passwd *ret;

#ifdef PASSWORD_LENGTH
  len = MIN(len,PASSWORD_LENGTH);
#endif

  if (N <= 0 || offset >= len)
    return(fn(s));


  for (i=offset;i<(len-(N-1));i++)

    {
      char c = s[i];
      if (!islower(c)) continue;
      s[i] = toupper(c);
      ret = uname_string_combinations2(s,i+1,fn,N-1);
      if(ret) return(ret);
      s[i] = c;
    }
  return(NULL);
}

/****************************************************************************
apply a function to upper/lower case combinations
of a string and return true if one of them returns true.
try all combinations with up to N uppercase letters.
offset is the first char to try and change (start with 0)
it assumes the string starts lowercased
****************************************************************************/
static struct passwd * uname_string_combinations(char *s,struct passwd * (*fn)(char *),int N)
{
  int n;
  struct passwd *ret;

  for (n=1;n<=N;n++)
  {
    ret = uname_string_combinations2(s,0,fn,n);
    if(ret) return(ret);
  }
  return(NULL);
}
