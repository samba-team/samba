/* 
   Unix SMB/Netbios implementation.
   Version 3.0
   MSDfs services for Samba
   Copyright (C) Shirish Kalele 2000
   Copyright (C) Samba Team 2000

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

#ifdef MS_DFS

#define MSDFS_TDB "msdfs.tdb"

/* structures for msdfs.tdb */
struct tdb_junction_key
{
  pstring service_name;
  pstring volume_name;
};

struct tdb_junction_data
{
  int referral_count;
  struct referral first_referral;
};

static TDB_CONTEXT* msdfs_map = NULL;

/*
 * Open the msdfs tdb map. Called once for update when parsing the dfsmap file 
 * and then subsequently at tconX for reading 
 */
BOOL msdfs_open(BOOL update)
{
  pstring fname;
  int oflags = (update)?O_RDWR|O_CREAT:O_RDONLY;
  
  /* close any open TDB contexts before opening */
  if(msdfs_map != NULL)
    {
      DEBUG(10,("msdfs_open: Closing existing TDB_CONTEXT msdfs_map: name: %s, fd: %d\n",
		msdfs_map->name,msdfs_map->fd));
      tdb_close(msdfs_map);
    }

  pstrcpy(fname,lock_path(MSDFS_TDB));
  DEBUG(10,("opening msdfs tdb : .%s.\n",fname));
  if((msdfs_map = tdb_open(fname,0,0,oflags,0644)) == NULL)
    {
      DEBUG(1,("Couldn't open Dfs tdb map %s %s.\nError was %s\n",fname,
	       (update?"for update":"for reading"),strerror(errno) ));
      return False;
    }
    DEBUG(10,("TDB_CONTEXT msdfs_map opened: name: %s, fd: %d\n",msdfs_map->name,msdfs_map->fd));

  return True;
}

BOOL add_junction_entry(struct junction_map* junction)
{
  struct tdb_junction_key* tlk;
  struct tdb_junction_data* tld;

  TDB_DATA key,data;
  uint16 data_size;
  
  int i=0;

  if(msdfs_map == NULL)
    {
      DEBUG(4,("Attempt to add junction entry to unopened %s\n",MSDFS_TDB));
      return False;
    }

  /* create the key */
  if((tlk = (struct tdb_junction_key*) malloc(sizeof(struct tdb_junction_key))) == NULL)
    {
      DEBUG(0,("malloc failed for tdb junction key\n"));
      return False;
    }
  
  ZERO_STRUCTP(tlk);

  pstrcpy(tlk->service_name,junction->service_name);
  pstrcpy(tlk->volume_name,junction->volume_name);
  strupper(tlk->service_name);
  strupper(tlk->volume_name);

  key.dptr = (char*) tlk;
  key.dsize = sizeof(struct tdb_junction_key);

  
  /* create the data */
  data_size = sizeof(struct tdb_junction_data) +
	((junction->referral_count-1)*sizeof(struct referral));

  if( (tld = (struct tdb_junction_data*) malloc(data_size)) == NULL)
    {
      DEBUG(0,("malloc failed for tdb junction data\n"));
      return False;
    }

  tld->referral_count = junction->referral_count;
  memcpy(&tld->first_referral,junction->referral_list,junction->referral_count * sizeof(struct referral));
  
  data.dptr = (char*) tld;
  data.dsize = data_size;

  DEBUG(10,("Storing key: .%s:%s.\n",tlk->service_name,tlk->volume_name));
  DEBUG(10,("Data: referral_count : %u\n",tld->referral_count));
  for(i=0;i<tld->referral_count;i++)
    DEBUG(10,("Path %d: %s, proximity: %u, ttl: %u\n",junction->referral_list[i].alternate_path));

  if( tdb_store(msdfs_map,key,data,TDB_REPLACE) != 0)
    {
      DEBUG(10,("Could not store referral for %s:%s \n",
		junction->service_name, junction->volume_name));
      free(key.dptr);
      free(data.dptr);
      return False;
    }
  
  free(key.dptr);
  free(data.dptr);
  return True;
}

BOOL get_junction_entry(struct junction_map* junction)
{
  struct tdb_junction_key* tlk;
  struct tdb_junction_data* tld;

  uint16 reflistsize=0;

  TDB_DATA key,data;
  
  if(msdfs_map == NULL)
    {
      DEBUG(4,("Attempt to get junction entry from unopened %s\n",MSDFS_TDB));
      return False;
    }

  if( (tlk=(struct tdb_junction_key*) malloc(sizeof(struct tdb_junction_key))) == NULL)
    {
      DEBUG(0,("couldn't malloc for tdb junction key\n"));
      return False;
    }
  
  ZERO_STRUCTP(tlk);

  pstrcpy(tlk->service_name,junction->service_name);
  pstrcpy(tlk->volume_name,junction->volume_name);
  strupper(tlk->service_name);
  strupper(tlk->volume_name);

  key.dptr = (char*) tlk;
  key.dsize = sizeof(struct tdb_junction_key);

  data = tdb_fetch(msdfs_map,key);
  
  if(data.dptr == NULL)
    {
      DEBUG(8,("No data found for key %s:%s\n",junction->service_name,junction->volume_name));
      DEBUG(8,("Error was %s\n",strerror(errno)));
      free(key.dptr);
      return False;
    }

  tld = (struct tdb_junction_data*) data.dptr;

  junction->referral_count = tld->referral_count;
  reflistsize = junction->referral_count * sizeof(struct referral);

  if((junction->referral_list = (struct referral*) malloc(reflistsize) ) == NULL)
    {
      DEBUG(0,("malloc failed for referral list\n"));
      free(key.dptr);
      free(data.dptr);
      return False;
    }
  
  memcpy(junction->referral_list,&(tld->first_referral),reflistsize);
  free(key.dptr);
  free(data.dptr);

  return True;
}

BOOL isDfsShare(char* svc,char* vol)
{
  TDB_DATA key;
  struct tdb_junction_key tlk;
  
  ZERO_STRUCT(tlk);

  if(msdfs_map == NULL)
    {
      DEBUG(4,("Attempt to check junction existence in unopened %s\n",MSDFS_TDB));
      return False;
    }

  pstrcpy(tlk.service_name,svc);
  pstrcpy(tlk.volume_name,vol);

  strupper(tlk.service_name);
  strupper(tlk.volume_name);

  key.dptr = (char*) &tlk;
  key.dsize = sizeof(struct tdb_junction_key);

  DEBUG(10,("tdb_exists for key %s:%s returns %d\n",tlk.service_name,tlk.volume_name,
	    tdb_exists(msdfs_map,key)));

  if(tdb_exists(msdfs_map,key))
    return True;
  else
    {
      DEBUG(10,("error was %s\n",strerror(errno)));
      return False;
    }

}

void msdfs_close()
{
  if(msdfs_map != NULL)
      tdb_close(msdfs_map);

  msdfs_map = NULL;
}

void msdfs_end()
{
  pstring fname;
  msdfs_close();
  
  /*  pstrcpy(fname,lock_path(MSDFS_TDB));
  unlink(fname); */
}
#endif    
  
    
      
      
  
  
      
