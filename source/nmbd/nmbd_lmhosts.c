/*
   Unix SMB/Netbios implementation.
   Version 1.9.
   NBT netbios routines and daemon - version 2
   Copyright (C) Jeremy Allison 1994-1998

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

   Revision History:

   Handle lmhosts file reading.

*/

#include "includes.h"

extern int DEBUGLEVEL;

/****************************************************************************
Load a lmhosts file.
****************************************************************************/
void load_lmhosts_file(char *fname)
{  
  FILE *fp = fopen(fname,"r");
  pstring line;
  if (!fp) {
    DEBUG(2,("load_lmhosts_file: Can't open lmhosts file %s. Error was %s\n",
             fname, strerror(errno)));
    return;
  }
   
  while (!feof(fp))
  {
    pstring ip,name,flags,extra;
    struct subnet_record *subrec = NULL;
    char *ptr;
    int count = 0;  
    struct in_addr ipaddr;
    enum name_source source = LMHOSTS_NAME;
    int name_type = -1;

    if (!fgets_slash(line,sizeof(pstring),fp))
      continue;

    if (*line == '#')
      continue;

    strcpy(ip,"");     
    strcpy(name,"");
    strcpy(flags,"");
     
    ptr = line;
     
    if (next_token(&ptr,ip   ,NULL))
      ++count;
    if (next_token(&ptr,name ,NULL))
      ++count;
    if (next_token(&ptr,flags,NULL))
      ++count;
    if (next_token(&ptr,extra,NULL))
      ++count;
   
    if (count <= 0)
      continue;
     
    if (count > 0 && count < 2)
    {
      DEBUG(0,("load_lmhosts_file: Ill formed hosts line [%s]\n",line));
      continue;
    }
      
    if (count >= 4)
    {
      DEBUG(0,("load_lmhosts_file: too many columns in lmhosts file %s (obsolete syntax)\n",
             fname));
      continue;
    }
      
    DEBUG(4, ("load_lmhosts_file: lmhost entry: %s %s %s\n", ip, name, flags));
    
    if (strchr(flags,'G') || strchr(flags,'S'))
    {
      DEBUG(0,("load_lmhosts_file: group flag in %s ignored (obsolete)\n",fname));
      continue;
    }

    ipaddr = *interpret_addr2(ip);

    /* Extra feature. If the name ends in '#XX', where XX is a hex number,
       then only add that name type. */
    if((ptr = strchr(name, '#')) != NULL)
    {
      char *endptr;

      ptr++;
      name_type = (int)strtol(ptr, &endptr,0);

      if(!*ptr || (endptr == ptr))
      {
        DEBUG(0,("load_lmhosts_file: invalid name %s containing '#'.\n", name));
        continue;
      }

      *(--ptr) = '\0'; /* Truncate at the '#' */
    }

    /* We find a relevent subnet to put this entry on, then add it. */
    /* Go through all the broadcast subnets and see if the mask matches. */
    for (subrec = FIRST_SUBNET; subrec ; subrec = NEXT_SUBNET_EXCLUDING_UNICAST(subrec))
    {
      if(same_net(ipaddr, subrec->bcast_ip, subrec->mask_ip))
        break;
    }
  
    /* If none match add the name to the remote_broadcast_subnet. */
    if(subrec == NULL)
      subrec = remote_broadcast_subnet;

    if(name_type == -1)
    {
      /* Add the (0) and (0x20) names directly into the namelist for this subnet. */
      add_name_to_subnet(subrec,name,0x00,(uint16)NB_ACTIVE,PERMANENT_TTL,source,1,&ipaddr);
      add_name_to_subnet(subrec,name,0x20,(uint16)NB_ACTIVE,PERMANENT_TTL,source,1,&ipaddr);
    }
    else
    {
      /* Add the given name type to the subnet namelist. */
      add_name_to_subnet(subrec,name,name_type,(uint16)NB_ACTIVE,PERMANENT_TTL,source,1,&ipaddr);
    }
  }
   
  fclose(fp);
}

/****************************************************************************
  Find a name read from the lmhosts file. We secretly check the names on
  the remote_broadcast_subnet as if the name was added to a regular broadcast
  subnet it will be found by normal name query processing.
****************************************************************************/

BOOL find_name_in_lmhosts(struct nmb_name *nmbname, struct name_record **namerecp)
{
  struct name_record *namerec;

  *namerecp = NULL;

  if((namerec = find_name_on_subnet(remote_broadcast_subnet, nmbname, 
                                 FIND_ANY_NAME))==NULL)
    return False;

  if(!NAME_IS_ACTIVE(namerec) || (namerec->source != LMHOSTS_NAME))
    return False;

  *namerecp = namerec;
  return True;
}
