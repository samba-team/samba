/* 
   Unix SMB/Netbios implementation.
   Version 3.0
   MSDfs services for Samba
   Copyright (C) Shirish Kalele 2000

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

/*********************************************************************** 
 * Parses the per-service Dfs map file which is of the form:
 * junction_point1
 *     alternate_path1:proximity:ttl
 *     alternate_path2:proximity:ttl
 * junction_point2
 * ...
 *
 * Junction points are directories in the service (upon encountering which
 * Samba redirects the client to the servers hosting the underlying share)
 *
 * Alternate paths are of the form: \\smbserver\share
 * Currently, the parser detects alternate paths by the leading \'s
 *
 ***********************************************************************/

#include "includes.h"

#ifdef MS_DFS

#define MAX_ALTERNATE_PATHS 256

extern int DEBUGLEVEL;

static char* Dfs_Crop_Whitespace(char* line)
{
  int i=0;
  int len = strlen(line);

  if(line[0]=='#' || line[0]==';') return NULL;
  
  for(i=0;i<len && line[i]==' ';i++);

  if(i>=len) return NULL;
  
  line = &line[i];

  /* crop off the newline at the end, if present */
  /* if(line[len-1]=='\n') line[len-1]='\0'; */

  /* remove white sace from the end */
  for(i=strlen(line)-1;i>=0 && isspace(line[i]);i--);
  
  if(i<0) return NULL;

  line[i]='\0';

  if(line[0] == '\0') return NULL;

  return line;
}

static BOOL parse_referral(char* s, struct referral* ref)
{
#define MAXTOK_IN_REFERRAL 3
  char *tok[MAXTOK_IN_REFERRAL+1];
  int count=0;
  int i=0;

  if(s[1]=='\\') s = &s[1]; /* skip one backslash
			       if there are two */

  tok[count++] = strtok(s,":");
  
  while( ((tok[count]=strtok(NULL,":")) != NULL) && count<MAXTOK_IN_REFERRAL)
    count++;

  DEBUG(10,("parse_referral: Tokens"));
  for(i=0;i<count;i++)
    DEBUG(10,(" %s",tok[i]));
  DEBUG(10,(".\n"));
  if(count > 0)
    pstrcpy(ref->alternate_path,tok[0]);
  else
    {
      DEBUG(6,("Invalid referral line: %s\n",s));
      return False;
    }

  if(count > 1)
    ref->proximity = atoi(tok[1]);
  else
    ref->proximity = 0;

  if(count > 2)
    ref->ttl = atoi(tok[2]);
  else
    ref->ttl = REFERRAL_TTL; 

  return True;
}

static BOOL load_dfsmap(char* fname, int snum)
{
  struct junction_map* junction = NULL;
  struct referral tmp_ref_array[MAX_ALTERNATE_PATHS];
  int ref_count = 0;
  FILE* fp;

  if(lp_dfsmap_loaded(snum))
    return True;
  
  if((fp = sys_fopen(fname,"r")) == NULL)
    {
      DEBUG(1,("can't open dfs map file %s for service [%s]\nError was %s",fname,
	       lp_servicename(snum), strerror(errno)));
      return False;
    }

  if(!msdfs_open(True))
    return False;

  while(!feof(fp))
    {
      pstring rawline;
      char* line;

      if(!fgets(rawline,PSTRING_LEN,fp))
	continue;

      if((line = Dfs_Crop_Whitespace(rawline)) == NULL)
	continue;

      DEBUG(6,("load_dfsmap: Cropped line: %s\n",line));

      /* the line contains a new junction or 
	 an alternate path to current junction */

      if(line[0]!='\\')
	{
	  /* a junction encountered. add the current junction first */
	  if(junction)
	    {
	      junction->referral_count = ref_count;
	      junction->referral_list = tmp_ref_array;
	      DEBUG(4,("Adding Dfs junction: %s\\%s  Referrals: %u First referral path: %s\n",
		       junction->service_name,junction->volume_name,
		       junction->referral_count, junction->referral_list[0].alternate_path));

	      if(!add_junction_entry(junction))
		{
		  DEBUG(6,("Unable to add junction entry %s:%s after parsing\n",
			   junction->service_name,junction->volume_name));
		}
	      free(junction);
	    }
	  
	  /* then, create a new junction_map node */
	  if((junction = (struct junction_map*) malloc(sizeof(struct junction_map))) == NULL)
	    {
	      DEBUG(0,("Couldn't malloc for Dfs junction_map node\n"));
	      return False;
	    }
	  pstrcpy(junction->service_name,lp_servicename(snum));
	  pstrcpy(junction->volume_name,line);
	  ref_count = 0;
	}
      else
	{
	  /* referral encountered. add to current junction */
	  if(!junction)
	    {
	      DEBUG(4,("Invalid entry in Dfs map file.\nAlternate path defined outside of a junction in line:\n%s\n",line));
	      return False;
	    }

	  /* parse the referral */
	  if(!parse_referral(line,&tmp_ref_array[ref_count]))
	    continue;
	  ref_count++;

	}
    }
  
  /* End of file. Add the current junction and return */
  if(junction)
    {
      junction->referral_count = ref_count;
      junction->referral_list = tmp_ref_array;
      DEBUG(4,("Adding Dfs junction: %s\%s  Referrals: %u First referral path: %s\n",
		       junction->service_name,junction->volume_name,
		       junction->referral_count, junction->referral_list[0].alternate_path));
      if(!add_junction_entry(junction))
	{
	  DEBUG(6,("Unable to add junction entry %s:%s after parsing\n",
		   junction->service_name,junction->volume_name));
	}
      free(junction);
    }
  
  fclose(fp);
  msdfs_close();
  return True;
}

void load_dfsmaps(void)
{
  int i=0;
  if(!lp_host_msdfs()) 
    return;
  
  for(i=0;*lp_servicename(i) && *lp_dfsmap(i) 
	&& !lp_dfsmap_loaded(i);i++)
    {
      char* dfsmapfile = lp_dfsmap(i);
      DEBUG(4,("loading dfsmap for servicename: %s\n",lp_servicename(i)));
      if(load_dfsmap(dfsmapfile,i))
	{
	  set_dfsmap_loaded(i,True);
	}
      else
	{
	  DEBUG(0,("handle_dfsmap: Unable to load Dfs map file %s.\nService %s not using MS Dfs",dfsmapfile,lp_servicename(i)));
	  set_dfsmap_loaded(i,False);
	}
      
    }
}
	  
#else 
/* Stub function if MS_DFS is not defined */	  

void load_dfsmaps(void)
{}	  
	  
#endif		
	  
	  
	  
	     
	
	
	  
	  
