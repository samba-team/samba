
#include "includes.h"

extern int DEBUGLEVEL;

dfs_internal dfs_struct;
extern pstring global_myname;

/****************************************************************************
read a line and split it
****************************************************************************/
static BOOL parse_dfs_text_entry(char *line, dfs_internal_table *buf)
{
#define MAXTOK 4
	char *tok[MAXTOK+1];
	int count = 0;

	tok[count] = strtok(line,":");
	
	/* strip the comment lines */
	if (tok[0][0]=='#') return (False);	
	count++;
	
	while ( ((tok[count] = strtok(NULL,":")) != NULL ) && count<MAXTOK)
	{
		count++;
	}

	DEBUG(7,("Found [%d] tokens\n", count));

	if (count>1) {
		StrnCpy(buf->localpath, tok[0], sizeof(buf->localpath)-1);
		StrnCpy(buf->sharename, tok[1], sizeof(buf->sharename)-1);
/*
		strupper(buf->localpath);
		strupper(buf->sharename);		
*/
		buf->localpath_length=strlen(buf->localpath);
		buf->sharename_length=strlen(buf->sharename);
	}
	else
		return (False);
	
	if (count>2)
		buf->proximity = atoi(tok[2]);
	else
		buf->proximity = 0;
			
	if (count>3)	
		buf->type = atoi(tok[3]);
	else
		buf->type = 2;

	DEBUGADD(7,("[%s]\n", buf->localpath));
	DEBUGADD(7,("[%s]\n", buf->sharename));
	return(True);
}  

/****************************************************************************
mangle the localpath and store it.
****************************************************************************/
static void mangle_dfs_path(dfs_internal_table *buf)
{
	char *p;
	char *mp;
	char *q;
	int mlen;
	
	fstring temp;
	
	p = buf->localpath;
	mp =buf->mangledpath;
	mlen = sizeof(buf->mangledpath);
	
	ZERO_STRUCTP(mp);
	DEBUG(2, ("DFS name is: [%s]\n", buf->localpath));

	/* copy the head: \server-name\ */	
	q = strchr(p + 1, '\\');
	safe_strcpy(mp, p, mlen);	
	p = q + 1;
	
	while (q != NULL)
	{
		q = strchr(p, '\\');	
		
		safe_strcpy(temp, p, sizeof(temp));
		
		if (!is_8_3(temp, True))
		{
			mangle_name_83(temp);
		}
		
		safe_strcat(mp, temp, mlen);

		if (q != NULL)
		{
			safe_strcat(mp, "\\", mlen);
		}
		p = q + 1;	
	}

/*	
	strupper(mp);
*/
	buf->mangledpath_length = strlen(mp);
	DEBUGADD(2, ("DFS mangled name is: [%s]\n", mp));
}

/****************************************************************************
initialisation de la table dfs en memoire au demarrage de samba 
****************************************************************************/
BOOL init_dfs_table(void)
{
	char *file=lp_dfs_map();
	int num_lines=0;
	int total=0;
	FILE *f;
	pstring line;
	int i;
	
	dfs_internal_table *entry;
	
	entry=NULL;
	dfs_struct.ready=False;	
	
	if (*file=='\0') {
		DEBUG(0,("No DFS map, Samba is running in NON DFS mode\n"));
		return False;
	}
	
	f = sys_fopen(file, "r");
	if (!f) {
		DEBUG(0,("No DFS map file, Samba is running in NON DFS mode\n"));
		return False;
	}
	
	while ( fgets(line, sizeof(pstring), f) )
	{
		entry = Realloc(entry,sizeof(dfs_internal_table)*(total+1));
		if (! entry)
		{
			total = 0;
			break;
		}
		
		if ( parse_dfs_text_entry(line, &(entry[total]) ) )
		{
			total++;
		}
		num_lines++;
	}
	dfs_struct.size=total;
	dfs_struct.table=entry;
	fclose(f);
	
	/* we have the file in memory */
	/* now initialise the mangled names */	
	for (i=0; i<total; i++)
	{
		mangle_dfs_path(&(entry[i]));
	}

	dfs_struct.ready=True;	
	DEBUG(0,("Samba is DFS aware now!\n"));
	return True;
}

/****************************************************************************
 check if a path name is a DFS branch
****************************************************************************/
int under_dfs(connection_struct *conn, const char *path)
{
	fstring fullpath; 
	int i; 
	int snum;
		
	int mangled_len;
	int file_len;
	int path_len;

	BOOL ok=False; 

	dfs_internal_table *list=dfs_struct.table;
	
	snum=SNUM(conn);
	if (path[0] != '\\')
	{
		snprintf(fullpath, sizeof(fullpath), "\\%s\\%s\\%s",
		           global_myname, lp_servicename(snum), path);
	}
	else
	{
		safe_strcpy(fullpath, path, sizeof(fullpath));
	}
	
	strupper(fullpath);
	
	path_len=strlen(fullpath); 

	DEBUG(2,("DFS looking for: [%s]\n", fullpath));
	for(i=0; i<dfs_struct.size; i++)
	{ 
		file_len=list[i].localpath_length;
		mangled_len=list[i].mangledpath_length;
 
		DEBUG(6,("checking against [%s][%d]\n", list[i].localpath,i));
		
		if(file_len==path_len && !StrnCaseCmp(list[i].localpath, fullpath, file_len))
		{
			DEBUG(2,("found one linked to [%s]\n", list[i].sharename));
			ok=True;
			break;
		}
 
		if(mangled_len==path_len && !StrnCaseCmp(list[i].mangledpath, fullpath, mangled_len))
		{
			DEBUG(2,("found one mangled linked to [%s]\n", list[i].sharename));
			ok=True;
			break;
		}
	}
	return ok;
}
