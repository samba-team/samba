 /*
   Unix SMB/Netbios implementation.
   Version 1.9.
   Create printer definition files.

   Copyright (C) Jean-Francois.Micouleau@utc.fr, 10/26/97 - 1998

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

/*
#define DEBUGIT
*/

char *files_to_copy;
char *driverfile, *datafile, *helpfile, *languagemonitor, *datatype;
char buffer[50][sizeof(pstring)];
char sbuffer[50][sizeof(pstring)];
char sub_dir[50][2][sizeof(pstring)];

void usage(char *name)
{
 fprintf(stderr,"%s: printer.def \"Printer Name\"\n", name);
}

char *myfgets(char *s, int n, FILE *stream)
{
  char *LString1;
  char *LString2;
  char *temp;
  pstring String;
  pstring NewString;
  int i;

  fgets(s,n,stream);
  while ((LString1 = strchr(s,'%')) != NULL) {
    if (!(LString2 = strchr(LString1+1,'%'))) break;
    *LString2 = '\0';
    pstrcpy(String,LString1+1);
    i = 0;
    while(*sbuffer[i]!='\0') {
      if (strncmp(sbuffer[i],String,strlen(String))==0)
      {
	pstrcpy(String,sbuffer[i]);
	if ((temp = strchr(String,'=')) != NULL) ++temp;
	pstrcpy(String,temp);
	break;
      }
      i++;	
    }
    *LString1 = '\0';
    pstrcpy(NewString,s);
    pstrcat(NewString,String);
    pstrcat(NewString,LString2+1);
    pstrcpy(s, NewString);
  }
  return(s);
}

/*
   This function split a line in two parts
   on both side of the equal sign
   "entry=value"
*/
char *scan(char *chaine,char **entry)
{
  char *value;
  char *temp;
  int i=0;
 
  *entry=(char *)malloc(sizeof(pstring));
  value=(char *)malloc(sizeof(pstring));
  pstrcpy(*entry,chaine);
  temp=chaine;
  while( temp[i]!='=' && temp[i]!='\0') {
 	i++;
  }
  (*entry)[i]='\0'; 
  pstrcpy(value,temp+i+1);      
  return (value);
}

void build_subdir(void)
{
  int i=0;
  char *entry;
  char *data;
 
  while (*buffer[i]!='\0') { 
    data=scan(buffer[i],&entry);
#ifdef DEBUGIT
    fprintf(stderr,"\tentry=data %s:%s\n",entry,data);
#endif      

    if (strcmp(data,"11")==0) {
      pstrcpy(sub_dir[i][0],entry);
      pstrcpy(sub_dir[i][1],"");
    }
    if (strcmp(data,"23")==0) {
      pstrcpy(sub_dir[i][0],entry);
      pstrcpy(sub_dir[i][1],"color\\");
    }
#ifdef DEBUGIT
    fprintf(stderr,"\tsubdir %s:%s\n",sub_dir[i][0],sub_dir[i][1]);
#endif      
    i++;
  }
}

/*
   Lockup Strings entry in a file
   Return all the lines between the entry and the next one or the end of file
   An entry is something between braces.
*/
void lookup_strings(FILE *fichier)
{
  int found=0,pointeur=0,i=0;
  char *temp,*temp2;
  
  temp=(char *)malloc(sizeof(pstring));
  temp2=(char *)malloc(sizeof(pstring));
  
  *sbuffer[0]='\0';
  
  pstrcpy(temp2,"[Strings]");
  
  rewind(fichier);
#ifdef DEBUGIT
  fprintf(stderr,"\tLooking for Strings\n");
#endif
  
  while (!feof(fichier) && found==0) {
  	*temp='\0';
  	fgets(temp,255,fichier);
	if (strncmp(temp,temp2,strlen(temp2))==0) found=1;
  }


  while (!feof(fichier) && found==1) {
  	*temp='\0';
  	fgets(temp,255,fichier);
	if (*temp=='[') {
		found=2;
		*sbuffer[pointeur]='\0';
	}
	else {
		pstrcpy(sbuffer[pointeur],temp);
		i=strlen(sbuffer[pointeur])-1;
		while (sbuffer[pointeur][i]=='\r' || sbuffer[pointeur][i]=='\n')
			sbuffer[pointeur][i--]='\0';
		pointeur++;
	}  
  }
#ifdef DEBUGIT
  fprintf(stderr,"\t\tFound %d entries\n",pointeur-1);
#endif
}


/*
   Lockup an entry in a file
   Return all the lines between the entry and the next one or the end of file
   An entry is something between braces.
*/
void lookup_entry(FILE *fichier,char *chaine)
{
  int found=0,pointeur=0,i=0;
  char *temp,*temp2;
  
  temp=(char *)malloc(sizeof(pstring));
  temp2=(char *)malloc(sizeof(pstring));
  
  *buffer[0]='\0';
  
  pstrcpy(temp2,"[");
  pstrcat(temp2,chaine);
  pstrcat(temp2,"]");
  
  rewind(fichier);
#ifdef DEBUGIT
  fprintf(stderr,"\tLooking for %s\n",chaine);
#endif
  
  while (!feof(fichier) && found==0) {
  	*temp='\0';
  	myfgets(temp,255,fichier);
	if (strncmp(temp,temp2,strlen(temp2))==0) found=1;
  }


  while (!feof(fichier) && found==1) {
  	*temp='\0';
  	myfgets(temp,255,fichier);
	if (*temp=='[') {
		found=2;
		*buffer[pointeur]='\0';
	}
	else {
		pstrcpy(buffer[pointeur],temp);
		i=strlen(buffer[pointeur])-1;
		while (buffer[pointeur][i]=='\r' || buffer[pointeur][i]=='\n')
			buffer[pointeur][i--]='\0';
		pointeur++;
	}  
  }
#ifdef DEBUGIT
  fprintf(stderr,"\t\tFound %d entries\n",pointeur-1);
#endif
}

char *find_desc(FILE *fichier,char *text)
{
  char *chaine;
  char *long_desc;
  char *short_desc;
  char *crap = NULL;
  char *p;

  int found=0;

  chaine=(char *)malloc(sizeof(pstring));
  long_desc=(char *)malloc(sizeof(pstring));
  short_desc=(char *)malloc(sizeof(pstring));
  if (!chaine || !long_desc || !short_desc) {
    fprintf(stderr,"Unable to malloc memory\n");
    exit(1);
  }

  rewind(fichier);
  while (!feof(fichier) && found==0)
  {
    myfgets(chaine,255,fichier);

    long_desc=strtok(chaine,"=");
    crap=strtok(NULL,",\r");

    p=long_desc;
    while(*p!='"' && *p!='\0')
     p++;
    if (*p=='"' && *(p+1)!='\0') p++;       
    long_desc=p;

    if (*p!='\0')
    {
      p++;
      while(*p!='\"')
       p++;
      *p='\0';
    }
    if (!strcmp(text,long_desc)) 
	found=1;
  }
  free(chaine);
  if (!found || !crap) return(NULL);
  while(*crap==' ') crap++;
  pstrcpy(short_desc,crap);
  return(short_desc);
}

void scan_copyfiles(FILE *fichier, char *chaine)
{
  char *part;
  char *mpart;
  int i;
  pstring direc;
#ifdef DEBUGIT
  fprintf(stderr,"In scan_copyfiles Lookup up of %s\n",chaine);
#endif 
  fprintf(stderr,"\nCopy the following files to your printer$ share location:\n");
  part=strtok(chaine,",");
  do {
     /* If the entry start with a @ then it's a file to copy
     else it's an entry refering to files to copy
     the main difference is when it's an entry
     you can have a directory to append before the file name
    */
    if (*part=='@') {
      if (strlen(files_to_copy) != 0)
        pstrcat(files_to_copy,",");
      pstrcat(files_to_copy,&part[1]);
      fprintf(stderr,"%s\n",&part[1]);
    } else {
      lookup_entry(fichier,part);
      i=0;
      pstrcpy(direc,"");
      while (*sub_dir[i][0]!='\0') {
#ifdef DEBUGIT
 	fprintf(stderr,"\tsubdir %s:%s\n",sub_dir[i][0],sub_dir[i][1]);
#endif      
      	if (strcmp(sub_dir[i][0],part)==0)
		pstrcpy(direc,sub_dir[i][1]);
	i++;
      }	
      i=0;
      while (*buffer[i]!='\0') {
/*
 * HP inf files have strange entries that this attempts to address
 * Entries in the Copy sections normally have only a single file name
 * on each line. I have seen the following format in various HP inf files:
 * 
 * pscript.hlp =  pscript.hl_
 * hpdcmon.dll,hpdcmon.dl_
 * ctl3dv2.dll,ctl3dv2.dl_,ctl3dv2.tmp
 *
 * In the first 2 cases you want the first file name - in the last case
 * you only want the last file name (at least that is what a Win95
 * machine sent). This may still be wrong but at least I get the same list
 * of files as seen on a printer test page.
 */
        part = strchr(buffer[i],'=');
        if (part) {
          *part = '\0';
	  while (--part > buffer[i])
	    if ((*part == ' ') || (*part =='\t')) *part = '\0';
	    else break;
	} else {
	  part = strchr(buffer[i],',');
	  if (part) {
	    if ((mpart = strrchr(part+1,','))!=NULL) {
		pstrcpy(buffer[i],mpart+1);
	    } else
		*part = '\0';
            while (--part > buffer[i])
              if ((*part == ' ') || (*part =='\t')) *part = '\0';
              else break;
	  }
	}
        if (strlen(files_to_copy) != 0)
          pstrcat(files_to_copy,",");
	pstrcat(files_to_copy,direc);
	pstrcat(files_to_copy,buffer[i]);
	fprintf(stderr,"%s%s\n",direc,buffer[i]);
	i++;
      } 
    }
    part=strtok(NULL,",");
  }
  while (part!=NULL);
  fprintf(stderr,"\n");
}


void scan_short_desc(FILE *fichier, char *short_desc)
{
  int i=0;
  char *chaine;
  char *temp;
  char *copyfiles=0,*datasection=0;
 
  helpfile=0;
  languagemonitor=0;
  datatype="RAW";
  chaine=(char *)malloc(sizeof(pstring));
  temp=(char *)malloc(sizeof(pstring));
  
  driverfile=short_desc;
  datafile=short_desc;

  lookup_entry(fichier,short_desc);

  while(*buffer[i]!='\0') {
#ifdef DEBUGIT
    fprintf(stderr,"\tLookup up of %s\n",buffer[i]);
#endif
    if (strncasecmp(buffer[i],"CopyFiles",9)==0) 
	copyfiles=scan(buffer[i],&temp);
    else if (strncasecmp(buffer[i],"DataSection",11)==0) 
	datasection=scan(buffer[i],&temp);
    else if (strncasecmp(buffer[i],"DataFile",8)==0) 
	datafile=scan(buffer[i],&temp);
    else if (strncasecmp(buffer[i],"DriverFile",10)==0) 
	driverfile=scan(buffer[i],&temp);
    else if (strncasecmp(buffer[i],"HelpFile",8)==0) 
	helpfile=scan(buffer[i],&temp);
    else if (strncasecmp(buffer[i],"LanguageMonitor",15)==0) 
	languagemonitor=scan(buffer[i],&temp);
    else if (strncasecmp(buffer[i],"DefaultDataType",15)==0) 
	datatype=scan(buffer[i],&temp);
    i++;	
  }

  if (datasection) {
    lookup_entry(fichier,datasection);

    i = 0;
    while(*buffer[i]!='\0') {
#ifdef DEBUGIT
      fprintf(stderr,"\tLookup up of %s\n",buffer[i]);
#endif
      if (strncasecmp(buffer[i],"CopyFiles",9)==0) 
	  copyfiles=scan(buffer[i],&temp);
      else if (strncasecmp(buffer[i],"DataSection",11)==0) 
	  datasection=scan(buffer[i],&temp);
      else if (strncasecmp(buffer[i],"DataFile",8)==0) 
	  datafile=scan(buffer[i],&temp);
      else if (strncasecmp(buffer[i],"DriverFile",10)==0) 
	  driverfile=scan(buffer[i],&temp);
      else if (strncasecmp(buffer[i],"HelpFile",8)==0) 
	  helpfile=scan(buffer[i],&temp);
      else if (strncasecmp(buffer[i],"LanguageMonitor",15)==0) 
	  languagemonitor=scan(buffer[i],&temp);
      else if (strncasecmp(buffer[i],"DefaultDataType",15)==0) 
	  datatype=scan(buffer[i],&temp);
      i++;	
    }
  }

  if (languagemonitor) {
	temp = strtok(languagemonitor,",");
	if (*temp == '"') ++temp;
	pstrcpy(languagemonitor,temp);
	if ((temp = strchr(languagemonitor,'"'))!=NULL) *temp = '\0';
  }

  if (i) fprintf(stderr,"End of section found\n");
 
  fprintf(stderr,"CopyFiles: %s\n",
	copyfiles?copyfiles:"(null)");
  fprintf(stderr,"Datasection: %s\n",
	datasection?datasection:"(null)");
  fprintf(stderr,"Datafile: %s\n",
	datafile?datafile:"(null)");
  fprintf(stderr,"Driverfile: %s\n",
	driverfile?driverfile:"(null)");
  fprintf(stderr,"Helpfile: %s\n",
	helpfile?helpfile:"(null)");
  fprintf(stderr,"LanguageMonitor: %s\n",
	languagemonitor?languagemonitor:"(null)");
  if (copyfiles) scan_copyfiles(fichier,copyfiles);
}

int main(int argc, char *argv[])
{
  char *short_desc;
  FILE *inf_file;

  if (argc!=3)
  {
    usage(argv[0]);
    return(-1);
  }

  inf_file=fopen(argv[1],"r");  
  if (!inf_file)
  {
    fprintf(stderr,"Description file not found, bye\n");
    return(-1);
  }

  lookup_strings(inf_file);

  short_desc=find_desc(inf_file,argv[2]);
  if (short_desc==NULL)
  {
    fprintf(stderr,"Printer not found\n");
    return(-1);
  }
  else fprintf(stderr,"Found:%s\n",short_desc);

  lookup_entry(inf_file,"DestinationDirs");
  build_subdir();

  files_to_copy=(char *)malloc(2048*sizeof(char));
  *files_to_copy='\0';
  scan_short_desc(inf_file,short_desc);
  fprintf(stdout,"%s:%s:%s:",
    argv[2],driverfile,datafile);
  fprintf(stdout,"%s:",
    helpfile?helpfile:"");
  fprintf(stdout,"%s:",
    languagemonitor?languagemonitor:"");
  fprintf(stdout,"%s:",datatype);
  fprintf(stdout,"%s\n",files_to_copy);
  return 0;
}

