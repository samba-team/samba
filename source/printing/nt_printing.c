#include "includes.h"
#include "nterr.h"

extern int DEBUGLEVEL;

/****************************************************************************
parse a form line.
****************************************************************************/
static BOOL parse_form_entry(char *line, nt_forms_struct *buf)
{
#define NAMETOK   0
#define FLAGTOK   1
#define WIDTHTOK  2
#define LENGTHTOK 3
#define LEFTTOK   4
#define TOPTOK    5
#define RIGHTTOK  6
#define BOTTOMTOK 7
#define MAXTOK 8
	char *tok[MAXTOK];
	int count = 0;

	tok[count] = strtok(line,":");
	
	/* strip the comment lines */
	if (tok[0][0]=='#') return (False);	
	count++;
	
	while ( ((tok[count] = strtok(NULL,":")) != NULL ) && count<MAXTOK-1)
	{
		count++;
	}

	DEBUG(6,("Found [%d] tokens\n", count));

	StrnCpy(buf->name,tok[NAMETOK],sizeof(buf->name)-1);
	buf->flag=atoi(tok[FLAGTOK]);
	buf->width=atoi(tok[WIDTHTOK]);
	buf->length=atoi(tok[LENGTHTOK]);
	buf->left=atoi(tok[LEFTTOK]);
	buf->top=atoi(tok[TOPTOK]);
	buf->right=atoi(tok[RIGHTTOK]);
	buf->bottom=atoi(tok[BOTTOMTOK]);
	
	return(True);
}  
  
/****************************************************************************
get a form struct list
****************************************************************************/
int get_ntforms(nt_forms_struct **list)
{
	FILE *f;
	pstring line;
	char *lp_forms = lp_nt_forms();
	int total=0;
	int grandtotal=0;
	*line=0;

	f = sys_fopen(lp_forms,"r");
	if (!f)
	{
		return(0);
	}

	while ( fgets(line, sizeof(pstring), f) )
	{
		DEBUG(5,("%s\n",line));
		
		*list = Realloc(*list, sizeof(nt_forms_struct)*(total+1));
		if (! *list)
		{
			total = 0;
			break;
		}
		memset( (char *)&(*list)[total], 0,  sizeof(nt_forms_struct) );
		if ( parse_form_entry(line, &(*list)[total] ) )
		{
			total++;
		}
		grandtotal++;
	}    
	fclose(f);

	DEBUG(4,("%d info lines on %d\n",total, grandtotal));

	return(total);
}

/****************************************************************************
write a form struct list
****************************************************************************/
int write_ntforms(nt_forms_struct **list, int number)
{
       FILE *f;
       pstring line;
       char *file = lp_nt_forms();
       int total=0;
       int i;

       *line=0;

       DEBUG(6,("write_ntforms\n"));

       if((f = sys_fopen(file, "w")) == NULL)
       {
	       DEBUG(1, ("cannot create forms file [%s]\n", file));
	       return(0);
       }

       for (i=0; i<number;i++)
       {

	       fprintf(f,"%s:%d:%d:%d:%d:%d:%d:%d\n", (*list)[i].name,
		       (*list)[i].flag, (*list)[i].width, (*list)[i].length,
		       (*list)[i].left, (*list)[i].top, (*list)[i].right, (*list)[i].bottom);

	       DEBUGADD(7,("adding entry [%s]\n", (*list)[i].name));
       }

       fclose(f);
       DEBUGADD(6,("closing file\n"));
       return(total);
}

/****************************************************************************
add a form struct at the end of the list
****************************************************************************/
void add_a_form(nt_forms_struct **list, const FORM *form, int *count)
{
	int n=0;
	BOOL update;
	fstring form_name;

	/* 
	 * NT tries to add forms even when 
	 * they are already in the base
	 * only update the values if already present
	 */

	update=False;
	
	unistr2_to_ascii(form_name, &(form->name), sizeof(form_name)-1);
	for (n=0; n<*count && update==False; n++)
	{
		if (!strncmp((*list)[n].name, form_name, strlen(form_name)))
		{
			DEBUG(3, ("NT workaround, [%s] already exists\n", form_name));
			update=True;
		}
	}

	if (update==False)
	{
		*list=Realloc(*list, (n+1)*sizeof(nt_forms_struct));
		unistr2_to_ascii((*list)[n].name, &(form->name), sizeof((*list)[n].name)-1);
		(*count)++;
	}
	
	(*list)[n].flag=form->flags;
	(*list)[n].width=form->size_x;
	(*list)[n].length=form->size_y;
	(*list)[n].left=form->left;
	(*list)[n].top=form->top;
	(*list)[n].right=form->right;
	(*list)[n].bottom=form->bottom;
}

/****************************************************************************
update a form struct 
****************************************************************************/
void update_a_form(nt_forms_struct **list, const FORM *form, int count)
{
	int n=0;
	fstring form_name;
	unistr2_to_ascii(form_name, &(form->name), sizeof(form_name)-1);

	DEBUG(6, ("[%s]\n", form_name));
	for (n=0; n<count; n++)
	{
		DEBUGADD(6, ("n [%d]:[%s]\n", n, (*list)[n].name));
		if (!strncmp((*list)[n].name, form_name, strlen(form_name)))
			break;
	}

	if (n==count) return;

	(*list)[n].flag=form->flags;
	(*list)[n].width=form->size_x;
	(*list)[n].length=form->size_y;
	(*list)[n].left=form->left;
	(*list)[n].top=form->top;
	(*list)[n].right=form->right;
	(*list)[n].bottom=form->bottom;
}
 
/****************************************************************************
get the nt drivers list

open the directory and look-up the matching names
****************************************************************************/
int get_ntdrivers(fstring **list, char *architecture)
{
	DIR *dirp;
	char *dpname;
	fstring name_match;
	fstring short_archi;
	fstring driver_name;
	int match_len;
	int total=0;

	DEBUG(5,("Getting the driver list from directory: [%s]\n", lp_nt_drivers_file()));
	
	*list=NULL;
	dirp = opendir(lp_nt_drivers_file());

	if (dirp == NULL)
	{
		DEBUG(0,("Error opening driver directory [%s]\n",lp_nt_drivers_file())); 
		return(-1);
	}
	
	get_short_archi(short_archi, architecture);
	slprintf(name_match, sizeof(name_match)-1, "NTdriver_%s_", short_archi);
	match_len=strlen(name_match);
	
	while ((dpname = readdirname(dirp)) != NULL)
	{
		if (strncmp(dpname, name_match, match_len)==0)
		{
			DEBUGADD(7,("Found: [%s]\n", dpname));
			
			StrCpy(driver_name, dpname+match_len);
			all_string_sub(driver_name, "#", "/", 0);
			*list = Realloc(*list, sizeof(fstring)*(total+1));
			StrnCpy((*list)[total], driver_name, strlen(driver_name));
			DEBUGADD(6,("Added: [%s]\n", driver_name));		
			total++;
		}
	}

	closedir(dirp);
	return(total);
}

/****************************************************************************
function to do the mapping between the long architecture name and
the short one.
****************************************************************************/
void get_short_archi(char *short_archi, char *long_archi)
{
	struct table {
		char *long_archi;
		char *short_archi;
	};
	
	struct table archi_table[]=
	{
		{"Windows 4.0",          ""       },
		{"Windows NT x86",       "W32X86" },
		{"Windows NT R4000",     ""       },
		{"Windows NT Alpha_AXP", ""       },
		{"Windows NT PowerPC",   ""       },
		{NULL,                   ""       }
	};
	
	int i=-1;

	DEBUG(7,("Getting architecture dependant directory\n"));
	do {
		i++;
	} while ( (archi_table[i].long_archi!=NULL ) && strncmp(long_archi, archi_table[i].long_archi, strlen(long_archi)) );

	if (archi_table[i].long_archi==NULL)
	{
		DEBUGADD(7,("Unknown architecture [%s] !\n", long_archi));
	}
	StrnCpy (short_archi, archi_table[i].short_archi, strlen(archi_table[i].short_archi));

	DEBUGADD(8,("index: [%d]\n", i));
	DEBUGADD(8,("long architecture: [%s]\n", long_archi));
	DEBUGADD(8,("short architecture: [%s]\n", short_archi));
}

/****************************************************************************
****************************************************************************/
static uint32 add_a_printer_driver_3(NT_PRINTER_DRIVER_INFO_LEVEL_3 *driver)
{
	FILE *f;
	pstring file;
	fstring architecture;
	fstring driver_name;
	char **dependentfiles;

	/* create a file in the dir lp_nt_driver_file */
	/* with the full printer DRIVER name */
	/* eg: "/usr/local/samba/lib/NTdriver_HP LaserJet 6MP" */
	/* each name is really defining an *unique* printer model */
	/* I don't want to mangle the name to find it back when enumerating */

	/* il faut substituer les / par 1 autre caractere d'abord */
	/* dans le nom de l'imprimante par un # ???*/

	StrnCpy(driver_name, driver->name, sizeof(driver_name)-1);

	all_string_sub(driver_name, "/", "#", 0);

	get_short_archi(architecture, driver->environment);
		
	slprintf(file, sizeof(file)-1, "%s/NTdriver_%s_%s",
	         lp_nt_drivers_file(), architecture, driver_name);
		
	if((f = sys_fopen(file, "w")) == NULL)
	{
		DEBUG(1, ("cannot create driver file [%s]\n", file));
		return(2);
	}

	/*
	 * cversion must be 2.
	 * when adding a printer ON the SERVER
	 * rpcAddPrinterDriver defines it to zero
	 * which is wrong !!!
	 *
	 * JFM, 4/14/99
	 */
	driver->cversion=2;
	
	fprintf(f, "version:         %d\n", driver->cversion);
	fprintf(f, "name:            %s\n", driver->name);
	fprintf(f, "environment:     %s\n", driver->environment);
	fprintf(f, "driverpath:      %s\n", driver->driverpath);
	fprintf(f, "datafile:        %s\n", driver->datafile);
	fprintf(f, "configfile:      %s\n", driver->configfile);
	fprintf(f, "helpfile:        %s\n", driver->helpfile);
	fprintf(f, "monitorname:     %s\n", driver->monitorname);
	fprintf(f, "defaultdatatype: %s\n", driver->defaultdatatype);

	/* and the dependants files */
	
	dependentfiles=driver->dependentfiles;
	
	while ( **dependentfiles != '\0' )
	{
		fprintf(f, "dependentfile:   %s\n", *dependentfiles);
		dependentfiles++;
	}
	
	fclose(f);	
	return(0);
}

/****************************************************************************
****************************************************************************/
static uint32 get_a_printer_driver_3(NT_PRINTER_DRIVER_INFO_LEVEL_3 **info_ptr, fstring in_prt, fstring in_arch)
{
	FILE *f;
	pstring file;
	fstring driver_name;
	fstring architecture;
	NT_PRINTER_DRIVER_INFO_LEVEL_3 *info;
	char *line;
	fstring p;
	char *v;
	int i=0;
	char **dependentfiles=NULL;
	
	/*
	 * replace all the / by # in the driver name
	 * get the short architecture name
	 * construct the driver file name
	 */
	StrnCpy(driver_name, in_prt, sizeof(driver_name)-1);
	all_string_sub(driver_name, "/", "#", 0);

	get_short_archi(architecture, in_arch);
		
	slprintf(file, sizeof(file)-1, "%s/NTdriver_%s_%s",
	         lp_nt_drivers_file(), architecture, driver_name);
			
	if((f = sys_fopen(file, "r")) == NULL)
	{
		DEBUG(2, ("cannot open printer driver file [%s]\n", file));
		return(2);
	}

	/* the file exists, allocate some memory */
	info=(NT_PRINTER_DRIVER_INFO_LEVEL_3 *)malloc(sizeof(NT_PRINTER_DRIVER_INFO_LEVEL_3));
	ZERO_STRUCTP(info);
	
	/* allocate a 4Kbytes buffer for parsing lines */
	line=(char *)malloc(4096*sizeof(char));
	
	while ( fgets(line, 4095, f) )
	{

		v=strncpyn(p, line, sizeof(p), ':');
		if (v==NULL)
		{
			DEBUG(1, ("malformed printer entry (no :)\n"));
			continue;
		}
		
		v++;
		
		trim_string(v, " ", NULL);
		trim_string(v, NULL, " ");
		trim_string(v, NULL, "\n");
		/* don't check if v==NULL as an empty arg is valid */
		
		if (!strncmp(p, "version", strlen("version")))
			info->cversion=atoi(v);

		if (!strncmp(p, "name", strlen("name")))
			StrnCpy(info->name, v, strlen(v));

		if (!strncmp(p, "environment", strlen("environment")))
			StrnCpy(info->environment, v, strlen(v));

		if (!strncmp(p, "driverpath", strlen("driverpath")))
			StrnCpy(info->driverpath, v, strlen(v));

		if (!strncmp(p, "datafile", strlen("datafile")))
			StrnCpy(info->datafile, v, strlen(v));

		if (!strncmp(p, "configfile", strlen("configfile")))
			StrnCpy(info->configfile, v, strlen(v));

		if (!strncmp(p, "helpfile", strlen("helpfile")))
			StrnCpy(info->helpfile, v, strlen(v));

		if (!strncmp(p, "monitorname", strlen("monitorname")))
			StrnCpy(info->monitorname, v, strlen(v));

		if (!strncmp(p, "defaultdatatype", strlen("defaultdatatype")))
			StrnCpy(info->defaultdatatype, v, strlen(v));

		if (!strncmp(p, "dependentfile", strlen("dependentfile")))
		{
			dependentfiles=(char **)Realloc(dependentfiles, sizeof(char *)*(i+1));
			
			dependentfiles[i]=(char *)malloc( sizeof(char)* (strlen(v)+1) );
			
			StrnCpy(dependentfiles[i], v, strlen(v) );
			i++;
		}

	}
	
	free(line);
	
	fclose(f);
	
	dependentfiles=(char **)Realloc(dependentfiles, sizeof(char *)*(i+1));
	dependentfiles[i]=(char *)malloc( sizeof(char) );
	*dependentfiles[i]='\0';
	
	info->dependentfiles=dependentfiles;
	
	*info_ptr=info;
	
	return (0);	
}

/****************************************************************************
debugging function, dump at level 6 the struct in the logs
****************************************************************************/
static uint32 dump_a_printer_driver(NT_PRINTER_DRIVER_INFO_LEVEL driver, uint32 level)
{
	uint32 success;
	NT_PRINTER_DRIVER_INFO_LEVEL_3 *info3;
	char **dependentfiles;	
	
	DEBUG(6,("Dumping printer driver at level [%d]\n", level));
	
	switch (level)
	{
		case 3: 
		{
			if (driver.info_3 == NULL)
			{
				DEBUGADD(3,("NULL pointer, memory not alloced ?\n"));
				success=5;
			}
			else
			{
				info3=driver.info_3;
			
				DEBUGADD(6,("version:[%d]\n",         info3->cversion));
				DEBUGADD(6,("name:[%s]\n",            info3->name));
				DEBUGADD(6,("environment:[%s]\n",     info3->environment));
				DEBUGADD(6,("driverpath:[%s]\n",      info3->driverpath));
				DEBUGADD(6,("datafile:[%s]\n",        info3->datafile));
				DEBUGADD(6,("configfile:[%s]\n",      info3->configfile));
				DEBUGADD(6,("helpfile:[%s]\n",        info3->helpfile));
				DEBUGADD(6,("monitorname:[%s]\n",     info3->monitorname));
				DEBUGADD(6,("defaultdatatype:[%s]\n", info3->defaultdatatype));
				
				dependentfiles=info3->dependentfiles;
	
				while ( **dependentfiles != '\0' )
				{
					DEBUGADD(6,("dependentfile:[%s]\n", *dependentfiles));
					dependentfiles++;
				}
				success=0;
			}
			break;
		}
		default:
			DEBUGADD(1,("Level not implemented\n"));
			success=1;
			break;
	}
	
	return (success);
}

/****************************************************************************
****************************************************************************/
static void add_a_devicemode(NT_DEVICEMODE *nt_devmode, FILE *f)
{
	int i;
	
	fprintf(f, "formname: %s\n",      nt_devmode->formname);
	fprintf(f, "specversion: %d\n",   nt_devmode->specversion);
	fprintf(f, "driverversion: %d\n", nt_devmode->driverversion);
	fprintf(f, "size: %d\n",          nt_devmode->size);
	fprintf(f, "driverextra: %d\n",   nt_devmode->driverextra);
	fprintf(f, "fields: %d\n",        nt_devmode->fields);
	fprintf(f, "orientation: %d\n",   nt_devmode->orientation);
	fprintf(f, "papersize: %d\n",     nt_devmode->papersize);
	fprintf(f, "paperlength: %d\n",   nt_devmode->paperlength);
	fprintf(f, "paperwidth: %d\n",    nt_devmode->paperwidth);
	fprintf(f, "scale: %d\n",         nt_devmode->scale);
	fprintf(f, "copies: %d\n",        nt_devmode->copies);
	fprintf(f, "defaultsource: %d\n", nt_devmode->defaultsource);
	fprintf(f, "printquality: %d\n",  nt_devmode->printquality);
	fprintf(f, "color: %d\n",         nt_devmode->color);
	fprintf(f, "duplex: %d\n",        nt_devmode->duplex);
	fprintf(f, "yresolution: %d\n",   nt_devmode->yresolution);
	fprintf(f, "ttoption: %d\n",      nt_devmode->ttoption);
	fprintf(f, "collate: %d\n",       nt_devmode->collate);
	fprintf(f, "icmmethod: %d\n",     nt_devmode->icmmethod);
	fprintf(f, "icmintent: %d\n",     nt_devmode->icmintent);
	fprintf(f, "mediatype: %d\n",     nt_devmode->mediatype);
	fprintf(f, "dithertype: %d\n",    nt_devmode->dithertype);
	
	if (nt_devmode->private != NULL)
	{
		fprintf(f, "private: ");		
		for (i=0; i<nt_devmode->driverextra; i++)
			fprintf(f, "%02X", nt_devmode->private[i]);
		fprintf(f, "\n");	
	}
}

/****************************************************************************
****************************************************************************/
static void save_specifics(NT_PRINTER_PARAM *param, FILE *f)
{
	int i;
	
	while (param != NULL)
	{
		fprintf(f, "specific: %s#%d#%d#", param->value, param->type, param->data_len);
		
		for (i=0; i<param->data_len; i++)
			fprintf(f, "%02X", param->data[i]);
		
		fprintf(f, "\n");
	
		param=param->next;	
	}
}

/****************************************************************************
****************************************************************************/
static uint32 add_a_printer_2(NT_PRINTER_INFO_LEVEL_2 *info)
{
	FILE *f;
	pstring file;
	fstring printer_name;
	NT_DEVICEMODE *nt_devmode;
	
	/*
	 * JFM: one day I'll forget.
	 * below that's info->portname because that's the SAMBA sharename
	 * and I made NT 'thinks' it's the portname
	 * the info->sharename is the thing you can name when you add a printer
	 * that's the short-name when you create shared printer for 95/98
	 * So I've made a limitation in SAMBA: you can only have 1 printer model
	 * behind a SAMBA share.
	 */


	StrnCpy(printer_name, info->portname, sizeof(printer_name)-1);
		
	slprintf(file, sizeof(file)-1, "%s/NTprinter_%s",
	         lp_nt_drivers_file(), printer_name);

	/* create a file in the dir lp_nt_driver_file */
	/* with the full printer name */
	/* eg: "/usr/local/samba/lib/NTprinter_HP LaserJet 6MP" */
	/* each name is really defining an *unique* printer model */
	/* I don't want to mangle the name to find it back when enumerating */
	
	if((f = sys_fopen(file, "w")) == NULL)
	{
		DEBUG(1, ("cannot create printer file [%s]\n", file));
		return(2);
	}

	fprintf(f, "attributes: %d\n", info->attributes);
	fprintf(f, "priority: %d\n", info->priority);
	fprintf(f, "default_priority: %d\n", info->default_priority);
	fprintf(f, "starttime: %d\n", info->starttime);
	fprintf(f, "untiltime: %d\n", info->untiltime);
	fprintf(f, "status: %d\n", info->status);
	fprintf(f, "cjobs: %d\n", info->cjobs);
	fprintf(f, "averageppm: %d\n", info->averageppm);

	/* 
	 * in addprinter: no servername and the printer is the name
	 * in setprinter: servername is \\server
	 *                and printer is \\server\\printer
	 *
	 * Samba manages only local printers.
	 * we currently don't support things like path=\\other_server\printer
	 */

	if (info->servername[0]!='\0')
	{
		trim_string(info->printername, info->servername, NULL);
		trim_string(info->printername, "\\", NULL);
		info->servername[0]='\0';
	}

	fprintf(f, "servername: %s\n", info->servername);
	fprintf(f, "printername: %s\n", info->printername);
	fprintf(f, "sharename: %s\n", info->sharename);
	fprintf(f, "portname: %s\n", info->portname);
	fprintf(f, "drivername: %s\n", info->drivername);
	fprintf(f, "comment: %s\n", info->comment);
	fprintf(f, "location: %s\n", info->location);
	fprintf(f, "sepfile: %s\n", info->sepfile);
	fprintf(f, "printprocessor: %s\n", info->printprocessor);
	fprintf(f, "datatype: %s\n", info->datatype);
	fprintf(f, "parameters: %s\n", info->parameters);

	/* store the devmode and the private part if it exist */
	nt_devmode=info->devmode;
	if (nt_devmode!=NULL)
	{
		add_a_devicemode(nt_devmode, f);
	}
	
	/* and store the specific parameters */
	if (info->specific != NULL)
	{
		save_specifics(info->specific, f);
	}
	
	fclose(f);
	
	return (0);	
}

/****************************************************************************
fill a NT_PRINTER_PARAM from a text file

used when reading from disk.
****************************************************************************/
static void dissect_and_fill_a_param(NT_PRINTER_PARAM *param, char *v)
{
	char *tok[5];
	int count = 0;

	DEBUG(5,("dissect_and_fill_a_param\n"));	
		
	tok[count] = strtok(v,"#");
	count++;
	
	while ( ((tok[count] = strtok(NULL,"#")) != NULL ) && count<4)
	{
		count++;
	}

	StrnCpy(param->value, tok[0], sizeof(param->value)-1);
	param->type=atoi(tok[1]);
	param->data_len=atoi(tok[2]);
	param->data=(uint8 *)malloc(param->data_len * sizeof(uint8));			
	strhex_to_str(param->data, 2*(param->data_len), tok[3]);		
	param->next=NULL;	

	DEBUGADD(5,("value:[%s], len:[%d]\n", param->value, param->data_len));
}

/****************************************************************************
fill a NT_PRINTER_PARAM from a text file

used when reading from disk.
****************************************************************************/
void dump_a_param(NT_PRINTER_PARAM *param)
{
	DEBUG(5,("dump_a_param\n"));
	DEBUGADD(6,("value [%s]\n", param->value));
	DEBUGADD(6,("type [%d]\n", param->type));
	DEBUGADD(6,("data len [%d]\n", param->data_len));
}

/****************************************************************************
****************************************************************************/
BOOL add_a_specific_param(NT_PRINTER_INFO_LEVEL_2 *info_2, NT_PRINTER_PARAM *param)
{
	NT_PRINTER_PARAM *current;
	
	DEBUG(8,("add_a_specific_param\n"));	

	param->next=NULL;
	
	if (info_2->specific == NULL)
	{
		info_2->specific=param;
	}
	else
	{
		current=info_2->specific;		
		while (current->next != NULL) {
			current=current->next;
		}		
		current->next=param;
	}
	return (True);
}

/****************************************************************************
****************************************************************************/
BOOL unlink_specific_param_if_exist(NT_PRINTER_INFO_LEVEL_2 *info_2, NT_PRINTER_PARAM *param)
{
	NT_PRINTER_PARAM *current;
	NT_PRINTER_PARAM *previous;
	
	current=info_2->specific;
	previous=current;
	
	if (current==NULL) return (False);
	
	if ( !strcmp(current->value, param->value) && 
	    (strlen(current->value)==strlen(param->value)) )
	{
		DEBUG(9,("deleting first value\n"));
		info_2->specific=current->next;
		free(current);
		DEBUG(9,("deleted first value\n"));
		return (True);
	}

	current=previous->next;
		
	while ( current!=NULL )
	{
		if (!strcmp(current->value, param->value) &&
		    strlen(current->value)==strlen(param->value) )
		{
			DEBUG(9,("deleting current value\n"));
			previous->next=current->next;
			free(current);
			DEBUG(9,("deleted current value\n"));
			return(True);
		}
		
		previous=previous->next;
		current=current->next;
	}
	return (False);
}

/****************************************************************************
****************************************************************************/
static uint32 get_a_printer_2(NT_PRINTER_INFO_LEVEL_2 **info_ptr, fstring sharename)
{
	FILE *f;
	pstring file;
	fstring printer_name;
	NT_PRINTER_INFO_LEVEL_2 *info;
	NT_DEVICEMODE *nt_devmode;
	NT_PRINTER_PARAM *param;
	char *line;
	fstring p;
	char *v;
		
	/*
	 * the sharename argument is the SAMBA sharename
	 */
	StrnCpy(printer_name, sharename, sizeof(printer_name)-1);
		
	slprintf(file, sizeof(file)-1, "%s/NTprinter_%s",
	         lp_nt_drivers_file(), printer_name);
	
	if((f = sys_fopen(file, "r")) == NULL)
	{
		DEBUG(2, ("cannot open printer file [%s]\n", file));
		return(2);
	}

	/* the file exists, allocate some memory */
	info=(NT_PRINTER_INFO_LEVEL_2 *)malloc(sizeof(NT_PRINTER_INFO_LEVEL_2));
	ZERO_STRUCTP(info);

	nt_devmode=(NT_DEVICEMODE *)malloc(sizeof(NT_DEVICEMODE));
	ZERO_STRUCTP(nt_devmode);
	init_devicemode(nt_devmode);
	
	info->devmode=nt_devmode;

	line=(char *)malloc(4096*sizeof(char));
	
	while ( fgets(line, 4095, f) )
	{

		v=strncpyn(p, line, sizeof(p), ':');
		if (v==NULL)
		{
			DEBUG(1, ("malformed printer entry (no `:')\n"));
			DEBUGADD(2, ("line [%s]\n", line));		
			continue;
		}
		
		v++;
		
		trim_string(v, " ", NULL);
		trim_string(v, NULL, " ");
		trim_string(v, NULL, "\n");
		
		/* don't check if v==NULL as an empty arg is valid */
		
		DEBUGADD(15, ("[%s]:[%s]\n", p, v));

		/*
		 * The PRINTER_INFO_2 fields
		 */
		
		if (!strncmp(p, "attributes", strlen("attributes")))
			info->attributes=atoi(v);

		if (!strncmp(p, "priority", strlen("priority")))
			info->priority=atoi(v);

		if (!strncmp(p, "default_priority", strlen("default_priority")))
			info->default_priority=atoi(v);

		if (!strncmp(p, "starttime", strlen("starttime")))
			info->starttime=atoi(v);

		if (!strncmp(p, "untiltime", strlen("untiltime")))
			info->untiltime=atoi(v);

		if (!strncmp(p, "status", strlen("status")))
			info->status=atoi(v);

		if (!strncmp(p, "cjobs", strlen("cjobs")))
			info->cjobs=atoi(v);

		if (!strncmp(p, "averageppm", strlen("averageppm")))
			info->averageppm=atoi(v);
		
		if (!strncmp(p, "servername", strlen("servername")))
			StrnCpy(info->servername, v, strlen(v));

		if (!strncmp(p, "printername", strlen("printername")))
			StrnCpy(info->printername, v, strlen(v));

		if (!strncmp(p, "sharename", strlen("sharename")))
			StrnCpy(info->sharename, v, strlen(v));

		if (!strncmp(p, "portname", strlen("portname")))
			StrnCpy(info->portname, v, strlen(v));

		if (!strncmp(p, "drivername", strlen("drivername")))
			StrnCpy(info->drivername, v, strlen(v));

		if (!strncmp(p, "comment", strlen("comment")))
			StrnCpy(info->comment, v, strlen(v));

		if (!strncmp(p, "location", strlen("location")))
			StrnCpy(info->location, v, strlen(v));

		if (!strncmp(p, "sepfile", strlen("sepfile")))
			StrnCpy(info->sepfile, v, strlen(v));

		if (!strncmp(p, "printprocessor", strlen("printprocessor")))
			StrnCpy(info->printprocessor, v, strlen(v));

		if (!strncmp(p, "datatype", strlen("datatype")))
			StrnCpy(info->datatype, v, strlen(v));

		if (!strncmp(p, "parameters", strlen("parameters")))
			StrnCpy(info->parameters, v, strlen(v));

		/*
		 * The DEVICEMODE fields
		 */

		if (!strncmp(p, "formname", strlen("formname")))
			StrnCpy(nt_devmode->formname, v, strlen(v));
			
		if (!strncmp(p, "specversion", strlen("specversion")))
			nt_devmode->specversion=atoi(v);

		if (!strncmp(p, "driverversion", strlen("driverversion")))
			nt_devmode->driverversion=atoi(v);

		if (!strncmp(p, "size", strlen("size")))
			nt_devmode->size=atoi(v);

		if (!strncmp(p, "driverextra", strlen("driverextra")))
			nt_devmode->driverextra=atoi(v);

		if (!strncmp(p, "fields", strlen("fields")))
			nt_devmode->fields=atoi(v);

		if (!strncmp(p, "orientation", strlen("orientation")))
			nt_devmode->orientation=atoi(v);

		if (!strncmp(p, "papersize", strlen("papersize")))
			nt_devmode->papersize=atoi(v);

		if (!strncmp(p, "paperlength", strlen("paperlength")))
			nt_devmode->paperlength=atoi(v);

		if (!strncmp(p, "paperwidth", strlen("paperwidth")))
			nt_devmode->paperwidth=atoi(v);

		if (!strncmp(p, "scale", strlen("scale")))
			nt_devmode->scale=atoi(v);

		if (!strncmp(p, "copies", strlen("copies")))
			nt_devmode->copies=atoi(v);

		if (!strncmp(p, "defaultsource", strlen("defaultsource")))
			nt_devmode->defaultsource=atoi(v);

		if (!strncmp(p, "printquality", strlen("printquality")))
			nt_devmode->printquality=atoi(v);

		if (!strncmp(p, "color", strlen("color")))
			nt_devmode->color=atoi(v);

		if (!strncmp(p, "duplex", strlen("duplex")))
			nt_devmode->duplex=atoi(v);

		if (!strncmp(p, "yresolution", strlen("yresolution")))
			nt_devmode->yresolution=atoi(v);

		if (!strncmp(p, "ttoption", strlen("ttoption")))
			nt_devmode->ttoption=atoi(v);

		if (!strncmp(p, "collate", strlen("collate")))
			nt_devmode->collate=atoi(v);

		if (!strncmp(p, "icmmethod", strlen("icmmethod")))
			nt_devmode->icmmethod=atoi(v);

		if (!strncmp(p, "icmintent", strlen("icmintent")))
			nt_devmode->icmintent=atoi(v);

		if (!strncmp(p, "mediatype", strlen("mediatype")))
			nt_devmode->mediatype=atoi(v);

		if (!strncmp(p, "dithertype", strlen("dithertype")))
			nt_devmode->dithertype=atoi(v);
			
		if (!strncmp(p, "private", strlen("private")))
		{
			nt_devmode->private=(uint8 *)malloc(nt_devmode->driverextra*sizeof(uint8));
			strhex_to_str(nt_devmode->private, 2*nt_devmode->driverextra, v);
		}
		
		/* the specific */
		
		if (!strncmp(p, "specific", strlen("specific")))
		{
			param=(NT_PRINTER_PARAM *)malloc(sizeof(NT_PRINTER_PARAM));
			ZERO_STRUCTP(param);
			
			dissect_and_fill_a_param(param, v);
			
			dump_a_param(param);
			
			add_a_specific_param(info, param);
		}
		
	}
	fclose(f);
	free(line);
	
	*info_ptr=info;
	
	return (0);	
}

/****************************************************************************
debugging function, dump at level 6 the struct in the logs
****************************************************************************/
static uint32 dump_a_printer(NT_PRINTER_INFO_LEVEL printer, uint32 level)
{
	uint32 success;
	NT_PRINTER_INFO_LEVEL_2	*info2;
	
	DEBUG(6,("Dumping printer at level [%d]\n", level));
	
	switch (level)
	{
		case 2: 
		{
			if (printer.info_2 == NULL)
			{
				DEBUGADD(3,("NULL pointer, memory not alloced ?\n"));
				success=5;
			}
			else
			{
				info2=printer.info_2;
			
				DEBUGADD(6,("attributes:[%d]\n",       info2->attributes));
				DEBUGADD(6,("priority:[%d]\n",         info2->priority));
				DEBUGADD(6,("default_priority:[%d]\n", info2->default_priority));
				DEBUGADD(6,("starttime:[%d]\n",        info2->starttime));
				DEBUGADD(6,("untiltime:[%d]\n",        info2->untiltime));
				DEBUGADD(6,("status:[%d]\n",           info2->status));
				DEBUGADD(6,("cjobs:[%d]\n",            info2->cjobs));
				DEBUGADD(6,("averageppm:[%d]\n",       info2->averageppm));

				DEBUGADD(6,("servername:[%s]\n",       info2->servername));
				DEBUGADD(6,("printername:[%s]\n",      info2->printername));
				DEBUGADD(6,("sharename:[%s]\n",        info2->sharename));
				DEBUGADD(6,("portname:[%s]\n",         info2->portname));
				DEBUGADD(6,("drivername:[%s]\n",       info2->drivername));
				DEBUGADD(6,("comment:[%s]\n",          info2->comment));
				DEBUGADD(6,("location:[%s]\n",         info2->location));
				DEBUGADD(6,("sepfile:[%s]\n",          info2->sepfile));
				DEBUGADD(6,("printprocessor:[%s]\n",   info2->printprocessor));
				DEBUGADD(6,("datatype:[%s]\n",         info2->datatype));
				DEBUGADD(6,("parameters:[%s]\n",       info2->parameters));
				success=0;
			}
			break;
		}
		default:
			DEBUGADD(1,("Level not implemented\n"));
			success=1;
			break;
	}
	
	return (success);
}

/*
 * The function below are the high level ones.
 * only those ones must be called from the spoolss code.
 * JFM.
 */


/****************************************************************************
****************************************************************************/
uint32 add_a_printer(NT_PRINTER_INFO_LEVEL printer, uint32 level)
{
	uint32 success;
	
	dump_a_printer(printer, level);	
	
	switch (level)
	{
		case 2: 
		{
			success=add_a_printer_2(printer.info_2);
			break;
		}
		default:
			success=1;
			break;
	}
	
	return (success);
}

/****************************************************************************
****************************************************************************/
uint32 get_a_printer(NT_PRINTER_INFO_LEVEL *printer, uint32 level, fstring sharename)
{
	uint32 success;
	
	switch (level)
	{
		case 2: 
		{
			printer->info_2=NULL;
			success=get_a_printer_2(&(printer->info_2), sharename);
			break;
		}
		default:
			success=1;
			break;
	}
	
	dump_a_printer(*printer, level);
	return (success);
}

/****************************************************************************
****************************************************************************/
uint32 free_a_printer(NT_PRINTER_INFO_LEVEL printer, uint32 level)
{
	uint32 success;
	DEBUG(4,("freeing a printer at level [%d]\n", level));
	
	switch (level)
	{
		case 2: 
		{
			if (printer.info_2 != NULL)
			{
				if ((printer.info_2)->devmode != NULL)
				{
					DEBUG(6,("deleting DEVMODE\n"));
					if ((printer.info_2)->devmode->private !=NULL )
						free((printer.info_2)->devmode->private);
					free((printer.info_2)->devmode);
				}
				
				if ((printer.info_2)->specific != NULL)
				{
					NT_PRINTER_PARAM *param;
					NT_PRINTER_PARAM *next_param;
	
					param=(printer.info_2)->specific;
					
					while (	param != NULL)
					{
						next_param=param->next;
						DEBUG(6,("deleting param [%s]\n", param->value));
						free(param->data);
						free(param);
						param=next_param;
					}
				}	
				
				free(printer.info_2);
				success=0;
			}
			else
			{
				success=4;
			}
			break;
		}
		default:
			success=1;
			break;
	}
	return (success);
}

/****************************************************************************
****************************************************************************/
uint32 add_a_printer_driver(NT_PRINTER_DRIVER_INFO_LEVEL driver, uint32 level)
{
	uint32 success;
	DEBUG(4,("adding a printer at level [%d]\n", level));
	dump_a_printer_driver(driver, level);
	
	switch (level)
	{
		case 3: 
		{
			success=add_a_printer_driver_3(driver.info_3);
			break;
		}
		default:
			success=1;
			break;
	}
	
	return (success);
}
/****************************************************************************
****************************************************************************/
uint32 get_a_printer_driver(NT_PRINTER_DRIVER_INFO_LEVEL *driver, uint32 level, 
                            fstring printername, fstring architecture)
{
	uint32 success;
	
	switch (level)
	{
		case 3: 
		{
			success=get_a_printer_driver_3(&(driver->info_3), 
			                               printername,
						       architecture);
			break;
		}
		default:
			success=1;
			break;
	}
	
	dump_a_printer_driver(*driver, level);
	return (success);
}

/****************************************************************************
****************************************************************************/
uint32 free_a_printer_driver(NT_PRINTER_DRIVER_INFO_LEVEL driver, uint32 level)
{
	uint32 success;
	NT_PRINTER_DRIVER_INFO_LEVEL_3 *info3;
	char **dependentfiles;
	
	switch (level)
	{
		case 3: 
		{
			if (driver.info_3 != NULL)
			{
				info3=driver.info_3;
				dependentfiles=info3->dependentfiles;
	
				while ( **dependentfiles != '\0' )
				{
					free (*dependentfiles);
					dependentfiles++;
				}
				
				/* the last one (1 char !) */
				free (*dependentfiles);
				
				dependentfiles=info3->dependentfiles;
				free (dependentfiles);
				
				free(info3);
				success=0;
			}
			else
			{
				success=4;
			}
			break;
		}
		default:
			success=1;
			break;
	}
	return (success);
}

/****************************************************************************
****************************************************************************/
BOOL get_specific_param_by_index(NT_PRINTER_INFO_LEVEL printer, uint32 level, uint32 param_index,
                                 fstring value, uint8 **data, uint32 *type, uint32 *len)
{
	/* right now that's enough ! */	
	NT_PRINTER_PARAM *param;
	int i=0;
	
	param=printer.info_2->specific;
	
	while (param != NULL && i < param_index)
	{
		param=param->next;
		i++;
	}
	
	if (param != NULL)
	{
		/* exited because it exist */
		*type=param->type;		
		StrnCpy(value, param->value, sizeof(value)-1);
		*data=(uint8 *)malloc(param->data_len*sizeof(uint8));
		memcpy(*data, param->data, param->data_len);
		*len=param->data_len;
		return (True);
	}
	return (False);
}

/****************************************************************************
****************************************************************************/
BOOL get_specific_param(NT_PRINTER_INFO_LEVEL printer, uint32 level, 
                        fstring value, uint8 **data, uint32 *type, uint32 *len)
{
	/* right now that's enough ! */	
	NT_PRINTER_PARAM *param;
	
	DEBUG(5, ("get_specific_param\n"));
	
	param=printer.info_2->specific;
		
	while (param != NULL)
	{
		if ( !strcmp(value, param->value) 
		    && strlen(value)==strlen(param->value))
			break;
			
		param=param->next;
	}
	
	DEBUG(6, ("found one param\n"));
	if (param != NULL)
	{
		/* exited because it exist */
		*type=param->type;	
		
		*data=(uint8 *)malloc(param->data_len*sizeof(uint8));
		memcpy(*data, param->data, param->data_len);
		*len=param->data_len;

		DEBUG(6, ("exit of get_specific_param:true\n"));
		return (True);
	}
	DEBUG(6, ("exit of get_specific_param:false\n"));
	return (False);
}

/****************************************************************************
****************************************************************************/
void init_devicemode(NT_DEVICEMODE *nt_devmode)
{
/*
 * should I init this ones ???
	nt_devmode->devicename
*/
	StrCpy(nt_devmode->formname, "A4");

	nt_devmode->specversion      = 0x0401;
	nt_devmode->driverversion    = 0x0400;
	nt_devmode->size             = 0x00DC;
	nt_devmode->driverextra      = 0x0000;
	nt_devmode->fields           = FORMNAME | TTOPTION | PRINTQUALITY | 
				       DEFAULTSOURCE | COPIES | SCALE | 
				       PAPERSIZE | ORIENTATION;
	nt_devmode->orientation      = 1;
	nt_devmode->papersize        = PAPER_A4;
	nt_devmode->paperlength      = 0;
	nt_devmode->paperwidth       = 0;
	nt_devmode->scale            = 0x64;
	nt_devmode->copies           = 01;
	nt_devmode->defaultsource    = BIN_FORMSOURCE;
	nt_devmode->printquality     = 0x0258;
	nt_devmode->color            = COLOR_MONOCHROME;
	nt_devmode->duplex           = DUP_SIMPLEX;
	nt_devmode->yresolution      = 0;
	nt_devmode->ttoption         = TT_SUBDEV;
	nt_devmode->collate          = COLLATE_FALSE;
	nt_devmode->icmmethod        = 0;
	nt_devmode->icmintent        = 0;
	nt_devmode->mediatype        = 0;
	nt_devmode->dithertype       = 0;

	/* non utilisés par un driver d'imprimante */
	nt_devmode->logpixels        = 0;
	nt_devmode->bitsperpel       = 0;
	nt_devmode->pelswidth        = 0;
	nt_devmode->pelsheight       = 0;
	nt_devmode->displayflags     = 0;
	nt_devmode->displayfrequency = 0;
	nt_devmode->reserved1        = 0;
	nt_devmode->reserved2        = 0;
	nt_devmode->panningwidth     = 0;
	nt_devmode->panningheight    = 0;
	
	nt_devmode->private=NULL;
}


/* error code:
	0: everything OK
	1: level not implemented
	2: file doesn't exist
	3: can't allocate memory
	4: can't free memory
	5: non existant struct
*/

/*
	A printer and a printer driver are 2 different things.
	NT manages them separatelly, Samba does the same.
	Why ? Simply because it's easier and it makes sense !
	
	Now explanation: You have 3 printers behind your samba server,
	2 of them are the same make and model (laser A and B). But laser B 
	has an 3000 sheet feeder and laser A doesn't such an option.
	Your third printer is an old dot-matrix model for the accounting :-).
	
	If the /usr/local/samba/lib directory (default dir), you will have
	5 files to describe all of this.
	
	3 files for the printers (1 by printer):
		NTprinter_laser A
		NTprinter_laser B
		NTprinter_accounting
	2 files for the drivers (1 for the laser and 1 for the dot matrix)
		NTdriver_printer model X
		NTdriver_printer model Y

jfm: I should use this comment for the text file to explain 
	same thing for the forms BTW.
	Je devrais mettre mes commentaires en francais, ca serait mieux :-)

*/


