/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   html smb.conf editing - prototype only
   Copyright (C) Andrew Tridgell 1997-1998
   
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

#ifdef SYSLOG
#undef SYSLOG
#endif

#include "includes.h"
#include "smb.h"

#define SDEFAULTS "Service defaults"
#define SGLOBAL "Global Parameters"
#define GLOBALS_SNUM -2
#define DEFAULTS_SNUM -1

static pstring servicesf = CONFIGFILE;


/* start the page with standard stuff */
static void print_header(void)
{
	printf("Content-type: text/html\r\n\r\n");
	printf("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 3.2//EN\">\n");
	printf("<HTML>\n<HEAD>\n<TITLE>smb.conf</TITLE>\n</HEAD>\n<BODY>\n\n");
}


/* finish off the page */
static void print_footer(void)
{
	printf("\n</BODY>\n</HTML>\n");
}

/* display a servce, ready for editing */
static void show_service(int snum, int allparameters)
{
	int i = 0;
	pstring label, value;
	char *sname;

	if (snum == GLOBALS_SNUM) 
		sname = SGLOBAL;
	else if (snum == DEFAULTS_SNUM)
		sname = SDEFAULTS;
	else sname = lp_servicename(snum);

	printf("\n<p><table border=0>\n<tr>\n<td></td><td>\n\n");
	printf("<form method=POST>\n");
	printf("<H3>%s</H3>\n", sname);
	printf("<input type=hidden name=service value=\"%s\">\n", sname);
	printf("<input type=submit name=request value=Change>\n");
	printf("<input type=submit name=request value=Rename>\n");
	printf("<input type=submit name=request value=Copy>\n");
	printf("<input type=submit name=request value=Remove>\n");
	printf("<br><input name=newvalue><br>\n");
	printf("<select name=parameter size=5>\n");
	
	while (lp_next_parameter(snum, &i, label, value, allparameters)) {
		printf("<option value=\"%s\">%s = %s\n", 
		       label, label, value);
	}

	printf("</select>\n");
	printf("</form>\n</td>\n</tr>\n</table>\n");

	printf("<p>\n");
}


/* loop over all services, displaying them one after the other */
static void show_services(void)
{
	int i;
	int n;
	int allparameters = cgi_boolean("allparameters", 0);

	printf("<FORM METHOD=POST>\n");
	printf("<p>Show all parameters?\n");
	printf("<INPUT NAME=allparameters TYPE=checkbox VALUE=1 %s>\n",
	       allparameters?"CHECKED":"");

	printf("<INPUT TYPE=submit NAME=reload VALUE=Reload>\n");
	
	printf("</FORM>\n");
	
	n = lp_numservices();

	show_service(GLOBALS_SNUM, allparameters);
	show_service(DEFAULTS_SNUM, allparameters);
	
	for (i=0;i<n;i++)
		if (VALID_SNUM(i))
			show_service(i, allparameters);
}


/* load the smb.conf file into loadparm. */
static int load_config(void)
{
	setuid(0);
	if (!lp_load(servicesf,False)) {
		printf("<b>Can't load %s - using defaults</b><p>\n", 
		       servicesf);
	}
	return 1;
}


static int save_reload(void)
{
	FILE *f;

	f = fopen(servicesf,"w");
	if (!f) {
		printf("failed to open %s for writing\n", servicesf);
		return 0;
	}

	fprintf(f, "# Samba config file created using wsmbconf\n");

	lp_dump(f);

	fclose(f);

	lp_killunused(NULL);

	if (!lp_load(servicesf,False)) {
                printf("Can't reload %s\n", servicesf);
                return 0;
        }

	return 1;
}

static void process_requests(void)
{
	char *req = cgi_variable("request");
	char *newvalue = cgi_variable("newvalue");
	char *parameter = cgi_variable("parameter");
	char *service = cgi_variable("service");
	int snum=0;

	if (!req) return;

	if (service) {
		/* work out what service it is */
		if (strcmp(service,SGLOBAL) == 0) {
			snum = GLOBALS_SNUM;
		} else if (strcmp(service,SDEFAULTS) == 0) {
			snum = DEFAULTS_SNUM;
		} else {
			snum = lp_servicenumber(service);
			if (snum < 0) return;
		}
	}

	if (!newvalue)
		newvalue = "";

	if (strcmp(req,"Change") == 0) {
		/* change the value of a parameter */
		if (!parameter || !service) return;

		lp_do_parameter(snum, parameter, newvalue); 
	} else if (strcmp(req,"Rename") == 0) {
		/* rename a service */
		if (!newvalue || !service) return;

		lp_rename_service(snum, newvalue);
	} else if (strcmp(req,"Remove") == 0) {
		/* remove a service */
		if (!service) return;

		lp_remove_service(snum);
	} else if (strcmp(req,"Copy") == 0) {
		/* copy a service */
		if (!service || !newvalue) return;

		lp_copy_service(snum, newvalue);
	}

	save_reload();
}


int main(int argc, char *argv[])
{
	extern char *optarg;
	extern int optind;
	extern FILE *dbf;
	int opt;

	dbf = fopen("/dev/null", "w");

	if (!dbf) dbf = stderr;

	cgi_setup(WEB_ROOT);


	while ((opt = getopt(argc, argv,"s:")) != EOF) {
		switch (opt) {
		case 's':
			pstrcpy(servicesf,optarg);
			break;	  
		}
	}


	print_header();

	charset_initialise();

	if (load_config()) {
		cgi_load_variables(NULL);
		process_requests();
		show_services();
	}
	print_footer();
	return 0;
}
