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

#define GLOBALS_SNUM -2
#define DEFAULTS_SNUM -1

static pstring servicesf = CONFIGFILE;


/* start the page with standard stuff */
static void print_header(void)
{
	printf("Content-type: text/html\r\n\r\n");
	printf("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 3.2//EN\">\n");
	printf("<HTML>\n<HEAD>\n<TITLE>Samba Web Administration Tool</TITLE>\n</HEAD>\n<BODY>\n\n");
}


/* finish off the page */
static void print_footer(void)
{
	printf("\n</BODY>\n</HTML>\n");
}

/* include a lump of html in a page */
static void include_html(char *fname)
{
	FILE *f = fopen(fname,"r");
	char buf[1024];
	int ret;

	if (!f) {
		printf("ERROR: Can't open %s\n", fname);
		return;
	}

	while (!feof(f)) {
		ret = fread(buf, 1, sizeof(buf), f);
		if (ret <= 0) break;
		fwrite(buf, 1, ret, stdout);
	}

	fclose(f);
}


/* display one editable parameter */
static void show_parameter(int snum, struct parm_struct *parm)
{
	int i;
	void *ptr = parm->ptr;

	if (parm->class == P_LOCAL) {
		ptr = lp_local_ptr(snum, ptr);
	}

	printf("<tr><td><A HREF=\"help/parameters.html#%s\">?</A> %s</td><td>", 
	       parm->label, parm->label);

	switch (parm->type) {
	case P_CHAR:
		printf("<input type=text size=2 name=\"parm_%s\" value=\"%c\">",
		       parm->label, *(char *)ptr);
		break;

	case P_STRING:
	case P_USTRING:
		printf("<input type=text size=40 name=\"parm_%s\" value=\"%s\">",
		       parm->label, *(char **)ptr);
		break;

	case P_GSTRING:
	case P_UGSTRING:
		printf("<input type=text size=40 name=\"parm_%s\" value=\"%s\">",
		       parm->label, (char *)ptr);
		break;

	case P_BOOL:
		printf("<input type=radio name=\"parm_%s\" value=Yes %s>yes&nbsp;&nbsp;", parm->label, (*(BOOL *)ptr)?"CHECKED":"");
		printf("<input type=radio name=\"parm_%s\" value=No %s>no", parm->label, (*(BOOL *)ptr)?"":"CHECKED");
		break;

	case P_BOOLREV:
		printf("<input type=radio name=\"parm_%s\" value=Yes %s>yes&nbsp;&nbsp;", parm->label, (*(BOOL *)ptr)?"":"CHECKED");
		printf("<input type=radio name=\"parm_%s\" value=No %s>no", parm->label, (*(BOOL *)ptr)?"CHECKED":"");
		break;

	case P_INTEGER:
		printf("<input type=text size=8 name=\"parm_%s\" value=%d>", parm->label, *(int *)ptr);
		break;

	case P_OCTAL:
		printf("<input type=text size=8 name=\"parm_%s\" value=0%o>", parm->label, *(int *)ptr);
		break;

	case P_ENUM:
		for (i=0;parm->enum_list[i].name;i++)
			printf("<input type=radio name=\"parm_%s\" value=%s %s>%s&nbsp;&nbsp;", 
			       parm->label, parm->enum_list[i].name, 
			       (*(int *)ptr)==parm->enum_list[i].value?"CHECKED":"", 
			       parm->enum_list[i].name);
		break;
			
	}
	printf("</td></tr>\n");
}

/* display a set of parameters for a service */
static void show_parameters(int snum, int allparameters, int advanced, int printers)
{
	int i = 0;
	struct parm_struct *parm;

	printf("<table>\n");

	while ((parm = lp_next_parameter(snum, &i, allparameters))) {
		if (parm->flags & FLAG_HIDE) continue;
		if (!advanced) {
			if (!printers && !(parm->flags & FLAG_BASIC)) continue;
			if (printers && !(parm->flags & FLAG_PRINT)) continue;
		}
		show_parameter(snum, parm);
	}
	printf("</table>\n");
}


static int save_reload(void)
{
	FILE *f;

	f = fopen(servicesf,"w");
	if (!f) {
		printf("failed to open %s for writing\n", servicesf);
		return 0;
	}

	fprintf(f, "# Samba config file created using SWAT\n");

	lp_dump(f);

	fclose(f);

	lp_killunused(NULL);

	if (!lp_load(servicesf,False)) {
                printf("Can't reload %s\n", servicesf);
                return 0;
        }

	return 1;
}



/* commit a set of parameters for a service */
static void commit_parameters(int snum)
{
	int i = 0;
	struct parm_struct *parm;
	pstring label;
	char *v;

	while ((parm = lp_next_parameter(snum, &i, 1))) {
		sprintf(label, "parm_%s", parm->label);
		if ((v = cgi_variable(label))) {
			lp_do_parameter(snum, parm->label, v); 
		}
	}

	save_reload();
}


/* load the smb.conf file into loadparm. */
static void load_config(void)
{
	if (!lp_load(servicesf,False)) {
		printf("<b>Can't load %s - using defaults</b><p>\n", 
		       servicesf);
	}
}

/* spit out the html for a link with an image */
static void image_link(char *name,char *hlink, char *src, int width, int height)
{
	printf("<A HREF=\"%s\"><img width=%d height=%d src=\"%s\" alt=\"%s\"></A>\n", hlink, width, height, src, name);
}

/* display the main navigation controls at the top of each page along
   with a title */
static void show_main_buttons(void)
{
	printf("<H2 align=center>Samba Web Administration Tool</H2>\n");

	image_link("Globals", "globals", "images/globals.gif", 50, 50);
	image_link("Shares", "shares", "images/shares.gif", 50, 50);
	image_link("Printers", "printers", "images/printers.gif", 50, 50);

	printf("<HR>\n");
}

/* display a welcome page  */
static void welcome_page(void)
{
	include_html("help/welcome.html");
}


/* display a globals editing page  */
static void globals_page(void)
{
	int advanced = 0;

	printf("<H2>Global Variables</H2>\n");

	if (cgi_variable("Advanced") && !cgi_variable("Basic"))
		advanced = 1;

	if (cgi_variable("Commit")) {
		commit_parameters(GLOBALS_SNUM);
	}

	printf("<FORM method=post>\n");

	printf("<input type=submit name=\"Commit\" value=\"Commit Changes\">\n");
	if (advanced == 0) {
		printf("<input type=submit name=\"Advanced\" value=\"Advanced View\">\n");
	} else {
		printf("<input type=submit name=\"Basic\" value=\"Basic View\">\n");
	}
	printf("<p>\n");
	
	show_parameters(GLOBALS_SNUM, 1, advanced, 0);

	if (advanced) {
		printf("<input type=hidden name=\"Advanced\" value=1>\n");
	}

	printf("</form>\n");
}

/* display a shares editing page  */
static void shares_page(void)
{
	char *share = cgi_variable("share");
	char *s;
	int snum=-1;
	int i;
	int advanced = 0;

	if (share)
		snum = lp_servicenumber(share);

	printf("<H2>Share Parameters</H2>\n");

	if (cgi_variable("Advanced") && !cgi_variable("Basic"))
		advanced = 1;

	if (cgi_variable("Commit") && snum >= 0) {
		commit_parameters(snum);
	}

	if (cgi_variable("Delete") && snum >= 0) {
		lp_remove_service(snum);
		save_reload();
		share = NULL;
		snum = -1;
	}

	if (cgi_variable("createshare") && (share=cgi_variable("newshare"))) {
		lp_copy_service(DEFAULTS_SNUM, share);
		save_reload();
		snum = lp_servicenumber(share);
	}

	printf("<FORM method=post>\n");

	printf("<table>\n");
	printf("<tr><td><input type=submit name=selectshare value=\"Choose Share\"></td>\n");
	printf("<td><select name=share>\n");
	if (snum < 0)
		printf("<option value=\" \"> \n");
	for (i=0;i<lp_numservices();i++) {
		s = lp_servicename(i);
		if (s && (*s) && strcmp(s,"IPC$") && !lp_print_ok(i)) {
			printf("<option %s value=\"%s\">%s\n", 
			       (share && strcmp(share,s)==0)?"SELECTED":"",
			       s, s);
		}
	}
	printf("</select></td></tr><p>");

	printf("<tr><td><input type=submit name=createshare value=\"Create Share\"></td>\n");
	printf("<td><input type=text size=30 name=newshare></td></tr>\n");
	printf("</table>");


	if (snum >= 0) {
		printf("<input type=submit name=\"Commit\" value=\"Commit Changes\">\n");
		printf("<input type=submit name=\"Delete\" value=\"Delete Share\">\n");
		if (advanced == 0) {
			printf("<input type=submit name=\"Advanced\" value=\"Advanced View\">\n");
		} else {
			printf("<input type=submit name=\"Basic\" value=\"Basic View\">\n");
		}
		printf("<p>\n");
	}

	if (snum >= 0) {
		show_parameters(snum, 1, advanced, 0);
	}

	if (advanced) {
		printf("<input type=hidden name=\"Advanced\" value=1>\n");
	}

	printf("</FORM>\n");
}


/* display a printers editing page  */
static void printers_page(void)
{
	char *share = cgi_variable("share");
	char *s;
	int snum=-1;
	int i;
	int advanced = 0;

	if (share)
		snum = lp_servicenumber(share);

	printf("<H2>Printer Parameters</H2>\n");

	if (cgi_variable("Advanced") && !cgi_variable("Basic"))
		advanced = 1;

	if (cgi_variable("Commit") && snum >= 0) {
		commit_parameters(snum);
	}

	if (cgi_variable("Delete") && snum >= 0) {
		lp_remove_service(snum);
		save_reload();
		share = NULL;
		snum = -1;
	}

	if (cgi_variable("createshare") && (share=cgi_variable("newshare"))) {
		lp_copy_service(DEFAULTS_SNUM, share);
		snum = lp_servicenumber(share);
		lp_do_parameter(snum, "print ok", "Yes");
		save_reload();
		snum = lp_servicenumber(share);
	}

	printf("<FORM method=post>\n");

	printf("<table>\n");
	printf("<tr><td><input type=submit name=selectshare value=\"Choose Printer\"></td>\n");
	printf("<td><select name=share>\n");
	if (snum < 0 || !lp_print_ok(snum))
		printf("<option value=\" \"> \n");
	for (i=0;i<lp_numservices();i++) {
		s = lp_servicename(i);
		if (s && (*s) && strcmp(s,"IPC$") && lp_print_ok(i)) {
			printf("<option %s value=\"%s\">%s\n", 
			       (share && strcmp(share,s)==0)?"SELECTED":"",
			       s, s);
		}
	}
	printf("</select></td></tr><p>");

	printf("<tr><td><input type=submit name=createshare value=\"Create Printer\"></td>\n");
	printf("<td><input type=text size=30 name=newshare></td></tr>\n");
	printf("</table>");


	if (snum >= 0) {
		printf("<input type=submit name=\"Commit\" value=\"Commit Changes\">\n");
		printf("<input type=submit name=\"Delete\" value=\"Delete Printer\">\n");
		if (advanced == 0) {
			printf("<input type=submit name=\"Advanced\" value=\"Advanced View\">\n");
		} else {
			printf("<input type=submit name=\"Basic\" value=\"Basic View\">\n");
		}
		printf("<p>\n");
	}

	if (snum >= 0) {
		show_parameters(snum, 1, advanced, 1);
	}

	if (advanced) {
		printf("<input type=hidden name=\"Advanced\" value=1>\n");
	}

	printf("</FORM>\n");
}


int main(int argc, char *argv[])
{
	extern char *optarg;
	extern int optind;
	extern FILE *dbf;
	int opt;
	char *page;
	int auth_required = 1;

	/* just in case it goes wild ... */
	alarm(300);

	dbf = fopen("/dev/null", "w");

	if (!dbf) dbf = stderr;

	while ((opt = getopt(argc, argv,"s:a")) != EOF) {
		switch (opt) {
		case 's':
			pstrcpy(servicesf,optarg);
			break;	  
		case 'a':
			auth_required = 0;
			break;	  
		}
	}

	cgi_setup(SWATDIR, auth_required);

	print_header();

	charset_initialise();

	/* if this binary is setuid then run completely as root */
	setuid(0);

	load_config();

	cgi_load_variables(NULL);

	show_main_buttons();

	page = cgi_baseurl();

	if (strcmp(page, "globals")==0) {
		globals_page();
	} else if (strcmp(page,"shares")==0) {
		shares_page();
	} else if (strcmp(page,"printers")==0) {
		printers_page();
	} else {
		welcome_page();
	}
	
	print_footer();
	return 0;
}


