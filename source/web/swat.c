/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Samba Web Administration Tool
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

#define GLOBALS_SNUM -1

static pstring servicesf = CONFIGFILE;
static BOOL demo_mode = False;

/*
 * Password Management Globals
 */
#define USER "username"
#define OLD_PSWD "old_passwd"
#define NEW_PSWD "new_passwd"
#define NEW2_PSWD "new2_passwd"
#define CHG_PASSWD_FLAG "chg_passwd_flag"
#define ADD_USER_FLAG "add_user_flag"
#define DISABLE_USER_FLAG "disable_user_flag"
#define ENABLE_USER_FLAG "enable_user_flag"

/* we need these because we link to locking*.o */
 void become_root(BOOL save_dir) {}
 void unbecome_root(BOOL restore_dir) {}

/****************************************************************************
****************************************************************************/
static int enum_index(int value, struct enum_list *enumlist)
{
int i;
	for (i=0;enumlist[i].name;i++)
		if (value == enumlist[i].value) break;
	return(i);
}

static char *fix_backslash(char *str)
{
static char newstring[1024];
char *p = newstring;

        while (*str) {
                if (*str == '\\') {*p++ = '\\';*p++ = '\\';}
                else *p++ = *str;
                ++str;
        }
	*p = '\0';
	return newstring;
}

static char *stripspace(char *str)
{
static char newstring[1024];
char *p = newstring;

        while (*str) {
                if (*str != ' ') *p++ = *str;
                ++str;
        }
	*p = '\0';
	return newstring;
}

static char *make_parm_name(char *label)
{
	static char parmname[1024];
	char *p = parmname;

	while (*label) {
		if (*label == ' ') *p++ = '_';
		else *p++ = *label;
		++label;
	}
	*p = '\0';
	return parmname;
}

/****************************************************************************
  include a lump of html in a page 
****************************************************************************/
static int include_html(char *fname)
{
	FILE *f = fopen(fname,"r");
	char buf[1024];
	int ret;

	if (!f) {
		printf("ERROR: Can't open %s\n", fname);
		return 0;
	}

	while (!feof(f)) {
		ret = fread(buf, 1, sizeof(buf), f);
		if (ret <= 0) break;
		fwrite(buf, 1, ret, stdout);
	}

	fclose(f);
	return 1;
}

/****************************************************************************
  start the page with standard stuff 
****************************************************************************/
static void print_header(void)
{
	if (!cgi_waspost()) {
		printf("Expires: 0\r\n");
	}
	printf("Content-type: text/html\r\n\r\n");

	if (!include_html("include/header.html")) {
		printf("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 3.2//EN\">\n");
		printf("<HTML>\n<HEAD>\n<TITLE>Samba Web Administration Tool</TITLE>\n</HEAD>\n<BODY background=\"/swat/images/background.jpg\">\n\n");
	}
}

/****************************************************************************
 finish off the page 
****************************************************************************/
static void print_footer(void)
{
	if (!include_html("include/footer.html")) {
		printf("\n</BODY>\n</HTML>\n");
	}
}

/****************************************************************************
  display one editable parameter in a form 
****************************************************************************/
static void show_parameter(int snum, struct parm_struct *parm)
{
	int i;
	void *ptr = parm->ptr;

	if (parm->class == P_LOCAL && snum >= 0) {
		ptr = lp_local_ptr(snum, ptr);
	}

	printf("<tr><td><A HREF=\"/swat/help/smb.conf.5.html#%s\">?</A> %s</td><td>", 
	       stripspace(parm->label), parm->label);

	switch (parm->type) {
	case P_CHAR:
		printf("<input type=text size=2 name=\"parm_%s\" value=\"%c\">",
		       make_parm_name(parm->label), *(char *)ptr);
		printf("<input type=button value=\"Set Default\" onClick=\"swatform.parm_%s.value=\'%c\'\">",
			make_parm_name(parm->label),(char)(parm->def.cvalue));
		break;

	case P_STRING:
	case P_USTRING:
		printf("<input type=text size=40 name=\"parm_%s\" value=\"%s\">",
		       make_parm_name(parm->label), *(char **)ptr);
		printf("<input type=button value=\"Set Default\" onClick=\"swatform.parm_%s.value=\'%s\'\">",
			make_parm_name(parm->label),fix_backslash((char *)(parm->def.svalue)));
		break;

	case P_GSTRING:
	case P_UGSTRING:
		printf("<input type=text size=40 name=\"parm_%s\" value=\"%s\">",
		       make_parm_name(parm->label), (char *)ptr);
		printf("<input type=button value=\"Set Default\" onClick=\"swatform.parm_%s.value=\'%s\'\">",
			make_parm_name(parm->label),fix_backslash((char *)(parm->def.svalue)));
		break;

	case P_BOOL:
		printf("<select name=\"parm_%s\">",make_parm_name(parm->label)); 
		printf("<option %s>Yes", (*(BOOL *)ptr)?"selected":"");
		printf("<option %s>No", (*(BOOL *)ptr)?"":"selected");
		printf("</select>");
		printf("<input type=button value=\"Set Default\" onClick=\"swatform.parm_%s.selectedIndex=\'%d\'\">",
			make_parm_name(parm->label),(BOOL)(parm->def.bvalue)?0:1);
		break;

	case P_BOOLREV:
		printf("<select name=\"parm_%s\">",make_parm_name(parm->label)); 
		printf("<option %s>Yes", (*(BOOL *)ptr)?"":"selected");
		printf("<option %s>No", (*(BOOL *)ptr)?"selected":"");
		printf("</select>");
		printf("<input type=button value=\"Set Default\" onClick=\"swatform.parm_%s.selectedIndex=\'%d\'\">",
			make_parm_name(parm->label),(BOOL)(parm->def.bvalue)?1:0);
		break;

	case P_INTEGER:
		printf("<input type=text size=8 name=\"parm_%s\" value=%d>", make_parm_name(parm->label), *(int *)ptr);
		printf("<input type=button value=\"Set Default\" onClick=\"swatform.parm_%s.value=\'%d\'\">",
			make_parm_name(parm->label),(int)(parm->def.ivalue));
		break;

	case P_OCTAL:
		printf("<input type=text size=8 name=\"parm_%s\" value=0%o>", make_parm_name(parm->label), *(int *)ptr);
		printf("<input type=button value=\"Set Default\" onClick=\"swatform.parm_%s.value=\'0%o\'\">",
			make_parm_name(parm->label),(int)(parm->def.ivalue));
		break;

	case P_ENUM:
		printf("<select name=\"parm_%s\">",make_parm_name(parm->label)); 
		for (i=0;parm->enum_list[i].name;i++)
			printf("<option %s>%s",(*(int *)ptr)==parm->enum_list[i].value?"selected":"",parm->enum_list[i].name);
		printf("</select>");
		printf("<input type=button value=\"Set Default\" onClick=\"swatform.parm_%s.selectedIndex=\'%d\'\">",
			make_parm_name(parm->label),enum_index((int)(parm->def.ivalue),parm->enum_list));
		break;
	case P_SEP:
		break;
	}
	printf("</td></tr>\n");
}

/****************************************************************************
  display a set of parameters for a service 
****************************************************************************/
static void show_parameters(int snum, int allparameters, int advanced, int printers)
{
	int i = 0;
	struct parm_struct *parm;
	char *heading = NULL;
	char *last_heading = NULL;

	while ((parm = lp_next_parameter(snum, &i, allparameters))) {
		if (snum < 0 && parm->class == P_LOCAL && !(parm->flags & FLAG_GLOBAL))
			continue;
		if (parm->class == P_SEPARATOR) {
			heading = parm->label;
			continue;
		}
		if (parm->flags & FLAG_HIDE) continue;
		if (!advanced) {
			if (!printers && !(parm->flags & FLAG_BASIC)) {
				void *ptr = parm->ptr;

				switch (parm->type) {
				case P_CHAR:
					if (*(char *)ptr == (char)(parm->def.cvalue)) continue;
					break;

				case P_STRING:
				case P_USTRING:
					if (!strcmp(*(char **)ptr,(char *)(parm->def.svalue))) continue;
					break;

				case P_GSTRING:
				case P_UGSTRING:
					if (!strcmp((char *)ptr,(char *)(parm->def.svalue))) continue;
					break;

				case P_BOOL:
				case P_BOOLREV:
					if (*(BOOL *)ptr == (BOOL)(parm->def.bvalue)) continue;
					break;

				case P_INTEGER:
				case P_OCTAL:
					if (*(int *)ptr == (int)(parm->def.ivalue)) continue;
					break;


				case P_ENUM:
					if (*(int *)ptr == (int)(parm->def.ivalue)) continue;
					break;
				case P_SEP:
					continue;
				}
			}
			if (printers && !(parm->flags & FLAG_PRINT)) continue;
		}
		if (heading && heading != last_heading) {
			printf("<tr><td></td></tr><tr><td><b><u>%s</u></b></td></tr>\n", heading);
			last_heading = heading;
		}
		show_parameter(snum, parm);
	}
}

/****************************************************************************
  write a config file 
****************************************************************************/
static void write_config(FILE *f, BOOL show_defaults)
{
	fprintf(f, "# Samba config file created using SWAT\n");
	fprintf(f, "# from %s (%s)\n", cgi_remote_host(), cgi_remote_addr());
	fprintf(f, "# Date: %s\n\n", timestring());
	
	lp_dump(f, show_defaults);	
}

/****************************************************************************
  save and reoad the smb.conf config file 
****************************************************************************/
static int save_reload(void)
{
	FILE *f;

	f = fopen(servicesf,"w");
	if (!f) {
		printf("failed to open %s for writing\n", servicesf);
		return 0;
	}

	write_config(f, False);
	fclose(f);

	lp_killunused(NULL);

	if (!lp_load(servicesf,False,False,False)) {
                printf("Can't reload %s\n", servicesf);
                return 0;
        }

	return 1;
}

/****************************************************************************
  commit one parameter 
****************************************************************************/
static void commit_parameter(int snum, struct parm_struct *parm, char *v)
{
	int i;
	char *s;

	if (snum < 0 && parm->class == P_LOCAL) {
		/* this handles the case where we are changing a local
		   variable globally. We need to change the parameter in 
		   all shares where it is currently set to the default */
		for (i=0;i<lp_numservices();i++) {
			s = lp_servicename(i);
			if (s && (*s) && lp_is_default(i, parm)) {
				lp_do_parameter(i, parm->label, v);
			}
		}
	}

	lp_do_parameter(snum, parm->label, v);
}

/****************************************************************************
  commit a set of parameters for a service 
****************************************************************************/
static void commit_parameters(int snum)
{
	int i = 0;
	struct parm_struct *parm;
	pstring label;
	char *v;

	while ((parm = lp_next_parameter(snum, &i, 1))) {
		slprintf(label, sizeof(label)-1, "parm_%s", make_parm_name(parm->label));
		if ((v = cgi_variable(label))) {
			if (parm->flags & FLAG_HIDE) continue;
			commit_parameter(snum, parm, v); 
		}
	}
}

/****************************************************************************
  load the smb.conf file into loadparm.
****************************************************************************/
static void load_config(void)
{
	if (!lp_load(servicesf,False,True,False)) {
		printf("<b>Can't load %s - using defaults</b><p>\n", 
		       servicesf);
	}
}

/****************************************************************************
  spit out the html for a link with an image 
****************************************************************************/
static void image_link(char *name,char *hlink, char *src)
{
	printf("<A HREF=\"%s/%s\"><img src=\"/swat/%s\" alt=\"%s\"></A>\n", 
	       cgi_baseurl(), hlink, src, name);
}

/****************************************************************************
  display the main navigation controls at the top of each page along
  with a title 
****************************************************************************/
static void show_main_buttons(void)
{
	image_link("Home", "", "images/home.gif");

	/* Root gets full functionality */
	if (demo_mode || am_root()) {
		image_link("Globals", "globals", "images/globals.gif");
		image_link("Shares", "shares", "images/shares.gif");
		image_link("Printers", "printers", "images/printers.gif");
		image_link("Status", "status", "images/status.gif");
		image_link("View Config", "viewconfig","images/viewconfig.gif");
	}

	/* Everyone gets this functionality */
	image_link("Password Management", "passwd", "images/passwd.gif");

	printf("<HR>\n");
}

/****************************************************************************
  display a welcome page  
****************************************************************************/
static void welcome_page(void)
{
	include_html("help/welcome.html");
}

/****************************************************************************
  display the current smb.conf  
****************************************************************************/
static void viewconfig_page(void)
{
	int full_view=0;

	if (cgi_variable("full_view")) {
		full_view = 1;
	}

	printf("<H2>Current Config</H2>\n");
	printf("<form method=post>\n");

	if (full_view) {
		printf("<input type=submit name=\"normal_view\" value=\"Normal View\">\n");
	} else {
		printf("<input type=submit name=\"full_view\" value=\"Full View\">\n");
	}

	printf("<p><pre>");
	write_config(stdout, full_view);
	printf("</pre>");
	printf("</form>\n");
}

/****************************************************************************
  display a globals editing page  
****************************************************************************/
static void globals_page(void)
{
	int advanced = 0;

	printf("<H2>Global Variables</H2>\n");

	if (cgi_variable("Advanced") && !cgi_variable("Basic"))
		advanced = 1;

	if (cgi_variable("Commit")) {
		commit_parameters(GLOBALS_SNUM);
		save_reload();
	}

	printf("<FORM name=\"swatform\" method=post>\n");

	printf("<input type=submit name=\"Commit\" value=\"Commit Changes\">\n");
	printf("<input type=reset name=\"Reset Values\" value=\"Reset Values\">\n");
	if (advanced == 0) {
		printf("<input type=submit name=\"Advanced\" value=\"Advanced View\">\n");
	} else {
		printf("<input type=submit name=\"Basic\" value=\"Basic View\">\n");
	}
	printf("<p>\n");
	
	printf("<table>\n");
	show_parameters(GLOBALS_SNUM, 1, advanced, 0);
	printf("</table>\n");

	if (advanced) {
		printf("<input type=hidden name=\"Advanced\" value=1>\n");
	}

	printf("</FORM>\n");
}

/****************************************************************************
  display a shares editing page  
****************************************************************************/
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
		save_reload();
	}

	if (cgi_variable("Delete") && snum >= 0) {
		lp_remove_service(snum);
		save_reload();
		share = NULL;
		snum = -1;
	}

	if (cgi_variable("createshare") && (share=cgi_variable("newshare"))) {
		lp_copy_service(GLOBALS_SNUM, share);
		save_reload();
		snum = lp_servicenumber(share);
	}

	printf("<FORM name=\"swatform\" method=post>\n");

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
		printf("<table>\n");
		show_parameters(snum, 1, advanced, 0);
		printf("</table>\n");
	}

	if (advanced) {
		printf("<input type=hidden name=\"Advanced\" value=1>\n");
	}

	printf("</FORM>\n");
}

/*************************************************************
change a password either locally or remotely
*************************************************************/
static BOOL change_password(const char *remote_machine, char *user_name, 
			    char *old_passwd, char *new_passwd, 
			    BOOL add_user, BOOL enable_user, BOOL disable_user)
{
	if (demo_mode) {
		printf("password change in demo mode rejected\n<p>");
		return False;
	}
	
	if (remote_machine != NULL) {
		return remote_password_change(remote_machine, user_name, old_passwd, new_passwd);
	}

	if(!initialize_password_db()) {
		printf("Can't setup password database vectors.\n<p>");
		return False;
	}
	
	return local_password_change(user_name, False, add_user, enable_user, 
				     disable_user, False, new_passwd);
}

/****************************************************************************
  do the stuff required to add or change a password 
****************************************************************************/
static void chg_passwd(void)
{
	BOOL rslt;

	/* Make sure users name has been specified */
	if (strlen(cgi_variable(USER)) == 0) {
		printf("<p> Must specify \"User Name\" \n");
		return;
	}

	/*
	 * smbpasswd doesn't require anything but the users name to disable or enable the user,
	 * so if that's what we're doing, skip the rest of the checks
	 */
	if (!cgi_variable(DISABLE_USER_FLAG) && !cgi_variable(ENABLE_USER_FLAG)) {

		/* If current user is not root, make sure old password has been specified */
		if ((am_root() == False) &&  (strlen( cgi_variable(OLD_PSWD)) <= 0)) {
			printf("<p> Must specify \"Old Password\" \n");
			return;
		}

		/* Make sure new passwords have been specified */
		if ((strlen( cgi_variable(NEW_PSWD)) <= 0) ||
		    (strlen( cgi_variable(NEW2_PSWD)) <= 0)) {
			printf("<p> Must specify \"New, and Re-typed Passwords\" \n");
			return;
		}

		/* Make sure new passwords was typed correctly twice */
		if (strcmp(cgi_variable(NEW_PSWD), cgi_variable(NEW2_PSWD)) != 0) {
			printf("<p> Re-typed password didn't match new password\n");
			return;
		}
	}

	rslt = change_password(am_root() ? NULL : "127.0.0.1",
			       cgi_variable(USER),
			       cgi_variable(OLD_PSWD), cgi_variable(NEW_PSWD),
			       cgi_variable(ADD_USER_FLAG)? True : False,
			       cgi_variable(ENABLE_USER_FLAG)? True : False,
			       cgi_variable(DISABLE_USER_FLAG)? True : False);


	if (rslt == True) {
		printf("<p> The passwd for '%s' has been changed. \n", cgi_variable(USER));
	} else {
		printf("<p> The passwd for '%s' has NOT been changed. \n",cgi_variable(USER));
	}
	
	return;
}

/****************************************************************************
  display a password editing page  
****************************************************************************/
static void passwd_page(void)
{
	char *new_name = get_user_name();

	printf("<H2>Password Manager</H2>\n");

	printf("<FORM name=\"swatform\" method=post>\n");

	printf("<table>\n");

	/* 
	 * After the first time through here be nice. If the user
	 * changed the User box text to another users name, remember it.
	 */
	if (cgi_variable(USER)) {
		new_name = cgi_variable(USER);
	} 

	if (!new_name) new_name = "";

	printf("<p> User Name        : <input type=text size=30 name=%s value=%s> \n", 
	       USER, new_name);
	if (am_root() == False) {
		printf("<p> Old Password: <input type=password size=30 name=%s>\n",OLD_PSWD);
	}
	printf("<p> New Password: <input type=password size=30 name=%s>\n",NEW_PSWD);
	printf("<p> Re-type New Password: <input type=password size=30 name=%s>\n",NEW2_PSWD);

	printf("</select></td></tr><p>");
	printf("<tr><td>");
	printf("<input type=submit name=%s value=\"Change Password\">", CHG_PASSWD_FLAG);
	if (am_root() == True) {
		printf("<input type=submit name=%s value=\"Add New User\">", ADD_USER_FLAG);
		printf("<input type=submit name=%s value=\"Disable User\">", DISABLE_USER_FLAG);
		printf("<input type=submit name=%s value=\"Enable User\">", ENABLE_USER_FLAG);
	}
	printf("</td>\n");

	/*
	 * If we don't have user information then there's nothing to do. It's probably
	 * the first time through this code.
	 */
	if (cgi_variable(USER)) {
		chg_passwd();		
	}

	printf("</table>");

	printf("</FORM>\n");
}

/****************************************************************************
  display a printers editing page  
****************************************************************************/
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
		save_reload();
	}

	if (cgi_variable("Delete") && snum >= 0) {
		lp_remove_service(snum);
		save_reload();
		share = NULL;
		snum = -1;
	}

	if (cgi_variable("createshare") && (share=cgi_variable("newshare"))) {
		lp_copy_service(GLOBALS_SNUM, share);
		snum = lp_servicenumber(share);
		lp_do_parameter(snum, "print ok", "Yes");
		save_reload();
		snum = lp_servicenumber(share);
	}

	printf("<FORM name=\"swatform\" method=post>\n");

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
		printf("<table>\n");
		show_parameters(snum, 1, advanced, 1);
		printf("</table>\n");
	}

	if (advanced) {
		printf("<input type=hidden name=\"Advanced\" value=1>\n");
	}

	printf("</FORM>\n");
}

/****************************************************************************
  MAIN()
****************************************************************************/
 int main(int argc, char *argv[])
{
	extern char *optarg;
	extern int optind;
	extern FILE *dbf;
	int opt;
	char *page;

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
			demo_mode = True;
			break;	  
		}
	}

	cgi_setup(SWATDIR, !demo_mode);

	print_header();
	
	charset_initialise();

	/* if this binary is setuid then run completely as root */
	setuid(0);

	load_config();

	cgi_load_variables(NULL);

	show_main_buttons();

	page = cgi_pathinfo();

	/* Root gets full functionality */
	if (demo_mode || am_root()) {
		if (strcmp(page, "globals")==0) {
			globals_page();
		} else if (strcmp(page,"shares")==0) {
			shares_page();
		} else if (strcmp(page,"printers")==0) {
			printers_page();
		} else if (strcmp(page,"status")==0) {
			status_page();
		} else if (strcmp(page,"viewconfig")==0) {
			viewconfig_page();
		} else if (strcmp(page,"passwd")==0) {
			passwd_page();
		} else {
			welcome_page();
		}
	} else {
		/* Everyone gets this functionality */
		if (strcmp(page,"passwd")==0) {
			passwd_page();
		} else {
			welcome_page();
		}
	}
	
	print_footer();
	return 0;
}
