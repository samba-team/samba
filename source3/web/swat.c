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

/*
 * Password Management Globals
 */
char user[] = "username";
char old_pswd[] = "old_passwd";
char new_pswd[] = "new_passwd";
char new2_pswd[] = "new2_passwd";
char chg_passwd_flag[] = "chg_passwd_flag";
char add_user_flag[] = "add_user_flag";
char disable_user_flag[] = "disable_user_flag";

/* we need these because we link to locking*.o */
 void become_root(BOOL save_dir) {}
 void unbecome_root(BOOL restore_dir) {}
/* We need this because we link to password.o */
BOOL change_oem_password(struct smb_passwd *smbpw, char *new_passwd, BOOL override) {return False;}

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
	if (am_root() == True) {
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

/****************************************************************************
****************************************************************************/
static void sig_pipe ( int signo)
{
	printf("<p> SIGPIPE caught\n");
}

/****************************************************************************
  create 2 pipes and use them to feed the smbpasswd program 
****************************************************************************/
static BOOL talk_to_smbpasswd(char *old, char *new)
{
	int 	i, n, fd1[2], fd2[2];
	pid_t	pid;
	BOOL	rslt;
	char	line[MAX_STRINGLEN + 2]; /* one for newline, one for null */

	if (signal(SIGPIPE, sig_pipe) == SIG_ERR) {
		printf("<p> signal error");
	}

	if ((pipe(fd1) < 0) || (pipe(fd2) < 0)) {
		printf("<p> pipe error");
	}

	if ((pid = fork()) < 0) {
		printf("<p> fork error");
	}

	/*
	 * Create this relationship with the pipes between the parent and 
	 * the child as detailed below.
	 *
	 * parent -> fd1[1] -- fd1[0] -> child 
	 * parent <- fd2[0] -- fd2[1] <- child 
	 *
	 * fd1[0] is turned into child's stdin
	 * fd2[1] is turned into child's stdout
	 * fd2[1] is also turned into child's stderr
	 *
	 */
	else if (pid > 0) {			/* parent */

		int	to_child    = fd1[1];
		int	from_child  = fd2[0];
		int	wstat;

		close(fd1[0]); /* parent doesn't need input  side of pipe fd1 */
		close(fd2[1]); /* parent doesn't need output side of pipe fd2 */

		/*
		 * smbpasswd doesn't require any input to disable a user 
		 */
		if (cgi_variable(disable_user_flag)) {
			/*
			 * smbpasswd requires a regular old user to send their old password 
			 */
			if (am_root() == False) {
				n = (strlen(old) <= (MAX_STRINGLEN)) ? strlen(old) : (MAX_STRINGLEN);
				strncpy( line, old, n);
				line[n] = '\n'; n++; /* add carriage return */
				line[n] =    0;      /* add null terminator, for debug */
				if (write( to_child, line, n) != n) {
					printf("<p> error on write to child");
				}
			}

			/*
			 * smbpasswd requires that the new password be sent to it twice
			 */
			for( i=0; i<2; i++) {
				n = (strlen(new) <= (MAX_STRINGLEN)) ? strlen(new) : (MAX_STRINGLEN);
				strncpy( line, new, n);
				line[n] = '\n'; n++; /* add carriage return */
				line[n] =    0;      /* add null terminator, for debug */
				if (write( to_child, line, n) != n) {
					printf("<p> error on write to child");
					break;
				}
			}
		}

		/*
		 * Wait for smbpasswd to finish
		 */
		if (sys_waitpid(pid, &wstat, 0) < 0) {
			printf("<p> problem waiting");
		}

		/* 
		 * Read the answer from the add program
		 */
		memset( line, '\0', sizeof(line));
		if ((n = read( from_child, line, MAX_STRINGLEN)) < 0) {
			printf("<p> error on read from child");
		}

		/*
		 * Write the response from smbpasswd to user, if all is well
		 * line[] should be just a null terminated line. We could 
		 * check for the null line and not print anything, but we 
		 * really should be checking the exit code if we want to be 
		 * sure.
		 */
		line[n] = 0;    /* null terminate */
		printf("<p> %s\n",line);
	
		close(to_child); 
		close(from_child); 
	
		if (line[0] == '\0') {
			rslt = True;   /* All ok */
		} else {
			rslt = False;  /* Something didn't work */
		}
		
	} else {				/* child  */

		int	from_parent  = fd1[0];
		int	to_parent    = fd2[1];

		close(fd1[1]); /* child  doesn't need output side of pipe fd1 */
		close(fd2[0]); /* child  doesn't need input  side of pipe fd2 */

		/*
		 * Turn the from_parent pipe into the childs stdin 
		 */
		if (from_parent != STDIN_FILENO) {
			if (dup2( from_parent, STDIN_FILENO) != STDIN_FILENO) {
				printf("<p> dup2 error of stdin");
			}
			close( from_parent);
		}

		/*
		 * Turn the to_parent pipe into the childs stdout
		 */
		if (to_parent != STDOUT_FILENO) {
			if (dup2( to_parent, STDOUT_FILENO) != STDOUT_FILENO) {
				printf("<p> dup2 error of stdout");
			}
			close( to_parent);
		}
		/*
		 * Make the childs stderr the to_parent pipe also
		 */
		if (dup2( STDOUT_FILENO, STDERR_FILENO) != STDERR_FILENO) {
			printf("<p> dup2 error of stdout");
		}

		
		/* Root can do more */
		if (am_root() == True) {
			if (cgi_variable(add_user_flag)) {
				/* 
				 * Add a user 
				 */
				if (execl(SMB_PASSWD_PROGRAM, "smbpasswd", "-s", "-a", cgi_variable(user), (char *) 0) < 0) {
					printf("<p> execl error of smbpasswd");
				}
			} else if (cgi_variable(disable_user_flag)) {
				/* 
				 * Disable a user 
				 */
				if (execl(SMB_PASSWD_PROGRAM, "smbpasswd", "-s", "-d", cgi_variable(user), (char *) 0) < 0) {
					printf("<p> execl error of smbpasswd");
				}
			} else {
				/* 
			 	 * Change a users password 
				 */
				if (execl(SMB_PASSWD_PROGRAM, "smbpasswd", "-s", cgi_variable(user), (char *) 0) < 0) {
					printf("<p> execl error of smbpasswd");
				}
			}
		} else {
			/* 
		 	 * Ordinary users can change any users passwd if they know the old passwd
			 */
			if (execl(SMB_PASSWD_PROGRAM, "smbpasswd", "-s", (char *) 0) < 0) {
				printf("<p> execl error of smbpasswd");
			}
		}
	}
	return(rslt);  
}

/****************************************************************************
  become the specified uid
****************************************************************************/
static BOOL become_uid(uid_t uid)
{
#ifdef HAVE_TRAPDOOR_UID
#ifdef HAVE_SETUIDX
	/* AIX3 has setuidx which is NOT a trapoor function (tridge) */
	if (setuidx(ID_EFFECTIVE, uid) != 0) {
		if (seteuid(uid) != 0) {
			printf("<p> Can't set uid %d (setuidx)\n", (int)uid);
			return False;
		}
	}
#endif
#endif

#ifdef HAVE_SETRESUID
	if (setresuid(-1,uid,-1) != 0)
#else
	if ((seteuid(uid) != 0) && (setuid(uid) != 0))
#endif
	{
		printf("<p> Couldn't set uid %d currently set to (uid %d, euid %d)\n",
			(int)uid,(int)getuid(), (int)geteuid());
		if (uid > (uid_t)32000) {
			printf("<p> Looks like your OS doesn't like high uid values - try using a different account\n");

		}
		return(False);
	}

	if (((uid == (uid_t)-1) || ((sizeof(uid_t) == 2) && (uid == 65535))) &&
            (geteuid() != uid)) {
		printf("<p> Invalid uid -1. perhaps you have a account with uid 65535?\n");
		return(False);
	}

	return(True);
}

/****************************************************************************
  become the specified gid
****************************************************************************/
static BOOL become_gid(gid_t gid)
{
#ifdef HAVE_SETRESUID
	if (setresgid(-1,gid,-1) != 0)
#else
	if (setgid(gid) != 0)
#endif
	{
		printf("<p> Couldn't set gid %d currently set to (gid %d, egid %d)\n",
                 (int)gid,(int)getgid(),(int)getegid());
		if (gid > 32000) {
			printf("<p> Looks like your OS doesn't like high gid values - try using a different account\n");
		}
		return(False);
	}

	return(True);
}

/****************************************************************************
  become the specified uid and gid
****************************************************************************/
static BOOL become_id(uid_t uid,gid_t gid)
{
	return(become_gid(gid) && become_uid(uid));
}

/****************************************************************************
  do the stuff required to add or change a password 
****************************************************************************/
static void chg_passwd(void)
{
	struct passwd *pass = NULL;
	BOOL rslt;

	/* Make sure users name has been specified */
	if (strlen(cgi_variable(user)) == 0) {
		printf("<p> Must specify \"User Name\" \n");
		return;
	}

	/*
	 * smbpasswd doesn't require anything but the users name to disable the user,
	 * so if that's what we're doing, skip the rest of the checks
	 */
	if (!cgi_variable(disable_user_flag)) {

		/* If current user is not root, make sure old password has been specified */
		if ((am_root() == False) &&  (strlen( cgi_variable(old_pswd)) <= 0)) {
			printf("<p> Must specify \"Old Password\" \n");
			return;
		}

		/* Make sure new passwords have been specified */
		if ((strlen( cgi_variable(new_pswd )) <= 0) ||
		    (strlen( cgi_variable(new2_pswd)) <= 0)) {
			printf("<p> Must specify \"New, and Re-typed Passwords\" \n");
			return;
		}

		/* Make sure new passwords was typed correctly twice */
		if (strcmp(cgi_variable(new_pswd), cgi_variable(new2_pswd)) != 0) {
			printf("<p> Re-typed password didn't match new password\n");
			return;
		}
	}

	/* Get the UID/GID of the user, and become that user  */
	if (am_root() == False) {
		pass = Get_Pwnam(cgi_variable(user),True);
		if (pass == NULL) {
			printf("<p> User uid unknown     \n");
		} else {
			if (become_id(pass->pw_uid, pass->pw_gid) == False) {
				printf("<p> uid/gid set failed \n");
				return;
			}
		}
	}

#ifndef SWAT_DEBUG
	if (pass) printf("<p> User uid %d  gid %d \n", pass->pw_uid, pass->pw_gid);
	printf("<p> Processes uid %d, euid %d, gid %d, egid %d \n",getuid(),geteuid(),getgid(),getegid());
	printf("<p> User Name %s     \n", cgi_variable(user));
	printf("<p> Old passwd %s    \n", cgi_variable(old_pswd) ? cgi_variable(old_pswd):"");
	printf("<p> New passwd %s    \n", cgi_variable(new_pswd));
	printf("<p> Re-typed New passwd %s    \n", cgi_variable(new2_pswd));
	printf("<p> flags '%s', '%s', '%s'   \n", 
		(cgi_variable( chg_passwd_flag) ? cgi_variable( chg_passwd_flag) : ""),
		(cgi_variable( add_user_flag) ? cgi_variable( add_user_flag) : ""),
		(cgi_variable( disable_user_flag) ? cgi_variable( disable_user_flag) : ""));
#endif /* SWAT_DEBUG */


	rslt = talk_to_smbpasswd( cgi_variable(old_pswd), cgi_variable(new_pswd));
	if (am_root() == False) {
		if (rslt == True) {
			printf("<p> The passwd for '%s' has been changed. \n",cgi_variable(user));
		} else {
			printf("<p> The passwd for '%s' has NOT been changed. \n",cgi_variable(user));
		}
	}
	
	return;
}

/****************************************************************************
  display a password editing page  
****************************************************************************/
static void passwd_page(void)
{
	char *new_name;

	printf("<H2>Password Manager</H2>\n");

	printf("<FORM name=\"swatform\" method=post>\n");

	printf("<table>\n");

	/* 
	 * After the first time through here be nice. If the user
	 * changed the User box text to another users name, remember it.
	 */
	if ( cgi_variable(user) && 
	    (strcmp(cgi_variable(user), get_user_name()))) {
		/* User is changing another accounts passwd */
		new_name = cgi_variable(user);
	} else {
		/* User is changing there own passwd */
		new_name = get_user_name();
	}

	printf("<p> User Name        : <input type=text size=30 name=%s value=%s> \n", user, new_name);
	if (am_root() == False) {
		printf("<p> Old Password: <input type=password size=30 name=%s>\n",old_pswd);
	}
	printf("<p> New Password: <input type=password size=30 name=%s>\n",new_pswd);
	printf("<p> Re-type New Password: <input type=password size=30 name=%s>\n",new2_pswd);

	printf("</select></td></tr><p>");
	printf("<tr><td>");
	printf("<input type=submit name=%s value=\"Change Password\">", chg_passwd_flag);
	if (am_root() == True) {
		printf("<input type=submit name=%s value=\"Add New User\">", add_user_flag);
		printf("<input type=submit name=%s value=\"Disable User\">", disable_user_flag);
	}
	printf("</td>\n");

	/*
	 * If we don't have user information then there's nothing to do. It's probably
	 * the first time through this code.
	 */
	if (cgi_variable(user)) {
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

	page = cgi_pathinfo();

	/* Root gets full functionality */
	if (am_root() == True) {
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

