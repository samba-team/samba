/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Parameter loading functions
   Copyright (C) Karl Auer 1993, 1994

   Extensively modified by Andrew Tridgell
   
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

/*
 *
 * Prototypes etc for loadparm.c.
 *
 */
#ifndef _LOADPARM_H
#define _LOADPARM_H

#include "smb.h"

extern BOOL lp_file_list_changed(void);
extern void lp_killunused(BOOL (*snumused)(int ));
extern BOOL lp_loaded(void);
extern BOOL lp_snum_ok(int iService);
extern BOOL lp_manglednames(int iService);
extern char *lp_interfaces(void);
extern char *lp_passwordserver(void);
extern char *lp_passwd_program(void);
extern char *lp_passwd_chat(void);
extern char *lp_guestaccount(int iService);
extern char *lp_printcapname(void);
extern char *lp_lockdir(void);
extern char *lp_logfile(void);
extern char *lp_smbrun(void);
extern char *lp_configfile(void);
extern char *lp_smb_passwd_file(void);
extern char *lp_rootdir(void);
extern char *lp_defaultservice(void);
extern char *lp_serverstring(void);
extern char *lp_dfree_command(void);
extern char *lp_msg_command(void);
extern char *lp_workgroup(void);
extern char *lp_domain_controller(void);
extern char *lp_username_map(void);
extern char *lp_hosts_equiv(void);
extern char *lp_logon_script(void);
extern char *lp_wins_server(void);
extern char *lp_magicscript(int iService);
extern char *lp_magicoutput(int iService);
extern char *lp_mangled_map(int iService);
char *volume_label(int snum);
extern int  lp_os_level(void);
extern int  lp_max_ttl(void);
extern int  lp_max_log_size(void);
extern int  lp_maxxmit(void);
extern int  lp_maxmux(void);
extern int  lp_mangledstack(void);
extern BOOL lp_wins_support(void);
extern BOOL lp_wins_proxy(void);
extern BOOL lp_preferred_master(void);
extern BOOL lp_domain_master(void);
extern BOOL lp_domain_logons(void);
extern BOOL lp_getwdcache(void);
extern BOOL lp_use_rhosts(void);
extern BOOL lp_readprediction(void);
extern BOOL lp_readbmpx(void);
extern BOOL lp_readraw(void);
extern BOOL lp_writeraw(void);
extern BOOL lp_null_passwords(void);
extern BOOL lp_strip_dot(void);
extern BOOL lp_encrypted_passwords(void);
extern BOOL lp_syslog_only(void);
extern BOOL lp_browse_list(void);
extern int  lp_numservices(void);
extern int  lp_keepalive(void);
extern int  lp_passwordlevel(void);
extern int  lp_security(void);
extern int  lp_printing(void);
extern int  lp_maxdisksize(void);
extern int  lp_lpqcachetime(void);
extern int  lp_syslog(void);
extern int  lp_deadtime(void);
extern int  lp_readsize(void);
extern int  lp_debuglevel(void);
extern int  lp_maxprotocol(void);
extern int  lp_maxpacket(void);
extern char *lp_comment(int iService);
extern char *lp_preexec(int iService);
extern char *lp_postexec(int iService);
extern char *lp_rootpreexec(int iService);
extern char *lp_rootpostexec(int iService);
extern char *lp_servicename(int iService);
extern char *lp_pathname(int iService);
extern char *lp_username(int iService);
extern char *lp_invalid_users(int iService);
extern char *lp_valid_users(int iService);
extern char *lp_admin_users(int iService);
extern char *lp_printcommand(int iService);
extern char *lp_lpqcommand(int iService);
extern char *lp_lprmcommand(int iService);
extern char *lp_lppausecommand(int iService);
extern char *lp_lpresumecommand(int iService);
extern char *lp_printername(int iService);
extern char *lp_hostsallow(int iService);
extern char *lp_hostsdeny(int iService);
extern char *lp_dontdescend(int iService);
extern char *lp_force_user(int iService);
extern char *lp_force_group(int iService);
extern char *lp_readlist(int iService);
extern char *lp_writelist(int iService);
extern BOOL lp_alternate_permissions(int iService);
extern BOOL lp_revalidate(int iService);
extern BOOL lp_status(int iService);
extern BOOL lp_hide_dot_files(int iService);
extern BOOL lp_browseable(int iService);
extern BOOL lp_widelinks(int iService);
extern BOOL lp_syncalways(int iService);
extern BOOL lp_readonly(int iService);
extern BOOL lp_no_set_dir(int iService);
extern BOOL lp_guest_ok(int iService);
extern BOOL lp_guest_only(int iService);
extern BOOL lp_print_ok(int iService);
extern BOOL lp_postscript(int iService);
extern BOOL lp_map_hidden(int iService);
extern BOOL lp_map_archive(int iService);
extern BOOL lp_locking(int iService);
extern BOOL lp_strict_locking(int iService);
extern BOOL lp_share_modes(int iService);
extern BOOL lp_onlyuser(int iService);
extern BOOL lp_map_system(int iService);
extern BOOL lp_casesensitive(int iService);
extern BOOL lp_casemangle(int iService);
extern BOOL lp_preservecase(int iService);
extern BOOL lp_shortpreservecase(int iService);
extern BOOL lp_load(char *pszFname,BOOL global_only);
extern void lp_dump(void);
extern int  lp_servicenumber(char *pszServiceName);
extern BOOL lp_add_home(char *pszHomename, 
                        int iDefaultService, char *pszHomedir);
extern int lp_add_service(char *service, int iDefaultService);
extern BOOL lp_add_printer(char *pszPrintername, int iDefaultService);
extern BOOL lp_readonly(int iService);
extern int lp_create_mode(int iService);
extern int lp_minprintspace(int iService);
extern int lp_defaultcase(int iService);
extern char lp_magicchar(int iService);
extern int lp_max_connections(int iService);
extern BOOL lp_add_home(char *pservice,int ifrom,char *phome);
extern char *lp_string(char *s);
extern BOOL lp_delete_readonly(int iService);
char *my_workgroup(void);

#endif

