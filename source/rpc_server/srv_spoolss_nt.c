/*
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-2000,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-2000,
 *  Copyright (C) Jean François Micouleau      1998-2000.
 *  Copyright (C) Jeremy Allison		    2001.
 *  Copyright (C) Gerald Carter		       2000-2001.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/* Since the SPOOLSS rpc routines are basically DOS 16-bit calls wrapped
   up, all the errors returned are DOS errors, not NT status codes. */

#include "includes.h"

extern pstring global_myname;

#ifndef MAX_OPEN_PRINTER_EXS
#define MAX_OPEN_PRINTER_EXS 50
#endif

#define PHANTOM_DEVMODE_KEY "_p_f_a_n_t_0_m_"
#define PRINTER_HANDLE_IS_PRINTER	0
#define PRINTER_HANDLE_IS_PRINTSERVER	1

struct table_node {
	char    *long_archi;
	char    *short_archi;
	int     version;
};


/* structure to store the printer handles */
/* and a reference to what it's pointing to */
/* and the notify info asked about */
/* that's the central struct */
typedef struct _Printer{
	BOOL document_started;
	BOOL page_started;
    int jobid; /* jobid in printing backend */
	BOOL printer_type;
	union {
	  	fstring handlename;
		fstring printerservername;
	} dev;
	uint32 type;
	uint32 access;
	struct {
		uint32 flags;
		uint32 options;
		fstring localmachine;
		uint32 printerlocal;
		SPOOL_NOTIFY_OPTION *option;
		POLICY_HND client_hnd;
		uint32 client_connected;
	} notify;
	struct {
		fstring machine;
		fstring user;
	} client;
} Printer_entry;

typedef struct _counter_printer_0 {
	ubi_dlNode Next;
	ubi_dlNode Prev;
	
	int snum;
	uint32 counter;
} counter_printer_0;

static ubi_dlList counter_list;

static struct cli_state cli;
static uint32 smb_connections=0;

#define OUR_HANDLE(hnd) ((hnd==NULL)?"NULL":(IVAL(hnd->data5,4)==(uint32)sys_getpid()?"OURS":"OTHER"))

/* translate between internal status numbers and NT status numbers */
static int nt_printj_status(int v)
{
	switch (v) {
	case LPQ_QUEUED:
		return 0;
	case LPQ_PAUSED:
		return JOB_STATUS_PAUSED;
	case LPQ_SPOOLING:
		return JOB_STATUS_SPOOLING;
	case LPQ_PRINTING:
		return JOB_STATUS_PRINTING;
	case LPQ_ERROR:
		return JOB_STATUS_ERROR;
	case LPQ_DELETING:
		return JOB_STATUS_DELETING;
	case LPQ_OFFLINE:
		return JOB_STATUS_OFFLINE;
	case LPQ_PAPEROUT:
		return JOB_STATUS_PAPEROUT;
	case LPQ_PRINTED:
		return JOB_STATUS_PRINTED;
	case LPQ_DELETED:
		return JOB_STATUS_DELETED;
	case LPQ_BLOCKED:
		return JOB_STATUS_BLOCKED;
	case LPQ_USER_INTERVENTION:
		return JOB_STATUS_USER_INTERVENTION;
	}
	return 0;
}

static int nt_printq_status(int v)
{
	switch (v) {
	case LPQ_PAUSED:
		return PRINTER_STATUS_PAUSED;
	case LPQ_QUEUED:
	case LPQ_SPOOLING:
	case LPQ_PRINTING:
		return 0;
	}
	return 0;
}

/****************************************************************************
 Functions to handle SPOOL_NOTIFY_OPTION struct stored in Printer_entry.
****************************************************************************/

static void free_spool_notify_option(SPOOL_NOTIFY_OPTION **pp)
{
	if (*pp == NULL)
		return;

	SAFE_FREE((*pp)->ctr.type);
	SAFE_FREE(*pp);
}

/***************************************************************************
 Disconnect from the client
****************************************************************************/

static void srv_spoolss_replycloseprinter(POLICY_HND *handle)
{
	WERROR status;

	/* weird if the test succeds !!! */
	if (smb_connections==0) {
		DEBUG(0,("srv_spoolss_replycloseprinter:Trying to close non-existant notify backchannel !\n"));
		return;
	}

	if(!cli_spoolss_reply_close_printer(&cli, handle, &status))
		DEBUG(0,("srv_spoolss_replycloseprinter: reply_close_printer failed.\n"));

	/* if it's the last connection, deconnect the IPC$ share */
	if (smb_connections==1) {
		if(!spoolss_disconnect_from_client(&cli))
			return;

		message_deregister(MSG_PRINTER_NOTIFY);
	}

	smb_connections--;
}

/****************************************************************************
 Functions to free a printer entry datastruct.
****************************************************************************/

static void free_printer_entry(void *ptr)
{
	Printer_entry *Printer = (Printer_entry *)ptr;

	if (Printer->notify.client_connected==True)
		srv_spoolss_replycloseprinter(&Printer->notify.client_hnd);

	Printer->notify.flags=0;
	Printer->notify.options=0;
	Printer->notify.localmachine[0]='\0';
	Printer->notify.printerlocal=0;
	free_spool_notify_option(&Printer->notify.option);
	Printer->notify.option=NULL;
	Printer->notify.client_connected=False;

	SAFE_FREE(Printer);
}

/****************************************************************************
 Functions to duplicate a SPOOL_NOTIFY_OPTION struct stored in Printer_entry.
****************************************************************************/

SPOOL_NOTIFY_OPTION *dup_spool_notify_option(SPOOL_NOTIFY_OPTION *sp)
{
	SPOOL_NOTIFY_OPTION *new_sp = NULL;

	if (!sp)
		return NULL;

	new_sp = (SPOOL_NOTIFY_OPTION *)malloc(sizeof(SPOOL_NOTIFY_OPTION));
	if (!new_sp)
		return NULL;

	*new_sp = *sp;

	if (sp->ctr.count) {
		new_sp->ctr.type = (SPOOL_NOTIFY_OPTION_TYPE *)memdup(sp->ctr.type, sizeof(SPOOL_NOTIFY_OPTION_TYPE) * sp->ctr.count);

		if (!new_sp->ctr.type) {
			SAFE_FREE(new_sp);
			return NULL;
		}
	}

	return new_sp;
}

/****************************************************************************
  find printer index by handle
****************************************************************************/

static Printer_entry *find_printer_index_by_hnd(pipes_struct *p, POLICY_HND *hnd)
{
	Printer_entry *find_printer = NULL;

	if(!find_policy_by_hnd(p,hnd,(void **)&find_printer)) {
		DEBUG(3,("find_printer_index_by_hnd: Printer handle not found: "));
		return NULL;
	}

	return find_printer;
}

/****************************************************************************
  close printer index by handle
****************************************************************************/

static BOOL close_printer_handle(pipes_struct *p, POLICY_HND *hnd)
{
	Printer_entry *Printer = find_printer_index_by_hnd(p, hnd);

	if (!Printer) {
		DEBUG(0,("close_printer_handle: Invalid handle (%s)\n", OUR_HANDLE(hnd)));
		return False;
	}

	close_policy_hnd(p, hnd);

	return True;
}	

/****************************************************************************
  delete a printer given a handle
****************************************************************************/
static WERROR delete_printer_handle(pipes_struct *p, POLICY_HND *hnd)
{
	Printer_entry *Printer = find_printer_index_by_hnd(p, hnd);

	if (!Printer) {
		DEBUG(0,("delete_printer_handle: Invalid handle (%s)\n", OUR_HANDLE(hnd)));
		return WERR_BADFID;
	}

	if (del_a_printer(Printer->dev.handlename) != 0) {
		DEBUG(3,("Error deleting printer %s\n", Printer->dev.handlename));
		return WERR_BADFID;
	}

	/* Check calling user has permission to delete printer.  Note that
	   since we set the snum parameter to -1 only administrators can
	   delete the printer.  This stops people with the Full Control
	   permission from deleting the printer. */

	if (!print_access_check(NULL, -1, PRINTER_ACCESS_ADMINISTER)) {
		DEBUG(3, ("printer delete denied by security descriptor\n"));
		return WERR_ACCESS_DENIED;
	}

	if (*lp_deleteprinter_cmd()) {

		char *cmd = lp_deleteprinter_cmd();
		pstring command;
		int ret;
		int i;

		/* Printer->dev.handlename equals portname equals sharename */
		slprintf(command, sizeof(command)-1, "%s \"%s\"", cmd,
					Printer->dev.handlename);
		dos_to_unix(command, True);  /* Convert printername to unix-codepage */

		DEBUG(10,("Running [%s]\n", command));
		ret = smbrun(command, NULL);
		if (ret != 0) {
			return WERR_BADFID; /* What to return here? */
		}
		DEBUGADD(10,("returned [%d]\n", ret));

		/* Send SIGHUP to process group... is there a better way? */
		kill(0, SIGHUP);

		if ( ( i = lp_servicenumber( Printer->dev.handlename ) ) >= 0 ) {
			lp_killservice( i );
			return WERR_OK;
		} else
			return WERR_ACCESS_DENIED;
	}

	return WERR_OK;
}	

/****************************************************************************
  return the snum of a printer corresponding to an handle
****************************************************************************/
static BOOL get_printer_snum(pipes_struct *p, POLICY_HND *hnd, int *number)
{
	Printer_entry *Printer = find_printer_index_by_hnd(p, hnd);
		
	if (!Printer) {
		DEBUG(0,("get_printer_snum: Invalid handle (%s)\n", OUR_HANDLE(hnd)));
		return False;
	}
	
	switch (Printer->printer_type) {
	case PRINTER_HANDLE_IS_PRINTER:		
		DEBUG(4,("short name:%s\n", Printer->dev.handlename));			
		*number = print_queue_snum(Printer->dev.handlename);
		return (*number != -1);
	case PRINTER_HANDLE_IS_PRINTSERVER:
		return False;
	default:
		return False;
	}
}

/****************************************************************************
  set printer handle type.
****************************************************************************/
static BOOL set_printer_hnd_accesstype(pipes_struct *p, POLICY_HND *hnd, uint32 access_required)
{
	Printer_entry *Printer = find_printer_index_by_hnd(p, hnd);

	if (!Printer) {
		DEBUG(0,("set_printer_hnd_accesstype: Invalid handle (%s)", OUR_HANDLE(hnd)));
		return False;
	}

	DEBUG(4,("Setting printer access=%x\n", access_required));
	Printer->access = access_required;
	return True;		
}

/****************************************************************************
 Set printer handle type.
 Check if it's \\server or \\server\printer
****************************************************************************/

static BOOL set_printer_hnd_printertype(Printer_entry *Printer, char *handlename)
{
	DEBUG(3,("Setting printer type=%s\n", handlename));

	if ( strlen(handlename) < 3 ) {
		DEBUGADD(4,("A print server must have at least 1 char ! %s\n", handlename));
		return False;
	}

	/* it's a print server */
	if (*handlename=='\\' && *(handlename+1)=='\\' && !strchr(handlename+2, '\\')) {
		DEBUGADD(4,("Printer is a print server\n"));
		Printer->printer_type = PRINTER_HANDLE_IS_PRINTSERVER;		
	}
	/* it's a printer */
	else {
		DEBUGADD(4,("Printer is a printer\n"));
		Printer->printer_type = PRINTER_HANDLE_IS_PRINTER;
	}

	return True;
}

/****************************************************************************
 Set printer handle name.
****************************************************************************/

static BOOL set_printer_hnd_name(Printer_entry *Printer, char *handlename)
{
	NT_PRINTER_INFO_LEVEL *printer = NULL;
	int snum;
	int n_services=lp_numservices();
	char *aprinter;
	BOOL found=False;
	
	DEBUG(4,("Setting printer name=%s (len=%d)\n", handlename, strlen(handlename)));

	if (Printer->printer_type==PRINTER_HANDLE_IS_PRINTSERVER) {
		ZERO_STRUCT(Printer->dev.printerservername);
		strncpy(Printer->dev.printerservername, handlename, strlen(handlename));
		return True;
	}

	if (Printer->printer_type!=PRINTER_HANDLE_IS_PRINTER)
		return False;
	
	if (*handlename=='\\') {
		aprinter=strchr(handlename+2, '\\');
		aprinter++;
	}
	else {
		aprinter=handlename;
	}

	DEBUGADD(5,("searching for [%s] (len=%d)\n", aprinter, strlen(aprinter)));

	/*
	 * store the Samba share name in it
	 * in back we have the long printer name
	 * need to iterate all the snum and do a
	 * get_a_printer each time to find the printer
	 * faster to do it here than later.
	 */

	for (snum=0;snum<n_services && found==False;snum++) {
		char *printername;
	
		if ( !(lp_snum_ok(snum) && lp_print_ok(snum) ) )
			continue;
		
		DEBUGADD(5,("share:%s\n",lp_servicename(snum)));

		if (!W_ERROR_IS_OK(get_a_printer(&printer, 2, lp_servicename(snum))))
			continue;

		printername=strchr(printer->info_2->printername+2, '\\');
		printername++;

		DEBUG(10,("set_printer_hnd_name: name [%s], aprinter [%s]\n",
				printer->info_2->printername, aprinter ));

		if ( strlen(printername) != strlen(aprinter) ) {
			free_a_printer(&printer, 2);
			continue;
		}
		
		if ( strncasecmp(printername, aprinter, strlen(aprinter)))  {
			free_a_printer(&printer, 2);
			continue;
		}
		
		found=True;
	}

	/*
	 * if we haven't found a printer with the given handlename
	 * then it can be a share name as you can open both \\server\printer and
	 * \\server\share
	 */

	/*
	 * we still check if the printer description file exists as NT won't be happy
	 * if we reply OK in the openprinter call and can't reply in the subsequent RPC calls
	 */

	if (found==False) {
		DEBUGADD(5,("Printer not found, checking for share now\n"));
	
		for (snum=0;snum<n_services && found==False;snum++) {
	
			if ( !(lp_snum_ok(snum) && lp_print_ok(snum) ) )
				continue;
		
			DEBUGADD(5,("set_printer_hnd_name: share:%s\n",lp_servicename(snum)));

			if (!W_ERROR_IS_OK(get_a_printer(&printer, 2, lp_servicename(snum))))
				continue;

			DEBUG(10,("set_printer_hnd_name: printername [%s], aprinter [%s]\n",
					printer->info_2->printername, aprinter ));

			if ( strlen(lp_servicename(snum)) != strlen(aprinter) ) {
				free_a_printer(&printer, 2);
				continue;
			}
		
			if ( strncasecmp(lp_servicename(snum), aprinter, strlen(aprinter)))  {
				free_a_printer(&printer, 2);
				continue;
			}
		
			found=True;
		}
	}
		
	if (found==False) {
		DEBUGADD(4,("Printer not found\n"));
		return False;
	}
	
	snum--;
	DEBUGADD(4,("set_printer_hnd_name: Printer found: %s -> %s[%x]\n",
			printer->info_2->printername, lp_servicename(snum),snum));

	ZERO_STRUCT(Printer->dev.handlename);
	strncpy(Printer->dev.handlename, lp_servicename(snum), strlen(lp_servicename(snum)));
	
	free_a_printer(&printer, 2);

	return True;
}

/****************************************************************************
  find first available printer slot. creates a printer handle for you.
 ****************************************************************************/

static BOOL open_printer_hnd(pipes_struct *p, POLICY_HND *hnd, char *name)
{
	Printer_entry *new_printer;

	DEBUG(10,("open_printer_hnd: name [%s]\n", name));

	if((new_printer=(Printer_entry *)malloc(sizeof(Printer_entry))) == NULL)
		return False;

	ZERO_STRUCTP(new_printer);
	
	new_printer->notify.option=NULL;
				
	if (!create_policy_hnd(p, hnd, free_printer_entry, new_printer)) {
		SAFE_FREE(new_printer);
		return False;
	}

	if (!set_printer_hnd_printertype(new_printer, name)) {
		close_printer_handle(p, hnd);
		return False;
	}
	
	if (!set_printer_hnd_name(new_printer, name)) {
		close_printer_handle(p, hnd);
		return False;
	}

	DEBUG(5, ("%d printer handles active\n", (int)p->pipe_handles->count ));

	return True;
}

/********************************************************************
 Return True is the handle is a print server.
 ********************************************************************/

static BOOL handle_is_printserver(pipes_struct *p, POLICY_HND *handle)
{
	Printer_entry *Printer=find_printer_index_by_hnd(p,handle);

	if (!Printer)
		return False;
		
	if (Printer->printer_type != PRINTER_HANDLE_IS_PRINTSERVER)
		return False;
	
	return True;
}

/****************************************************************************
 allocate more memory for a BUFFER.
****************************************************************************/
static BOOL alloc_buffer_size(NEW_BUFFER *buffer, uint32 buffer_size)
{
	prs_struct *ps;
	uint32 extra_space;
	uint32 old_offset;
	
	ps= &buffer->prs;

	/* damn, I'm doing the reverse operation of prs_grow() :) */
	if (buffer_size < prs_data_size(ps))
		extra_space=0;
	else	
		extra_space = buffer_size - prs_data_size(ps);

	/*
	 * save the offset and move to the end of the buffer
	 * prs_grow() checks the extra_space against the offset
	 */
	old_offset=prs_offset(ps);	
	prs_set_offset(ps, prs_data_size(ps));
	
	if (!prs_grow(ps, extra_space))
		return False;

	prs_set_offset(ps, old_offset);

	buffer->string_at_end=prs_data_size(ps);

	return True;
}

/***************************************************************************
 receive the notify message
****************************************************************************/

static void srv_spoolss_receive_message(int msg_type, pid_t src, void *buf, size_t len)
{
	fstring printer;
	WERROR status;
	struct pipes_struct *p;
	struct policy *pol;
	struct handle_list *hl;

	*printer = '\0';
	fstrcpy(printer,buf);

	if (len == 0) {
		DEBUG(0,("srv_spoolss_receive_message: got null message !\n"));
		return;
	}

	DEBUG(10,("srv_spoolss_receive_message: Got message about printer %s\n", printer ));

	/*
	 * We need to enumerate all printers. The handle list is shared
	 * across pipes of the same name, so just find the first open
	 * spoolss pipe.
	 */

	hl = NULL;	
	for ( p = get_first_pipe(); p; get_next_pipe(p)) {
		if (strequal(p->name, "spoolss")) {
			hl = p->pipe_handles;
			break;
		}
	}

	if (!hl) {
		DEBUG(0,("srv_spoolss_receive_message: no handle list on spoolss pipe !\n"));
		return;
	}

	/* Iterate the printer list on this pipe. */
	for (pol = hl->Policy; pol; pol = pol->next ) {
		Printer_entry *find_printer = (Printer_entry *)pol->data_ptr;

		if (!find_printer)
			continue;

		/*
		 * if the entry is the given printer or if it's a printerserver
		 * we send the message
		 */

		if (find_printer->printer_type==PRINTER_HANDLE_IS_PRINTER)
			if (strcmp(find_printer->dev.handlename, printer))
				continue;

		if (find_printer->notify.client_connected==True)
			cli_spoolss_reply_rrpcn(&cli, &find_printer->notify.client_hnd, PRINTER_CHANGE_ALL, 0x0, &status);
	}
}

/***************************************************************************
 send a notify event
****************************************************************************/
static BOOL srv_spoolss_sendnotify(pipes_struct *p, POLICY_HND *handle)
{
	fstring printer;

	Printer_entry *Printer=find_printer_index_by_hnd(p, handle);

	if (!Printer) {
		DEBUG(0,("srv_spoolss_sendnotify: Invalid handle (%s).\n", OUR_HANDLE(handle)));
		return False;
	}

	if (Printer->printer_type==PRINTER_HANDLE_IS_PRINTER)
		fstrcpy(printer, Printer->dev.handlename);
	else
		fstrcpy(printer, "");

	/*srv_spoolss_receive_message(printer);*/
	DEBUG(10,("srv_spoolss_sendnotify: Sending message about printer %s\n", printer ));

	message_send_all(conn_tdb_ctx(), MSG_PRINTER_NOTIFY, printer, strlen(printer) + 1, False); /* Null terminate... */

	return True;
}	

/********************************************************************
 * spoolss_open_printer
 *
 * called from the spoolss dispatcher
 ********************************************************************/

WERROR _spoolss_open_printer_ex( pipes_struct *p, SPOOL_Q_OPEN_PRINTER_EX *q_u, SPOOL_R_OPEN_PRINTER_EX *r_u)
{
#if 0
	WERROR result = WERR_OK;
#endif

	UNISTR2 *printername = NULL;
	PRINTER_DEFAULT *printer_default = &q_u->printer_default;
/*	uint32 user_switch = q_u->user_switch; - notused */
/*	SPOOL_USER_CTR user_ctr = q_u->user_ctr; - notused */
	POLICY_HND *handle = &r_u->handle;

	fstring name;
	int snum;
	struct current_user user;

	if (q_u->printername_ptr != 0)
		printername = &q_u->printername;

	if (printername == NULL)
		return WERR_INVALID_PRINTER_NAME;

	/* some sanity check because you can open a printer or a print server */
	/* aka: \\server\printer or \\server */
	unistr2_to_ascii(name, printername, sizeof(name)-1);

	DEBUGADD(3,("checking name: %s\n",name));

	if (!open_printer_hnd(p, handle, name))
		return WERR_INVALID_PRINTER_NAME;
	
/*
	if (printer_default->datatype_ptr != NULL)
	{
		unistr2_to_ascii(datatype, printer_default->datatype, sizeof(datatype)-1);
		set_printer_hnd_datatype(handle, datatype);
	}
	else
		set_printer_hnd_datatype(handle, "");
*/
	
	if (!set_printer_hnd_accesstype(p, handle, printer_default->access_required)) {
		close_printer_handle(p, handle);
		return WERR_ACCESS_DENIED;
	}
		
	/*
	   First case: the user is opening the print server:

	   Disallow MS AddPrinterWizard if parameter disables it. A Win2k
	   client 1st tries an OpenPrinterEx with access==0, MUST be allowed.

	   Then both Win2k and WinNT clients try an OpenPrinterEx with
	   SERVER_ALL_ACCESS, which we allow only if the user is root (uid=0)
	   or if the user is listed in the smb.conf printer admin parameter.

	   Then they try OpenPrinterEx with SERVER_READ which we allow. This lets the
	   client view printer folder, but does not show the MSAPW.

	   Note: this test needs code to check access rights here too. Jeremy
	   could you look at this?
	   
	   
	   Second case: the user is opening a printer:
	   NT doesn't let us connect to a printer if the connecting user
	   doesn't have print permission.

	*/

	get_current_user(&user, p);

	if (handle_is_printserver(p, handle)) {
		if (printer_default->access_required == 0) {
			return WERR_OK;
		}
		else if ((printer_default->access_required & SERVER_ACCESS_ADMINISTER ) == SERVER_ACCESS_ADMINISTER) {

			/* Printserver handles use global struct... */
			snum = -1;

			if (!lp_ms_add_printer_wizard()) {
				close_printer_handle(p, handle);
				return WERR_ACCESS_DENIED;
			}
			else if (user.uid == 0 || user_in_list(uidtoname(user.uid), lp_printer_admin(snum))) {
				return WERR_OK;
			} 
			else {
				close_printer_handle(p, handle);
				return WERR_ACCESS_DENIED;
			}
		}
	}
	else
	{
		/* NT doesn't let us connect to a printer if the connecting user
		   doesn't have print permission.  */

		if (!get_printer_snum(p, handle, &snum))
			return WERR_BADFID;

		/* map an empty access mask to the minimum access mask */
		if (printer_default->access_required == 0x0)
			printer_default->access_required = PRINTER_ACCESS_USE;
		

		/*
		 * If we are not serving the printer driver for this printer,
		 * map PRINTER_ACCESS_ADMINISTER to PRINTER_ACCESS_USE.  This
		 * will keep NT clients happy  --jerry	
		 */
		 
		if (lp_use_client_driver(snum) 
			&& (printer_default->access_required & PRINTER_ACCESS_ADMINISTER))
		{
			printer_default->access_required = PRINTER_ACCESS_USE;
		}

		if (!print_access_check(&user, snum, printer_default->access_required)) {
			DEBUG(3, ("access DENIED for printer open\n"));
			close_printer_handle(p, handle);
			return WERR_ACCESS_DENIED;
		}

		/*
		 * If we have a default device pointer in the
		 * printer_default struct, then we need to get
		 * the printer info from the tdb and if there is
	 	 * no default devicemode there then we do a *SET*
		 * here ! This is insanity.... JRA.
		 */

		/*
		 * If the openprinterex rpc call contains a devmode,
		 * it's a per-user one. This per-user devmode is derivated
		 * from the global devmode. Openprinterex() contains a per-user 
		 * devmode for when you do EMF printing and spooling.
		 * In the EMF case, the NT workstation is only doing half the job
		 * of rendering the page. The other half is done by running the printer
		 * driver on the server.
		 * The EMF file doesn't contain the page description (paper size, orientation, ...).
		 * The EMF file only contains what is to be printed on the page.
		 * So in order for the server to know how to print, the NT client sends
		 * a devicemode attached to the openprinterex call.
		 * But this devicemode is short lived, it's only valid for the current print job.
		 *
		 * If Samba would have supported EMF spooling, this devicemode would
		 * have been attached to the handle, to sent it to the driver to correctly
		 * rasterize the EMF file.
		 *
		 * As Samba only supports RAW spooling, we only receive a ready-to-print file,
		 * we just act as a pass-thru between windows and the printer.
		 *
		 * In order to know that Samba supports only RAW spooling, NT has to call
		 * getprinter() at level 2 (attribute field) or NT has to call startdoc()
		 * and until NT sends a RAW job, we refuse it.
		 *
		 * But to call getprinter() or startdoc(), you first need a valid handle,
		 * and to get an handle you have to call openprintex(). Hence why you have
		 * a devicemode in the openprinterex() call.
		 *
		 *
		 * Differences between NT4 and NT 2000.
		 * NT4:
		 * ---
		 * On NT4, you only have a global devicemode. This global devicemode can be changed
		 * by the administrator (or by a user with enough privs). Everytime a user
		 * wants to print, the devicemode is resetted to the default. In Word, everytime
		 * you print, the printer's characteristics are always reset to the global devicemode.
		 *
		 * NT 2000:
		 * -------
		 * In W2K, there is the notion of per-user devicemode. The first time you use
		 * a printer, a per-user devicemode is build from the global devicemode.
		 * If you change your per-user devicemode, it is saved in the registry, under the
		 * H_KEY_CURRENT_KEY sub_tree. So that everytime you print, you have your default
		 * printer preferences available.
		 *
		 * To change the per-user devicemode: it's the "Printing Preferences ..." button
		 * on the General Tab of the printer properties windows.
		 *
		 * To change the global devicemode: it's the "Printing Defaults..." button
		 * on the Advanced Tab of the printer properties window.
		 *
		 * JFM.
		 */



#if 0
		if (printer_default->devmode_cont.devmode != NULL) {
			result = printer_write_default_dev( snum, printer_default);
			if (result != 0) {
				close_printer_handle(p, handle);
				return result;
			}
		}
#endif
	}

	return WERR_OK;
}

/****************************************************************************
****************************************************************************/
static BOOL convert_printer_info(const SPOOL_PRINTER_INFO_LEVEL *uni,
				NT_PRINTER_INFO_LEVEL *printer, uint32 level)
{
	switch (level) {
		case 2:
			uni_2_asc_printer_info_2(uni->info_2, &printer->info_2);
			break;
		default:
			break;
	}

	return True;
}

static BOOL convert_printer_driver_info(const SPOOL_PRINTER_DRIVER_INFO_LEVEL *uni,
                                 	NT_PRINTER_DRIVER_INFO_LEVEL *printer, uint32 level)
{
	BOOL result = True;

	switch (level) {
		case 3:
			printer->info_3=NULL;
			if (!uni_2_asc_printer_driver_3(uni->info_3, &printer->info_3))
				result = False;
			break;
		case 6:
			printer->info_6=NULL;
			if (!uni_2_asc_printer_driver_6(uni->info_6, &printer->info_6))
				result = False;
			break;
		default:
			break;
	}

	return result;
}

BOOL convert_devicemode(char *printername, const DEVICEMODE *devmode,
				NT_DEVICEMODE **pp_nt_devmode)
{
	NT_DEVICEMODE *nt_devmode = *pp_nt_devmode;

	/*
	 * Ensure nt_devmode is a valid pointer
	 * as we will be overwriting it.
	 */
		
	if (nt_devmode == NULL) {
		DEBUG(5, ("convert_devicemode: allocating a generic devmode\n"));
		if ((nt_devmode = construct_nt_devicemode(printername)) == NULL)
			return False;
	}

	unistr_to_dos(nt_devmode->devicename, (const char *)devmode->devicename.buffer, 31);
	unistr_to_dos(nt_devmode->formname, (const char *)devmode->formname.buffer, 31);

	nt_devmode->specversion=devmode->specversion;
	nt_devmode->driverversion=devmode->driverversion;
	nt_devmode->size=devmode->size;
	nt_devmode->fields=devmode->fields;
	nt_devmode->orientation=devmode->orientation;
	nt_devmode->papersize=devmode->papersize;
	nt_devmode->paperlength=devmode->paperlength;
	nt_devmode->paperwidth=devmode->paperwidth;
	nt_devmode->scale=devmode->scale;
	nt_devmode->copies=devmode->copies;
	nt_devmode->defaultsource=devmode->defaultsource;
	nt_devmode->printquality=devmode->printquality;
	nt_devmode->color=devmode->color;
	nt_devmode->duplex=devmode->duplex;
	nt_devmode->yresolution=devmode->yresolution;
	nt_devmode->ttoption=devmode->ttoption;
	nt_devmode->collate=devmode->collate;

	nt_devmode->logpixels=devmode->logpixels;
	nt_devmode->bitsperpel=devmode->bitsperpel;
	nt_devmode->pelswidth=devmode->pelswidth;
	nt_devmode->pelsheight=devmode->pelsheight;
	nt_devmode->displayflags=devmode->displayflags;
	nt_devmode->displayfrequency=devmode->displayfrequency;
	nt_devmode->icmmethod=devmode->icmmethod;
	nt_devmode->icmintent=devmode->icmintent;
	nt_devmode->mediatype=devmode->mediatype;
	nt_devmode->dithertype=devmode->dithertype;
	nt_devmode->reserved1=devmode->reserved1;
	nt_devmode->reserved2=devmode->reserved2;
	nt_devmode->panningwidth=devmode->panningwidth;
	nt_devmode->panningheight=devmode->panningheight;

	/*
	 * Only change private and driverextra if the incoming devmode
	 * has a new one. JRA.
	 */

	if ((devmode->driverextra != 0) && (devmode->private != NULL)) {
		SAFE_FREE(nt_devmode->private);
		nt_devmode->driverextra=devmode->driverextra;
		if((nt_devmode->private=(uint8 *)malloc(nt_devmode->driverextra * sizeof(uint8))) == NULL)
			return False;
		memcpy(nt_devmode->private, devmode->private, nt_devmode->driverextra);
	}

	*pp_nt_devmode = nt_devmode;

	return True;
}

/********************************************************************
 * _spoolss_enddocprinter_internal.
 ********************************************************************/

static WERROR _spoolss_enddocprinter_internal(pipes_struct *p, POLICY_HND *handle)
{
	Printer_entry *Printer=find_printer_index_by_hnd(p, handle);
	
	if (!Printer) {
		DEBUG(0,("_spoolss_enddocprinter_internal: Invalid handle (%s)\n", OUR_HANDLE(handle)));
		return WERR_BADFID;
	}
	
	Printer->document_started=False;
	print_job_end(Printer->jobid,True);
	/* error codes unhandled so far ... */

	return WERR_OK;
}

/********************************************************************
 * api_spoolss_closeprinter
 ********************************************************************/

WERROR _spoolss_closeprinter(pipes_struct *p, SPOOL_Q_CLOSEPRINTER *q_u, SPOOL_R_CLOSEPRINTER *r_u)
{
	POLICY_HND *handle = &q_u->handle;

	Printer_entry *Printer=find_printer_index_by_hnd(p, handle);

	if (Printer && Printer->document_started)
		_spoolss_enddocprinter_internal(p, handle);          /* print job was not closed */

	memcpy(&r_u->handle, &q_u->handle, sizeof(r_u->handle));

	if (!close_printer_handle(p, handle))
		return WERR_BADFID;	
		
	return WERR_OK;
}

/********************************************************************
 * api_spoolss_deleteprinter

 ********************************************************************/

WERROR _spoolss_deleteprinter(pipes_struct *p, SPOOL_Q_DELETEPRINTER *q_u, SPOOL_R_DELETEPRINTER *r_u)
{
	POLICY_HND *handle = &q_u->handle;
	Printer_entry *Printer=find_printer_index_by_hnd(p, handle);
	WERROR result;

	if (Printer && Printer->document_started)
		_spoolss_enddocprinter_internal(p, handle);  /* print job was not closed */

	memcpy(&r_u->handle, &q_u->handle, sizeof(r_u->handle));

	result = delete_printer_handle(p, handle);

	if (W_ERROR_IS_OK(result)) {
		srv_spoolss_sendnotify(p, handle);
	}
		
	return result;
}

/*******************************************************************
 * static function to lookup the version id corresponding to an
 * long architecture string
 ******************************************************************/
static int get_version_id (char * arch)
{
	int i;
	struct table_node archi_table[]= {
 
	        {"Windows 4.0",          "WIN40",       0 },
	        {"Windows NT x86",       "W32X86",      2 },
	        {"Windows NT R4000",     "W32MIPS",     2 },	
	        {"Windows NT Alpha_AXP", "W32ALPHA",    2 },
	        {"Windows NT PowerPC",   "W32PPC",      2 },
	        {NULL,                   "",            -1 }
	};
 
	for (i=0; archi_table[i].long_archi != NULL; i++)
	{
		if (strcmp(arch, archi_table[i].long_archi) == 0)
			return (archi_table[i].version);
        }
	
	return -1;
}

/********************************************************************
 * _spoolss_deleteprinterdriver
 *
 * We currently delete the driver for the architecture only.
 * This can leave the driver for other archtectures.  However,
 * since every printer associates a "Windows NT x86" driver name
 * and we cannot delete that one while it is in use, **and** since
 * it is impossible to assign a driver to a Samba printer without
 * having the "Windows NT x86" driver installed,...
 * 
 * ....we should not get into trouble here.  
 *
 *                                                      --jerry
 ********************************************************************/

WERROR _spoolss_deleteprinterdriver(pipes_struct *p, SPOOL_Q_DELETEPRINTERDRIVER *q_u, 
				    SPOOL_R_DELETEPRINTERDRIVER *r_u)
{
	fstring				driver;
	fstring				arch;
	NT_PRINTER_DRIVER_INFO_LEVEL	info;
	int				version;
	 
	unistr2_to_ascii(driver, &q_u->driver, sizeof(driver)-1 );
	unistr2_to_ascii(arch,   &q_u->arch,   sizeof(arch)-1   );
	
	/* check that we have a valid driver name first */
	if ((version=get_version_id(arch)) == -1) {
		/* this is what NT returns */
		return WERR_INVALID_ENVIRONMENT;
	}
		
	ZERO_STRUCT(info);
	if (!W_ERROR_IS_OK(get_a_printer_driver(&info, 3, driver, arch, version))) {
		return WERR_UNKNOWN_PRINTER_DRIVER;
	}
	

	if (printer_driver_in_use(arch, driver))
	{
		return WERR_PRINTER_DRIVER_IN_USE;
	}

	return delete_printer_driver(info.info_3);	 
}


/********************************************************************
 GetPrinterData on a printer server Handle.
********************************************************************/
static BOOL getprinterdata_printer_server(TALLOC_CTX *ctx, fstring value, uint32 *type, uint8 **data, uint32 *needed, uint32 in_size)
{		
	int i;
	
	DEBUG(8,("getprinterdata_printer_server:%s\n", value));
		
	if (!strcmp(value, "BeepEnabled")) {
		*type = 0x4;
		if((*data = (uint8 *)talloc(ctx, 4*sizeof(uint8) )) == NULL)
			return False;
		SIVAL(*data, 0, 0x01);
		*needed = 0x4;			
		return True;
	}

	if (!strcmp(value, "EventLog")) {
		*type = 0x4;
		if((*data = (uint8 *)talloc(ctx, 4*sizeof(uint8) )) == NULL)
			return False;
		SIVAL(*data, 0, 0x1B);
		*needed = 0x4;			
		return True;
	}

	if (!strcmp(value, "NetPopup")) {
		*type = 0x4;
		if((*data = (uint8 *)talloc(ctx, 4*sizeof(uint8) )) == NULL)
			return False;
		SIVAL(*data, 0, 0x01);
		*needed = 0x4;
		return True;
	}

	if (!strcmp(value, "MajorVersion")) {
		*type = 0x4;
		if((*data = (uint8 *)talloc(ctx, 4*sizeof(uint8) )) == NULL)
			return False;
		SIVAL(*data, 0, 0x02);
		*needed = 0x4;
		return True;
	}

   if (!strcmp(value, "DefaultSpoolDirectory")) {
		pstring string="You are using a Samba server";
		*type = 0x1;			
		*needed = 2*(strlen(string)+1);		
		if((*data  = (uint8 *)talloc(ctx, ((*needed > in_size) ? *needed:in_size) *sizeof(uint8))) == NULL)
			return False;
		memset(*data, 0, (*needed > in_size) ? *needed:in_size);
		
		/* it's done by hand ready to go on the wire */
		for (i=0; i<strlen(string); i++) {
			(*data)[2*i]=string[i];
			(*data)[2*i+1]='\0';
		}			
		return True;
	}

	if (!strcmp(value, "Architecture")) {			
		pstring string="Windows NT x86";
		*type = 0x1;			
		*needed = 2*(strlen(string)+1);	
		if((*data  = (uint8 *)talloc(ctx, ((*needed > in_size) ? *needed:in_size) *sizeof(uint8))) == NULL)
			return False;
		memset(*data, 0, (*needed > in_size) ? *needed:in_size);
		for (i=0; i<strlen(string); i++) {
			(*data)[2*i]=string[i];
			(*data)[2*i+1]='\0';
		}			
		return True;
	}
	
	return False;
}

/********************************************************************
 GetPrinterData on a printer Handle.
********************************************************************/
static BOOL getprinterdata_printer(pipes_struct *p, TALLOC_CTX *ctx, POLICY_HND *handle,
				fstring value, uint32 *type,
                        	uint8 **data, uint32 *needed, uint32 in_size )
{
	NT_PRINTER_INFO_LEVEL *printer = NULL;
	int snum=0;
	uint8 *idata=NULL;
	uint32 len;
	Printer_entry *Printer = find_printer_index_by_hnd(p, handle);
	
	DEBUG(5,("getprinterdata_printer\n"));

	if (!Printer) {
		DEBUG(0,("getprinterdata_printer: Invalid handle (%s).\n", OUR_HANDLE(handle)));
		return False;
	}

	if(!get_printer_snum(p, handle, &snum))
		return False;

	if (!W_ERROR_IS_OK(get_a_printer(&printer, 2, lp_servicename(snum))))
		return False;

	if (!get_specific_param(*printer, 2, value, &idata, type, &len)) {
		free_a_printer(&printer, 2);
		return False;
	}

	free_a_printer(&printer, 2);

	DEBUG(5,("getprinterdata_printer:allocating %d\n", in_size));

	if (in_size) {
		if((*data  = (uint8 *)talloc(ctx, in_size *sizeof(uint8) )) == NULL) {
			return False;
		}

		memset(*data, 0, in_size *sizeof(uint8));
		/* copy the min(in_size, len) */
		memcpy(*data, idata, (len>in_size)?in_size:len *sizeof(uint8));
	} else {
		*data = NULL;
	}

	*needed = len;
	
	DEBUG(5,("getprinterdata_printer:copy done\n"));
			
	SAFE_FREE(idata);
	
	return True;
}	

/********************************************************************
 * spoolss_getprinterdata
 ********************************************************************/

WERROR _spoolss_getprinterdata(pipes_struct *p, SPOOL_Q_GETPRINTERDATA *q_u, SPOOL_R_GETPRINTERDATA *r_u)
{
	POLICY_HND *handle = &q_u->handle;
	UNISTR2 *valuename = &q_u->valuename;
	uint32 in_size = q_u->size;
	uint32 *type = &r_u->type;
	uint32 *out_size = &r_u->size;
	uint8 **data = &r_u->data;
	uint32 *needed = &r_u->needed;

	fstring value;
	BOOL found=False;
	Printer_entry *Printer = find_printer_index_by_hnd(p, handle);
	
	/*
	 * Reminder: when it's a string, the length is in BYTES
	 * even if UNICODE is negociated.
	 *
	 * JFM, 4/19/1999
	 */

	*out_size=in_size;

	/* in case of problem, return some default values */
	*needed=0;
	*type=0;
	
	DEBUG(4,("_spoolss_getprinterdata\n"));
	
	if (!Printer) {
		if((*data=(uint8 *)talloc_zero(p->mem_ctx, 4*sizeof(uint8))) == NULL)
			return WERR_NOMEM;
		DEBUG(0,("_spoolss_getprinterdata: Invalid handle (%s).\n", OUR_HANDLE(handle)));
		return WERR_BADFID;
	}
	
	unistr2_to_ascii(value, valuename, sizeof(value)-1);
	
	if (Printer->printer_type == PRINTER_HANDLE_IS_PRINTSERVER)
		found=getprinterdata_printer_server(p->mem_ctx, value, type, data, needed, *out_size);
	else
		found= getprinterdata_printer(p, p->mem_ctx, handle, value, type, data, needed, *out_size);

	if (found==False) {
		DEBUG(5, ("value not found, allocating %d\n", *out_size));
		/* reply this param doesn't exist */
		if (*out_size) {
			if((*data=(uint8 *)talloc_zero(p->mem_ctx, *out_size*sizeof(uint8))) == NULL)
				return WERR_NOMEM;
		} else {
			*data = NULL;
		}

		return WERR_INVALID_PARAM;
	}
	
	if (*needed > *out_size)
		return WERR_STATUS_MORE_ENTRIES;
	else 
		return WERR_OK;
}

/***************************************************************************
 connect to the client
****************************************************************************/
static BOOL srv_spoolss_replyopenprinter(char *printer, uint32 localprinter, uint32 type, POLICY_HND *handle)
{
	WERROR status;

	/*
	 * If it's the first connection, contact the client
	 * and connect to the IPC$ share anonumously
	 */
	if (smb_connections==0) {
		fstring unix_printer;

		fstrcpy(unix_printer, printer+2); /* the +2 is to strip the leading 2 backslashs */
		dos_to_unix(unix_printer, True);

		if(!spoolss_connect_to_client(&cli, unix_printer))
			return False;
		message_register(MSG_PRINTER_NOTIFY, srv_spoolss_receive_message);

	}

	smb_connections++;

	if(!cli_spoolss_reply_open_printer(&cli, printer, localprinter, type, &status, handle))
		return False;

	return True;
}

/********************************************************************
 * _spoolss_rffpcnex
 * ReplyFindFirstPrinterChangeNotifyEx
 *
 * jfmxxxx: before replying OK: status=0
 * should do a rpc call to the workstation asking ReplyOpenPrinter
 * have to code it, later.
 *
 * in fact ReplyOpenPrinter is the changenotify equivalent on the spoolss pipe
 * called from api_spoolss_rffpcnex
 ********************************************************************/

WERROR _spoolss_rffpcnex(pipes_struct *p, SPOOL_Q_RFFPCNEX *q_u, SPOOL_R_RFFPCNEX *r_u)
{
	POLICY_HND *handle = &q_u->handle;
	uint32 flags = q_u->flags;
	uint32 options = q_u->options;
	UNISTR2 *localmachine = &q_u->localmachine;
	uint32 printerlocal = q_u->printerlocal;
	SPOOL_NOTIFY_OPTION *option = q_u->option;

	/* store the notify value in the printer struct */

	Printer_entry *Printer=find_printer_index_by_hnd(p, handle);

	if (!Printer) {
		DEBUG(0,("_spoolss_rffpcnex: Invalid handle (%s).\n", OUR_HANDLE(handle)));
		return WERR_BADFID;
	}

	Printer->notify.flags=flags;
	Printer->notify.options=options;
	Printer->notify.printerlocal=printerlocal;

	if (Printer->notify.option)
		free_spool_notify_option(&Printer->notify.option);

	Printer->notify.option=dup_spool_notify_option(option);

	unistr2_to_ascii(Printer->notify.localmachine, localmachine, sizeof(Printer->notify.localmachine)-1);

	/* connect to the client machine and send a ReplyOpenPrinter */
	if(srv_spoolss_replyopenprinter(Printer->notify.localmachine,
					Printer->notify.printerlocal, 1,
					&Printer->notify.client_hnd))
		Printer->notify.client_connected=True;

	return WERR_OK;
}

/*******************************************************************
 * fill a notify_info_data with the servername
 ********************************************************************/

static void spoolss_notify_server_name(int snum, 
				       SPOOL_NOTIFY_INFO_DATA *data, 
				       print_queue_struct *queue,
				       NT_PRINTER_INFO_LEVEL *printer,
				       TALLOC_CTX *mem_ctx) 
{
	pstring temp_name, temp;
	uint32 len;

	slprintf(temp_name, sizeof(temp_name)-1, "\\\\%s", global_myname);

	len = (uint32)dos_PutUniCode(temp, temp_name, sizeof(temp) - 2, True);

	data->notify_data.data.length = len / 2 - 1;
	data->notify_data.data.string = (uint16 *)talloc(mem_ctx, len);

	if (!data->notify_data.data.string) {
		data->notify_data.data.length = 0;
		return;
	}
	
	memcpy(data->notify_data.data.string, temp, len);
}

/*******************************************************************
 * fill a notify_info_data with the printername (not including the servername).
 ********************************************************************/
static void spoolss_notify_printer_name(int snum, 
					SPOOL_NOTIFY_INFO_DATA *data, 
					print_queue_struct *queue,
					NT_PRINTER_INFO_LEVEL *printer,
					TALLOC_CTX *mem_ctx)
{
	pstring temp;
	uint32 len;
		
	/* the notify name should not contain the \\server\ part */
	char *p = strrchr(printer->info_2->printername, '\\');

	if (!p) {
		p = printer->info_2->printername;
	} else {
		p++;
	}

	len = (uint32)dos_PutUniCode(temp, p, sizeof(temp) - 2, True);

	data->notify_data.data.length = len / 2 - 1;
	data->notify_data.data.string = (uint16 *)talloc(mem_ctx, len);
	
	if (!data->notify_data.data.string) {
		data->notify_data.data.length = 0;
		return;
	}
	
	memcpy(data->notify_data.data.string, temp, len);
}

/*******************************************************************
 * fill a notify_info_data with the servicename
 ********************************************************************/
static void spoolss_notify_share_name(int snum, 
				      SPOOL_NOTIFY_INFO_DATA *data, 
				      print_queue_struct *queue,
				      NT_PRINTER_INFO_LEVEL *printer,
				      TALLOC_CTX *mem_ctx)
{
	pstring temp;
	uint32 len;

	len = (uint32)dos_PutUniCode(temp, lp_servicename(snum), 
				     sizeof(temp) - 2, True);

	data->notify_data.data.length = len / 2 - 1;
	data->notify_data.data.string = (uint16 *)talloc(mem_ctx, len);
	
	if (!data->notify_data.data.string) {
		data->notify_data.data.length = 0;
		return;
	}
	
	memcpy(data->notify_data.data.string, temp, len);
}

/*******************************************************************
 * fill a notify_info_data with the port name
 ********************************************************************/
static void spoolss_notify_port_name(int snum, 
				     SPOOL_NOTIFY_INFO_DATA *data, 
				     print_queue_struct *queue,
				     NT_PRINTER_INFO_LEVEL *printer,
				     TALLOC_CTX *mem_ctx)
{
	pstring temp;
	uint32 len;

	/* even if it's strange, that's consistant in all the code */

	len = (uint32)dos_PutUniCode(temp, printer->info_2->portname, 
				     sizeof(temp) - 2, True);

	data->notify_data.data.length = len / 2 - 1;
	data->notify_data.data.string = (uint16 *)talloc(mem_ctx, len);
	
	if (!data->notify_data.data.string) {
		data->notify_data.data.length = 0;
		return;
	}
	
	memcpy(data->notify_data.data.string, temp, len);
}

/*******************************************************************
 * fill a notify_info_data with the printername
 * jfmxxxx: it's incorrect, should be lp_printerdrivername()
 * but it doesn't exist, have to see what to do
 ********************************************************************/
static void spoolss_notify_driver_name(int snum, 
				       SPOOL_NOTIFY_INFO_DATA *data,
				       print_queue_struct *queue,
				       NT_PRINTER_INFO_LEVEL *printer,
				       TALLOC_CTX *mem_ctx)
{
	pstring temp;
	uint32 len;

	len = (uint32)dos_PutUniCode(temp, printer->info_2->drivername, 
				     sizeof(temp) - 2, True);

	data->notify_data.data.length = len / 2 - 1;
	data->notify_data.data.string = (uint16 *)talloc(mem_ctx, len);
	
	if (!data->notify_data.data.string) {
		data->notify_data.data.length = 0;
		return;
	}
	
	memcpy(data->notify_data.data.string, temp, len);
}

/*******************************************************************
 * fill a notify_info_data with the comment
 ********************************************************************/
static void spoolss_notify_comment(int snum, 
				   SPOOL_NOTIFY_INFO_DATA *data,
				   print_queue_struct *queue,
				   NT_PRINTER_INFO_LEVEL *printer,
				   TALLOC_CTX *mem_ctx)
{
	pstring temp;
	uint32 len;

	if (*printer->info_2->comment == '\0')
		len = (uint32)dos_PutUniCode(temp, lp_comment(snum), 
					     sizeof(temp) - 2, True);
	else
		len = (uint32)dos_PutUniCode(temp, printer->info_2->comment, 
					     sizeof(temp) - 2, True);

	data->notify_data.data.length = len / 2 - 1;
	data->notify_data.data.string = (uint16 *)talloc(mem_ctx, len);
	
	if (!data->notify_data.data.string) {
		data->notify_data.data.length = 0;
		return;
	}
	
	memcpy(data->notify_data.data.string, temp, len);
}

/*******************************************************************
 * fill a notify_info_data with the comment
 * jfm:xxxx incorrect, have to create a new smb.conf option
 * location = "Room 1, floor 2, building 3"
 ********************************************************************/
static void spoolss_notify_location(int snum, 
				    SPOOL_NOTIFY_INFO_DATA *data,
				    print_queue_struct *queue,
				    NT_PRINTER_INFO_LEVEL *printer,
				    TALLOC_CTX *mem_ctx)
{
	pstring temp;
	uint32 len;

	len = (uint32)dos_PutUniCode(temp, printer->info_2->location, 
				     sizeof(temp) - 2, True);

	data->notify_data.data.length = len / 2 - 1;
	data->notify_data.data.string = (uint16 *)talloc(mem_ctx, len);
	
	if (!data->notify_data.data.string) {
		data->notify_data.data.length = 0;
		return;
	}
	
	memcpy(data->notify_data.data.string, temp, len);
}

/*******************************************************************
 * fill a notify_info_data with the device mode
 * jfm:xxxx don't to it for know but that's a real problem !!!
 ********************************************************************/
static void spoolss_notify_devmode(int snum, 
				   SPOOL_NOTIFY_INFO_DATA *data,
				   print_queue_struct *queue,
				   NT_PRINTER_INFO_LEVEL *printer,
				   TALLOC_CTX *mem_ctx)
{
}

/*******************************************************************
 * fill a notify_info_data with the separator file name
 * jfm:xxxx just return no file could add an option to smb.conf
 * separator file = "separator.txt"
 ********************************************************************/
static void spoolss_notify_sepfile(int snum, 
				   SPOOL_NOTIFY_INFO_DATA *data, 
				   print_queue_struct *queue,
				   NT_PRINTER_INFO_LEVEL *printer,
				   TALLOC_CTX *mem_ctx)
{
	pstring temp;
	uint32 len;

	len = (uint32)dos_PutUniCode(temp, printer->info_2->sepfile, 
				     sizeof(temp) - 2, True);

	data->notify_data.data.length = len / 2 - 1;
	data->notify_data.data.string = (uint16 *)talloc(mem_ctx, len);
	
	if (!data->notify_data.data.string) {
		data->notify_data.data.length = 0;
		return;
	}
	
	memcpy(data->notify_data.data.string, temp, len);
}

/*******************************************************************
 * fill a notify_info_data with the print processor
 * jfm:xxxx return always winprint to indicate we don't do anything to it
 ********************************************************************/
static void spoolss_notify_print_processor(int snum, 
					   SPOOL_NOTIFY_INFO_DATA *data,
					   print_queue_struct *queue,
					   NT_PRINTER_INFO_LEVEL *printer,
					   TALLOC_CTX *mem_ctx)
{
	pstring temp;
	uint32 len;

	len = (uint32)dos_PutUniCode(temp, printer->info_2->printprocessor, 
				     sizeof(temp) - 2, True);

	data->notify_data.data.length = len / 2 - 1;
	data->notify_data.data.string = (uint16 *)talloc(mem_ctx, len);
	
	if (!data->notify_data.data.string) {
		data->notify_data.data.length = 0;
		return;
	}
	
	memcpy(data->notify_data.data.string, temp, len);
}

/*******************************************************************
 * fill a notify_info_data with the print processor options
 * jfm:xxxx send an empty string
 ********************************************************************/
static void spoolss_notify_parameters(int snum, 
				      SPOOL_NOTIFY_INFO_DATA *data,
				      print_queue_struct *queue,
				      NT_PRINTER_INFO_LEVEL *printer,
				      TALLOC_CTX *mem_ctx)
{
	pstring temp;
	uint32 len;

	len = (uint32)dos_PutUniCode(temp, printer->info_2->parameters, 
				     sizeof(temp) - 2, True);

	data->notify_data.data.length = len / 2 - 1;
	data->notify_data.data.string = (uint16 *)talloc(mem_ctx, len);
	
	if (!data->notify_data.data.string) {
		data->notify_data.data.length = 0;
		return;
	}
	
	memcpy(data->notify_data.data.string, temp, len);
}

/*******************************************************************
 * fill a notify_info_data with the data type
 * jfm:xxxx always send RAW as data type
 ********************************************************************/
static void spoolss_notify_datatype(int snum, 
				    SPOOL_NOTIFY_INFO_DATA *data,
				    print_queue_struct *queue,
				    NT_PRINTER_INFO_LEVEL *printer,
				    TALLOC_CTX *mem_ctx)
{
	pstring temp;
	uint32 len;

	len = (uint32)dos_PutUniCode(temp, printer->info_2->datatype, 
				     sizeof(pstring) - 2, True);

	data->notify_data.data.length = len / 2 - 1;
	data->notify_data.data.string = (uint16 *)talloc(mem_ctx, len);
	
	if (!data->notify_data.data.string) {
		data->notify_data.data.length = 0;
		return;
	}
	
	memcpy(data->notify_data.data.string, temp, len);
}

/*******************************************************************
 * fill a notify_info_data with the security descriptor
 * jfm:xxxx send an null pointer to say no security desc
 * have to implement security before !
 ********************************************************************/
static void spoolss_notify_security_desc(int snum, 
					 SPOOL_NOTIFY_INFO_DATA *data,
					 print_queue_struct *queue,
					 NT_PRINTER_INFO_LEVEL *printer,
					 TALLOC_CTX *mem_ctx)
{
	data->notify_data.data.length=0;
	data->notify_data.data.string = NULL;
}

/*******************************************************************
 * fill a notify_info_data with the attributes
 * jfm:xxxx a samba printer is always shared
 ********************************************************************/
static void spoolss_notify_attributes(int snum, 
				      SPOOL_NOTIFY_INFO_DATA *data,
				      print_queue_struct *queue,
				      NT_PRINTER_INFO_LEVEL *printer,
				      TALLOC_CTX *mem_ctx)
{
	data->notify_data.value[0] = printer->info_2->attributes;
	data->notify_data.value[1] = 0;
}

/*******************************************************************
 * fill a notify_info_data with the priority
 ********************************************************************/
static void spoolss_notify_priority(int snum, 
				    SPOOL_NOTIFY_INFO_DATA *data,
				    print_queue_struct *queue,
				    NT_PRINTER_INFO_LEVEL *printer,
				    TALLOC_CTX *mem_ctx)
{
	data->notify_data.value[0] = printer->info_2->priority;
	data->notify_data.value[1] = 0;
}

/*******************************************************************
 * fill a notify_info_data with the default priority
 ********************************************************************/
static void spoolss_notify_default_priority(int snum, 
					    SPOOL_NOTIFY_INFO_DATA *data,
					    print_queue_struct *queue,
					    NT_PRINTER_INFO_LEVEL *printer,
					    TALLOC_CTX *mem_ctx)
{
	data->notify_data.value[0] = printer->info_2->default_priority;
	data->notify_data.value[1] = 0;
}

/*******************************************************************
 * fill a notify_info_data with the start time
 ********************************************************************/
static void spoolss_notify_start_time(int snum, 
				      SPOOL_NOTIFY_INFO_DATA *data,
				      print_queue_struct *queue,
				      NT_PRINTER_INFO_LEVEL *printer,
				      TALLOC_CTX *mem_ctx)
{
	data->notify_data.value[0] = printer->info_2->starttime;
	data->notify_data.value[1] = 0;
}

/*******************************************************************
 * fill a notify_info_data with the until time
 ********************************************************************/
static void spoolss_notify_until_time(int snum, 
				      SPOOL_NOTIFY_INFO_DATA *data,
				      print_queue_struct *queue,
				      NT_PRINTER_INFO_LEVEL *printer,
				      TALLOC_CTX *mem_ctx)
{
	data->notify_data.value[0] = printer->info_2->untiltime;
	data->notify_data.value[1] = 0;
}

/*******************************************************************
 * fill a notify_info_data with the status
 ********************************************************************/
static void spoolss_notify_status(int snum, 
				  SPOOL_NOTIFY_INFO_DATA *data,
				  print_queue_struct *queue,
				  NT_PRINTER_INFO_LEVEL *printer,
				  TALLOC_CTX *mem_ctx)
{
	print_queue_struct *q=NULL;
	print_status_struct status;

	memset(&status, 0, sizeof(status));
	print_queue_status(snum, &q, &status);
	data->notify_data.value[0]=(uint32) status.status;
	data->notify_data.value[1] = 0;
	SAFE_FREE(q);
}

/*******************************************************************
 * fill a notify_info_data with the number of jobs queued
 ********************************************************************/
static void spoolss_notify_cjobs(int snum, 
				 SPOOL_NOTIFY_INFO_DATA *data,
				 print_queue_struct *queue,
				 NT_PRINTER_INFO_LEVEL *printer, 
				 TALLOC_CTX *mem_ctx)
{
	print_queue_struct *q=NULL;
	print_status_struct status;

	memset(&status, 0, sizeof(status));
	data->notify_data.value[0] = print_queue_status(snum, &q, &status);
	data->notify_data.value[1] = 0;
	SAFE_FREE(q);
}

/*******************************************************************
 * fill a notify_info_data with the average ppm
 ********************************************************************/
static void spoolss_notify_average_ppm(int snum, 
				       SPOOL_NOTIFY_INFO_DATA *data,
				       print_queue_struct *queue,
				       NT_PRINTER_INFO_LEVEL *printer,
				       TALLOC_CTX *mem_ctx)
{
	/* always respond 8 pages per minutes */
	/* a little hard ! */
	data->notify_data.value[0] = printer->info_2->averageppm;
	data->notify_data.value[1] = 0;
}

/*******************************************************************
 * fill a notify_info_data with username
 ********************************************************************/
static void spoolss_notify_username(int snum, 
				    SPOOL_NOTIFY_INFO_DATA *data,
				    print_queue_struct *queue,
				    NT_PRINTER_INFO_LEVEL *printer,
				    TALLOC_CTX *mem_ctx)
{
	pstring temp;
	uint32 len;

	len = (uint32)dos_PutUniCode(temp, queue->user, 
				     sizeof(temp) - 2, True);

	data->notify_data.data.length = len / 2 - 1;
	data->notify_data.data.string = (uint16 *)talloc(mem_ctx, len);
	
	if (!data->notify_data.data.string) {
		data->notify_data.data.length = 0;
		return;
	}
	
	memcpy(data->notify_data.data.string, temp, len);
}

/*******************************************************************
 * fill a notify_info_data with job status
 ********************************************************************/
static void spoolss_notify_job_status(int snum, 
				      SPOOL_NOTIFY_INFO_DATA *data,
				      print_queue_struct *queue,
				      NT_PRINTER_INFO_LEVEL *printer,
				      TALLOC_CTX *mem_ctx)
{
	data->notify_data.value[0]=nt_printj_status(queue->status);
	data->notify_data.value[1] = 0;
}

/*******************************************************************
 * fill a notify_info_data with job name
 ********************************************************************/
static void spoolss_notify_job_name(int snum, 
				    SPOOL_NOTIFY_INFO_DATA *data,
				    print_queue_struct *queue,
				    NT_PRINTER_INFO_LEVEL *printer,
				    TALLOC_CTX *mem_ctx)
{
	pstring temp;
	uint32 len;

	len = (uint32)dos_PutUniCode(temp, queue->file, sizeof(temp) - 2, 
				     True);

	data->notify_data.data.length = len / 2 - 1;
	data->notify_data.data.string = (uint16 *)talloc(mem_ctx, len);
	
	if (!data->notify_data.data.string) {
		data->notify_data.data.length = 0;
		return;
	}
	
	memcpy(data->notify_data.data.string, temp, len);
}

/*******************************************************************
 * fill a notify_info_data with job status
 ********************************************************************/
static void spoolss_notify_job_status_string(int snum, 
					     SPOOL_NOTIFY_INFO_DATA *data,
					     print_queue_struct *queue,
					     NT_PRINTER_INFO_LEVEL *printer, 
					     TALLOC_CTX *mem_ctx)
{
	/*
	 * Now we're returning job status codes we just return a "" here. JRA.
	 */

	char *p = "";
	pstring temp;
	uint32 len;

#if 0 /* NO LONGER NEEDED - JRA. 02/22/2001 */
	p = "unknown";

	switch (queue->status) {
	case LPQ_QUEUED:
		p = "Queued";
		break;
	case LPQ_PAUSED:
		p = "";    /* NT provides the paused string */
		break;
	case LPQ_SPOOLING:
		p = "Spooling";
		break;
	case LPQ_PRINTING:
		p = "Printing";
		break;
	}
#endif /* NO LONGER NEEDED. */

	len = (uint32)dos_PutUniCode(temp, p, sizeof(temp) - 2, True);

	data->notify_data.data.length = len / 2 - 1;
	data->notify_data.data.string = (uint16 *)talloc(mem_ctx, len);
	
	if (!data->notify_data.data.string) {
		data->notify_data.data.length = 0;
		return;
	}
	
	memcpy(data->notify_data.data.string, temp, len);
}

/*******************************************************************
 * fill a notify_info_data with job time
 ********************************************************************/
static void spoolss_notify_job_time(int snum, 
				    SPOOL_NOTIFY_INFO_DATA *data,
				    print_queue_struct *queue,
				    NT_PRINTER_INFO_LEVEL *printer,
				    TALLOC_CTX *mem_ctx)
{
	data->notify_data.value[0]=0x0;
	data->notify_data.value[1]=0;
}

/*******************************************************************
 * fill a notify_info_data with job size
 ********************************************************************/
static void spoolss_notify_job_size(int snum, 
				    SPOOL_NOTIFY_INFO_DATA *data,
				    print_queue_struct *queue,
				    NT_PRINTER_INFO_LEVEL *printer,
				    TALLOC_CTX *mem_ctx)
{
	data->notify_data.value[0]=queue->size;
	data->notify_data.value[1]=0;
}

/*******************************************************************
 * fill a notify_info_data with job position
 ********************************************************************/
static void spoolss_notify_job_position(int snum, 
					SPOOL_NOTIFY_INFO_DATA *data,
					print_queue_struct *queue,
					NT_PRINTER_INFO_LEVEL *printer,
					TALLOC_CTX *mem_ctx)
{
	data->notify_data.value[0]=queue->job;
	data->notify_data.value[1]=0;
}

/*******************************************************************
 * fill a notify_info_data with submitted time
 ********************************************************************/
static void spoolss_notify_submitted_time(int snum, 
					  SPOOL_NOTIFY_INFO_DATA *data,
					  print_queue_struct *queue,
					  NT_PRINTER_INFO_LEVEL *printer,
					  TALLOC_CTX *mem_ctx)
{
	struct tm *t;
	uint32 len;
	SYSTEMTIME st;

	t=gmtime(&queue->time);

	len = sizeof(SYSTEMTIME);

	data->notify_data.data.length = len/2 - 1;
	data->notify_data.data.string = (uint16 *)talloc(mem_ctx, len);

	if (!data->notify_data.data.string) {
		data->notify_data.data.length = 0;
		return;
	}
	
	make_systemtime(&st, t);
	memcpy(data->notify_data.data.string,&st,len);
}

#define END 65535

struct s_notify_info_data_table
{
	uint16 type;
	uint16 field;
	char *name;
	uint32 size;
	void (*fn) (int snum, SPOOL_NOTIFY_INFO_DATA *data,
		    print_queue_struct *queue,
		    NT_PRINTER_INFO_LEVEL *printer, TALLOC_CTX *mem_ctx);
};

struct s_notify_info_data_table notify_info_data_table[] =
{
{ PRINTER_NOTIFY_TYPE, PRINTER_NOTIFY_SERVER_NAME,         "PRINTER_NOTIFY_SERVER_NAME",         POINTER,   spoolss_notify_server_name },
{ PRINTER_NOTIFY_TYPE, PRINTER_NOTIFY_PRINTER_NAME,        "PRINTER_NOTIFY_PRINTER_NAME",        POINTER,   spoolss_notify_printer_name },
{ PRINTER_NOTIFY_TYPE, PRINTER_NOTIFY_SHARE_NAME,          "PRINTER_NOTIFY_SHARE_NAME",          POINTER,   spoolss_notify_share_name },
{ PRINTER_NOTIFY_TYPE, PRINTER_NOTIFY_PORT_NAME,           "PRINTER_NOTIFY_PORT_NAME",           POINTER,   spoolss_notify_port_name },
{ PRINTER_NOTIFY_TYPE, PRINTER_NOTIFY_DRIVER_NAME,         "PRINTER_NOTIFY_DRIVER_NAME",         POINTER,   spoolss_notify_driver_name },
{ PRINTER_NOTIFY_TYPE, PRINTER_NOTIFY_COMMENT,             "PRINTER_NOTIFY_COMMENT",             POINTER,   spoolss_notify_comment },
{ PRINTER_NOTIFY_TYPE, PRINTER_NOTIFY_LOCATION,            "PRINTER_NOTIFY_LOCATION",            POINTER,   spoolss_notify_location },
{ PRINTER_NOTIFY_TYPE, PRINTER_NOTIFY_DEVMODE,             "PRINTER_NOTIFY_DEVMODE",             POINTER,   spoolss_notify_devmode },
{ PRINTER_NOTIFY_TYPE, PRINTER_NOTIFY_SEPFILE,             "PRINTER_NOTIFY_SEPFILE",             POINTER,   spoolss_notify_sepfile },
{ PRINTER_NOTIFY_TYPE, PRINTER_NOTIFY_PRINT_PROCESSOR,     "PRINTER_NOTIFY_PRINT_PROCESSOR",     POINTER,   spoolss_notify_print_processor },
{ PRINTER_NOTIFY_TYPE, PRINTER_NOTIFY_PARAMETERS,          "PRINTER_NOTIFY_PARAMETERS",          POINTER,   spoolss_notify_parameters },
{ PRINTER_NOTIFY_TYPE, PRINTER_NOTIFY_DATATYPE,            "PRINTER_NOTIFY_DATATYPE",            POINTER,   spoolss_notify_datatype },
{ PRINTER_NOTIFY_TYPE, PRINTER_NOTIFY_SECURITY_DESCRIPTOR, "PRINTER_NOTIFY_SECURITY_DESCRIPTOR", POINTER,   spoolss_notify_security_desc },
{ PRINTER_NOTIFY_TYPE, PRINTER_NOTIFY_ATTRIBUTES,          "PRINTER_NOTIFY_ATTRIBUTES",          ONE_VALUE, spoolss_notify_attributes },
{ PRINTER_NOTIFY_TYPE, PRINTER_NOTIFY_PRIORITY,            "PRINTER_NOTIFY_PRIORITY",            ONE_VALUE, spoolss_notify_priority },
{ PRINTER_NOTIFY_TYPE, PRINTER_NOTIFY_DEFAULT_PRIORITY,    "PRINTER_NOTIFY_DEFAULT_PRIORITY",    ONE_VALUE, spoolss_notify_default_priority },
{ PRINTER_NOTIFY_TYPE, PRINTER_NOTIFY_START_TIME,          "PRINTER_NOTIFY_START_TIME",          ONE_VALUE, spoolss_notify_start_time },
{ PRINTER_NOTIFY_TYPE, PRINTER_NOTIFY_UNTIL_TIME,          "PRINTER_NOTIFY_UNTIL_TIME",          ONE_VALUE, spoolss_notify_until_time },
{ PRINTER_NOTIFY_TYPE, PRINTER_NOTIFY_STATUS,              "PRINTER_NOTIFY_STATUS",              ONE_VALUE, spoolss_notify_status },
{ PRINTER_NOTIFY_TYPE, PRINTER_NOTIFY_STATUS_STRING,       "PRINTER_NOTIFY_STATUS_STRING",       POINTER,   NULL },
{ PRINTER_NOTIFY_TYPE, PRINTER_NOTIFY_CJOBS,               "PRINTER_NOTIFY_CJOBS",               ONE_VALUE, spoolss_notify_cjobs },
{ PRINTER_NOTIFY_TYPE, PRINTER_NOTIFY_AVERAGE_PPM,         "PRINTER_NOTIFY_AVERAGE_PPM",         ONE_VALUE, spoolss_notify_average_ppm },
{ PRINTER_NOTIFY_TYPE, PRINTER_NOTIFY_TOTAL_PAGES,         "PRINTER_NOTIFY_TOTAL_PAGES",         POINTER,   NULL },
{ PRINTER_NOTIFY_TYPE, PRINTER_NOTIFY_PAGES_PRINTED,       "PRINTER_NOTIFY_PAGES_PRINTED",       POINTER,   NULL },
{ PRINTER_NOTIFY_TYPE, PRINTER_NOTIFY_TOTAL_BYTES,         "PRINTER_NOTIFY_TOTAL_BYTES",         POINTER,   NULL },
{ PRINTER_NOTIFY_TYPE, PRINTER_NOTIFY_BYTES_PRINTED,       "PRINTER_NOTIFY_BYTES_PRINTED",       POINTER,   NULL },
{ JOB_NOTIFY_TYPE,     JOB_NOTIFY_PRINTER_NAME,            "JOB_NOTIFY_PRINTER_NAME",            POINTER,   spoolss_notify_printer_name },
{ JOB_NOTIFY_TYPE,     JOB_NOTIFY_MACHINE_NAME,            "JOB_NOTIFY_MACHINE_NAME",            POINTER,   spoolss_notify_server_name },
{ JOB_NOTIFY_TYPE,     JOB_NOTIFY_PORT_NAME,               "JOB_NOTIFY_PORT_NAME",               POINTER,   spoolss_notify_port_name },
{ JOB_NOTIFY_TYPE,     JOB_NOTIFY_USER_NAME,               "JOB_NOTIFY_USER_NAME",               POINTER,   spoolss_notify_username },
{ JOB_NOTIFY_TYPE,     JOB_NOTIFY_NOTIFY_NAME,             "JOB_NOTIFY_NOTIFY_NAME",             POINTER,   spoolss_notify_username },
{ JOB_NOTIFY_TYPE,     JOB_NOTIFY_DATATYPE,                "JOB_NOTIFY_DATATYPE",                POINTER,   spoolss_notify_datatype },
{ JOB_NOTIFY_TYPE,     JOB_NOTIFY_PRINT_PROCESSOR,         "JOB_NOTIFY_PRINT_PROCESSOR",         POINTER,   spoolss_notify_print_processor },
{ JOB_NOTIFY_TYPE,     JOB_NOTIFY_PARAMETERS,              "JOB_NOTIFY_PARAMETERS",              POINTER,   spoolss_notify_parameters },
{ JOB_NOTIFY_TYPE,     JOB_NOTIFY_DRIVER_NAME,             "JOB_NOTIFY_DRIVER_NAME",             POINTER,   spoolss_notify_driver_name },
{ JOB_NOTIFY_TYPE,     JOB_NOTIFY_DEVMODE,                 "JOB_NOTIFY_DEVMODE",                 POINTER,   spoolss_notify_devmode },
{ JOB_NOTIFY_TYPE,     JOB_NOTIFY_STATUS,                  "JOB_NOTIFY_STATUS",                  ONE_VALUE, spoolss_notify_job_status },
{ JOB_NOTIFY_TYPE,     JOB_NOTIFY_STATUS_STRING,           "JOB_NOTIFY_STATUS_STRING",           POINTER,   spoolss_notify_job_status_string },
{ JOB_NOTIFY_TYPE,     JOB_NOTIFY_SECURITY_DESCRIPTOR,     "JOB_NOTIFY_SECURITY_DESCRIPTOR",     POINTER,   NULL },
{ JOB_NOTIFY_TYPE,     JOB_NOTIFY_DOCUMENT,                "JOB_NOTIFY_DOCUMENT",                POINTER,   spoolss_notify_job_name },
{ JOB_NOTIFY_TYPE,     JOB_NOTIFY_PRIORITY,                "JOB_NOTIFY_PRIORITY",                ONE_VALUE, spoolss_notify_priority },
{ JOB_NOTIFY_TYPE,     JOB_NOTIFY_POSITION,                "JOB_NOTIFY_POSITION",                ONE_VALUE, spoolss_notify_job_position },
{ JOB_NOTIFY_TYPE,     JOB_NOTIFY_SUBMITTED,               "JOB_NOTIFY_SUBMITTED",               POINTER,   spoolss_notify_submitted_time },
{ JOB_NOTIFY_TYPE,     JOB_NOTIFY_START_TIME,              "JOB_NOTIFY_START_TIME",              ONE_VALUE, spoolss_notify_start_time },
{ JOB_NOTIFY_TYPE,     JOB_NOTIFY_UNTIL_TIME,              "JOB_NOTIFY_UNTIL_TIME",              ONE_VALUE, spoolss_notify_until_time },
{ JOB_NOTIFY_TYPE,     JOB_NOTIFY_TIME,                    "JOB_NOTIFY_TIME",                    ONE_VALUE, spoolss_notify_job_time },
{ JOB_NOTIFY_TYPE,     JOB_NOTIFY_TOTAL_PAGES,             "JOB_NOTIFY_TOTAL_PAGES",             ONE_VALUE, NULL },
{ JOB_NOTIFY_TYPE,     JOB_NOTIFY_PAGES_PRINTED,           "JOB_NOTIFY_PAGES_PRINTED",           ONE_VALUE, NULL },
{ JOB_NOTIFY_TYPE,     JOB_NOTIFY_TOTAL_BYTES,             "JOB_NOTIFY_TOTAL_BYTES",             ONE_VALUE, spoolss_notify_job_size },
{ JOB_NOTIFY_TYPE,     JOB_NOTIFY_BYTES_PRINTED,           "JOB_NOTIFY_BYTES_PRINTED",           ONE_VALUE, NULL },
{ END,                 END,                                "",                                   END,       NULL }
};

/*******************************************************************
return the size of info_data structure
********************************************************************/
static uint32 size_of_notify_info_data(uint16 type, uint16 field)
{
	int i=0;

	while (notify_info_data_table[i].type != END)
	{
		if ( (notify_info_data_table[i].type == type ) &&
		     (notify_info_data_table[i].field == field ) )
		{
			return (notify_info_data_table[i].size);
		}
		i++;
	}
	return (65535);
}

/*******************************************************************
return the type of notify_info_data
********************************************************************/
static BOOL type_of_notify_info_data(uint16 type, uint16 field)
{
	int i=0;

	while (notify_info_data_table[i].type != END)
	{
		if ( (notify_info_data_table[i].type == type ) &&
		     (notify_info_data_table[i].field == field ) )
		{
			if (notify_info_data_table[i].size == POINTER)
			{
				return (False);
			}
			else
			{
				return (True);
			}
		}
		i++;
	}
	return (False);
}

/****************************************************************************
****************************************************************************/
static int search_notify(uint16 type, uint16 field, int *value)
{	
	int j;
	BOOL found;

	for (j=0, found=False; found==False && notify_info_data_table[j].type != END ; j++)
	{
		if ( (notify_info_data_table[j].type  == type  ) &&
		     (notify_info_data_table[j].field == field ) )
			found=True;
	}
	*value=--j;

	if ( found && (notify_info_data_table[j].fn != NULL) )
		return True;
	else
		return False;	
}

/****************************************************************************
****************************************************************************/
static void construct_info_data(SPOOL_NOTIFY_INFO_DATA *info_data, uint16 type, uint16 field, int id)
{
	info_data->type     = type;
	info_data->field    = field;
	info_data->reserved = 0;
	info_data->id       = id;
	info_data->size     = size_of_notify_info_data(type, field);
	info_data->enc_type = type_of_notify_info_data(type, field);
}


/*******************************************************************
 *
 * fill a notify_info struct with info asked
 *
 ********************************************************************/
static BOOL construct_notify_printer_info(SPOOL_NOTIFY_INFO *info, int
					  snum, SPOOL_NOTIFY_OPTION_TYPE
					  *option_type, uint32 id,
					  TALLOC_CTX *mem_ctx) 
{
	int field_num,j;
	uint16 type;
	uint16 field;

	SPOOL_NOTIFY_INFO_DATA *current_data, *tid;
	NT_PRINTER_INFO_LEVEL *printer = NULL;
	print_queue_struct *queue=NULL;

	type=option_type->type;

	DEBUG(4,("construct_notify_printer_info: Notify type: [%s], number of notify info: [%d] on printer: [%s]\n",
		(option_type->type==PRINTER_NOTIFY_TYPE?"PRINTER_NOTIFY_TYPE":"JOB_NOTIFY_TYPE"),
		option_type->count, lp_servicename(snum)));
	
	if (!W_ERROR_IS_OK(get_a_printer(&printer, 2, lp_servicename(snum))))
		return False;

	for(field_num=0; field_num<option_type->count; field_num++) {
		field = option_type->fields[field_num];
		DEBUG(4,("construct_notify_printer_info: notify [%d]: type [%x], field [%x]\n", field_num, type, field));

		if (!search_notify(type, field, &j) )
			continue;

		if((tid=(SPOOL_NOTIFY_INFO_DATA *)Realloc(info->data, (info->count+1)*sizeof(SPOOL_NOTIFY_INFO_DATA))) == NULL) {
			DEBUG(0,("construct_notify_printer_info: failed to enlarge buffer info->data!\n"));
			return False;
		}
		else info->data = tid;

		current_data=&info->data[info->count];

		construct_info_data(current_data, type, field, id);		

		DEBUG(10,("construct_notify_printer_info: calling [%s]  snum=%d  printername=[%s])\n",
				notify_info_data_table[j].name, snum, printer->info_2->printername ));

		notify_info_data_table[j].fn(snum, current_data, queue,
					     printer, mem_ctx);

		info->count++;
	}

	free_a_printer(&printer, 2);
	return True;
}

/*******************************************************************
 *
 * fill a notify_info struct with info asked
 *
 ********************************************************************/
static BOOL construct_notify_jobs_info(print_queue_struct *queue,
				       SPOOL_NOTIFY_INFO *info,
				       NT_PRINTER_INFO_LEVEL *printer,
				       int snum, SPOOL_NOTIFY_OPTION_TYPE
				       *option_type, uint32 id,
				       TALLOC_CTX *mem_ctx) 
{
	int field_num,j;
	uint16 type;
	uint16 field;

	SPOOL_NOTIFY_INFO_DATA *current_data, *tid;
	
	DEBUG(4,("construct_notify_jobs_info\n"));
	
	type = option_type->type;

	DEBUGADD(4,("Notify type: [%s], number of notify info: [%d]\n",
		(option_type->type==PRINTER_NOTIFY_TYPE?"PRINTER_NOTIFY_TYPE":"JOB_NOTIFY_TYPE"),
		option_type->count));

	for(field_num=0; field_num<option_type->count; field_num++) {
		field = option_type->fields[field_num];

		if (!search_notify(type, field, &j) )
			continue;

		if((tid=Realloc(info->data, (info->count+1)*sizeof(SPOOL_NOTIFY_INFO_DATA))) == NULL) {
			DEBUG(0,("construct_notify_jobs_info: failed to enlarg buffer info->data!\n"));
			return False;
		}
		else info->data = tid;

		current_data=&(info->data[info->count]);

		construct_info_data(current_data, type, field, id);
		notify_info_data_table[j].fn(snum, current_data, queue,
					     printer, mem_ctx);
		info->count++;
	}

	return True;
}

/*
 * JFM: The enumeration is not that simple, it's even non obvious.
 *
 * let's take an example: I want to monitor the PRINTER SERVER for
 * the printer's name and the number of jobs currently queued.
 * So in the NOTIFY_OPTION, I have one NOTIFY_OPTION_TYPE structure.
 * Its type is PRINTER_NOTIFY_TYPE and it has 2 fields NAME and CJOBS.
 *
 * I have 3 printers on the back of my server.
 *
 * Now the response is a NOTIFY_INFO structure, with 6 NOTIFY_INFO_DATA
 * structures.
 *   Number	Data			Id
 *	1	printer 1 name		1
 *	2	printer 1 cjob		1
 *	3	printer 2 name		2
 *	4	printer 2 cjob		2
 *	5	printer 3 name		3
 *	6	printer 3 name		3
 *
 * that's the print server case, the printer case is even worse.
 */

/*******************************************************************
 *
 * enumerate all printers on the printserver
 * fill a notify_info struct with info asked
 *
 ********************************************************************/

static WERROR printserver_notify_info(pipes_struct *p, POLICY_HND *hnd, 
				      SPOOL_NOTIFY_INFO *info,
				      TALLOC_CTX *mem_ctx)
{
	int snum;
	Printer_entry *Printer=find_printer_index_by_hnd(p, hnd);
	int n_services=lp_numservices();
	int i;
	uint32 id;
	SPOOL_NOTIFY_OPTION *option;
	SPOOL_NOTIFY_OPTION_TYPE *option_type;

	DEBUG(4,("printserver_notify_info\n"));
	
	option=Printer->notify.option;
	id=1;
	info->version=2;
	info->data=NULL;
	info->count=0;

	for (i=0; i<option->count; i++) {
		option_type=&(option->ctr.type[i]);
		
		if (option_type->type!=PRINTER_NOTIFY_TYPE)
			continue;
		
		for (snum=0; snum<n_services; snum++)
			if ( lp_browseable(snum) && lp_snum_ok(snum) && lp_print_ok(snum) )
				if (construct_notify_printer_info
				    (info, snum, option_type, id, mem_ctx))
					id++;
	}
			
	/*
	 * Debugging information, don't delete.
	 */
	/*
	DEBUG(1,("dumping the NOTIFY_INFO\n"));
	DEBUGADD(1,("info->version:[%d], info->flags:[%d], info->count:[%d]\n", info->version, info->flags, info->count));
	DEBUGADD(1,("num\ttype\tfield\tres\tid\tsize\tenc_type\n"));
	
	for (i=0; i<info->count; i++) {
		DEBUGADD(1,("[%d]\t[%d]\t[%d]\t[%d]\t[%d]\t[%d]\t[%d]\n",
		i, info->data[i].type, info->data[i].field, info->data[i].reserved,
		info->data[i].id, info->data[i].size, info->data[i].enc_type));
	}
	*/
	
	return WERR_OK;
}

/*******************************************************************
 *
 * fill a notify_info struct with info asked
 *
 ********************************************************************/
static WERROR printer_notify_info(pipes_struct *p, POLICY_HND *hnd, SPOOL_NOTIFY_INFO *info,
				  TALLOC_CTX *mem_ctx)
{
	int snum;
	Printer_entry *Printer=find_printer_index_by_hnd(p, hnd);
	int i;
	uint32 id;
	SPOOL_NOTIFY_OPTION *option;
	SPOOL_NOTIFY_OPTION_TYPE *option_type;
	int count,j;
	print_queue_struct *queue=NULL;
	print_status_struct status;
	
	DEBUG(4,("printer_notify_info\n"));

	option=Printer->notify.option;
	id=0xffffffff;
	info->version=2;
	info->data=NULL;
	info->count=0;

	get_printer_snum(p, hnd, &snum);

	for (i=0; i<option->count; i++) {
		option_type=&option->ctr.type[i];
		
		switch ( option_type->type ) {
		case PRINTER_NOTIFY_TYPE:
			if(construct_notify_printer_info(info, snum, 
							 option_type, id,
							 mem_ctx))  
				id--;
			break;
			
		case JOB_NOTIFY_TYPE: {
			NT_PRINTER_INFO_LEVEL *printer = NULL;

			memset(&status, 0, sizeof(status));	
			count = print_queue_status(snum, &queue, &status);

			if (!W_ERROR_IS_OK(get_a_printer(&printer, 2, 
							 lp_servicename(snum))))
				goto done;

			for (j=0; j<count; j++) {
				construct_notify_jobs_info(&queue[j], info,
							   printer, snum,
							   option_type,
							   queue[j].job,
							   mem_ctx); 
			}

			free_a_printer(&printer, 2);
			
		done:
			SAFE_FREE(queue);
			break;
		}
		}
	}
	
	/*
	 * Debugging information, don't delete.
	 */
	/*
	DEBUG(1,("dumping the NOTIFY_INFO\n"));
	DEBUGADD(1,("info->version:[%d], info->flags:[%d], info->count:[%d]\n", info->version, info->flags, info->count));
	DEBUGADD(1,("num\ttype\tfield\tres\tid\tsize\tenc_type\n"));
	
	for (i=0; i<info->count; i++) {
		DEBUGADD(1,("[%d]\t[%d]\t[%d]\t[%d]\t[%d]\t[%d]\t[%d]\n",
		i, info->data[i].type, info->data[i].field, info->data[i].reserved,
		info->data[i].id, info->data[i].size, info->data[i].enc_type));
	}
	*/
	return WERR_OK;
}

/********************************************************************
 * spoolss_rfnpcnex
 ********************************************************************/

WERROR _spoolss_rfnpcnex( pipes_struct *p, SPOOL_Q_RFNPCNEX *q_u, SPOOL_R_RFNPCNEX *r_u)
{
	POLICY_HND *handle = &q_u->handle;
/*	uint32 change = q_u->change; - notused. */
/*	SPOOL_NOTIFY_OPTION *option = q_u->option; - notused. */
	SPOOL_NOTIFY_INFO *info = &r_u->info;

	Printer_entry *Printer=find_printer_index_by_hnd(p, handle);
	WERROR result = WERR_BADFID;

	/* we always have a NOTIFY_INFO struct */
	r_u->info_ptr=0x1;

	if (!Printer) {
		DEBUG(0,("_spoolss_rfnpcnex: Invalid handle (%s).\n",
			 OUR_HANDLE(handle)));
		goto done;
	}

	DEBUG(4,("Printer type %x\n",Printer->printer_type));

	/* jfm: the change value isn't used right now.
	 * 	we will honour it when
	 *	a) we'll be able to send notification to the client
	 *	b) we'll have a way to communicate between the spoolss process.
	 *
	 *	same thing for option->flags
	 *	I should check for PRINTER_NOTIFY_OPTIONS_REFRESH but as
	 *	I don't have a global notification system, I'm sending back all the
	 *	informations even when _NOTHING_ has changed.
	 */

	/* just ignore the SPOOL_NOTIFY_OPTION */
	
	switch (Printer->printer_type) {
		case PRINTER_HANDLE_IS_PRINTSERVER:
			result = printserver_notify_info(p, handle, info, p->mem_ctx);
			break;
			
		case PRINTER_HANDLE_IS_PRINTER:
			result = printer_notify_info(p, handle, info, p->mem_ctx);
			break;
	}
	
 done:
	return result;
}

/********************************************************************
 * construct_printer_info_0
 * fill a printer_info_0 struct
 ********************************************************************/
static BOOL construct_printer_info_0(PRINTER_INFO_0 *printer, int snum)
{
	pstring chaine;
	int count;
	NT_PRINTER_INFO_LEVEL *ntprinter = NULL;
	counter_printer_0 *session_counter;
	uint32 global_counter;
	struct tm *t;
	time_t setuptime;

	print_queue_struct *queue=NULL;
	print_status_struct status;
	
	memset(&status, 0, sizeof(status));	

	if (!W_ERROR_IS_OK(get_a_printer(&ntprinter, 2, lp_servicename(snum))))
		return False;

	count = print_queue_status(snum, &queue, &status);

	/* check if we already have a counter for this printer */	
	session_counter = (counter_printer_0 *)ubi_dlFirst(&counter_list);

	for(; session_counter; session_counter = (counter_printer_0 *)ubi_dlNext(session_counter)) {
		if (session_counter->snum == snum)
			break;
	}

	/* it's the first time, add it to the list */
	if (session_counter==NULL) {
		if((session_counter=(counter_printer_0 *)malloc(sizeof(counter_printer_0))) == NULL) {
			free_a_printer(&ntprinter, 2);
			return False;
		}
		ZERO_STRUCTP(session_counter);
		session_counter->snum=snum;
		session_counter->counter=0;
		ubi_dlAddHead( &counter_list, (ubi_dlNode *)session_counter);
	}
	
	/* increment it */
	session_counter->counter++;
	
	/* JFM:
	 * the global_counter should be stored in a TDB as it's common to all the clients
	 * and should be zeroed on samba startup
	 */
	global_counter=session_counter->counter;
	
	pstrcpy(chaine,ntprinter->info_2->printername);

	init_unistr(&printer->printername, chaine);
	
	slprintf(chaine,sizeof(chaine)-1,"\\\\%s", global_myname);
	init_unistr(&printer->servername, chaine);
	
	printer->cjobs = count;
	printer->total_jobs = 0;
	printer->total_bytes = 0;

	setuptime = (time_t)ntprinter->info_2->setuptime;
	t=gmtime(&setuptime);

	printer->year = t->tm_year+1900;
	printer->month = t->tm_mon+1;
	printer->dayofweek = t->tm_wday;
	printer->day = t->tm_mday;
	printer->hour = t->tm_hour;
	printer->minute = t->tm_min;
	printer->second = t->tm_sec;
	printer->milliseconds = 0;

	printer->global_counter = global_counter;
	printer->total_pages = 0;
	printer->major_version = 0x0004; 	/* NT 4 */
	printer->build_version = 0x0565; 	/* build 1381 */
	printer->unknown7 = 0x1;
	printer->unknown8 = 0x0;
	printer->unknown9 = 0x0;
	printer->session_counter = session_counter->counter;
	printer->unknown11 = 0x0;
	printer->printer_errors = 0x0;		/* number of print failure */
	printer->unknown13 = 0x0;
	printer->unknown14 = 0x1;
	printer->unknown15 = 0x024a;		/* 586 Pentium ? */
	printer->unknown16 =  0x0;
	printer->change_id = ntprinter->info_2->changeid; /* ChangeID in milliseconds*/
	printer->unknown18 =  0x0;
	printer->status = nt_printq_status(status.status);
	printer->unknown20 =  0x0;
	printer->c_setprinter = ntprinter->info_2->c_setprinter; /* how many times setprinter has been called */
	printer->unknown22 = 0x0;
	printer->unknown23 = 0x6; 		/* 6  ???*/
	printer->unknown24 = 0; 		/* unknown 24 to 26 are always 0 */
	printer->unknown25 = 0;
	printer->unknown26 = 0;
	printer->unknown27 = 0;
	printer->unknown28 = 0;
	printer->unknown29 = 0;
	
	SAFE_FREE(queue);
	free_a_printer(&ntprinter,2);
	return (True);	
}

/********************************************************************
 * construct_printer_info_1
 * fill a printer_info_1 struct
 ********************************************************************/
static BOOL construct_printer_info_1(uint32 flags, PRINTER_INFO_1 *printer, int snum)
{
	pstring chaine;
	pstring chaine2;
	NT_PRINTER_INFO_LEVEL *ntprinter = NULL;

	if (!W_ERROR_IS_OK(get_a_printer(&ntprinter, 2, lp_servicename(snum))))
		return False;

	printer->flags=flags;

	if (*ntprinter->info_2->comment == '\0') {
		init_unistr(&printer->comment, lp_comment(snum));
		slprintf(chaine,sizeof(chaine)-1,"%s%s,%s,%s",global_myname, ntprinter->info_2->printername,
			ntprinter->info_2->drivername, lp_comment(snum));
	}
	else {
		init_unistr(&printer->comment, ntprinter->info_2->comment); /* saved comment. */
		slprintf(chaine,sizeof(chaine)-1,"%s%s,%s,%s",global_myname, ntprinter->info_2->printername,
			ntprinter->info_2->drivername, ntprinter->info_2->comment);
	}
		
	slprintf(chaine2,sizeof(chaine)-1,"%s", ntprinter->info_2->printername);

	init_unistr(&printer->description, chaine);
	init_unistr(&printer->name, chaine2);	
	
	free_a_printer(&ntprinter,2);

	return True;
}

/****************************************************************************
 Free a DEVMODE struct.
****************************************************************************/

static void free_dev_mode(DEVICEMODE *dev)
{
	if (dev == NULL)
		return;

		SAFE_FREE(dev->private);
	SAFE_FREE(dev);	
}

/****************************************************************************
 Create a DEVMODE struct. Returns malloced memory.
****************************************************************************/

static DEVICEMODE *construct_dev_mode(int snum)
{
	char adevice[32];
	char aform[32];
	NT_PRINTER_INFO_LEVEL *printer = NULL;
	NT_DEVICEMODE *ntdevmode = NULL;
	DEVICEMODE *devmode = NULL;

	DEBUG(7,("construct_dev_mode\n"));
	
	DEBUGADD(8,("getting printer characteristics\n"));

	if ((devmode = (DEVICEMODE *)malloc(sizeof(DEVICEMODE))) == NULL) {
		DEBUG(0,("construct_dev_mode: malloc fail.\n"));
		return NULL;
	}

	ZERO_STRUCTP(devmode);	

	if (!W_ERROR_IS_OK(get_a_printer(&printer, 2, lp_servicename(snum))))
		goto fail;

	if (printer->info_2->devmode)
		ntdevmode = dup_nt_devicemode(printer->info_2->devmode);

	if (ntdevmode == NULL)
		goto fail;

	DEBUGADD(8,("loading DEVICEMODE\n"));

	slprintf(adevice, sizeof(adevice)-1, printer->info_2->printername);
	init_unistr(&devmode->devicename, adevice);

	slprintf(aform, sizeof(aform)-1, ntdevmode->formname);
	init_unistr(&devmode->formname, aform);

	devmode->specversion      = ntdevmode->specversion;
	devmode->driverversion    = ntdevmode->driverversion;
	devmode->size             = ntdevmode->size;
	devmode->driverextra      = ntdevmode->driverextra;
	devmode->fields           = ntdevmode->fields;
				
	devmode->orientation      = ntdevmode->orientation;	
	devmode->papersize        = ntdevmode->papersize;
	devmode->paperlength      = ntdevmode->paperlength;
	devmode->paperwidth       = ntdevmode->paperwidth;
	devmode->scale            = ntdevmode->scale;
	devmode->copies           = ntdevmode->copies;
	devmode->defaultsource    = ntdevmode->defaultsource;
	devmode->printquality     = ntdevmode->printquality;
	devmode->color            = ntdevmode->color;
	devmode->duplex           = ntdevmode->duplex;
	devmode->yresolution      = ntdevmode->yresolution;
	devmode->ttoption         = ntdevmode->ttoption;
	devmode->collate          = ntdevmode->collate;
	devmode->icmmethod        = ntdevmode->icmmethod;
	devmode->icmintent        = ntdevmode->icmintent;
	devmode->mediatype        = ntdevmode->mediatype;
	devmode->dithertype       = ntdevmode->dithertype;

	if (ntdevmode->private != NULL) {
		if ((devmode->private=(uint8 *)memdup(ntdevmode->private, ntdevmode->driverextra)) == NULL)
			goto fail;
	}

	free_nt_devicemode(&ntdevmode);
	free_a_printer(&printer,2);

	return devmode;

  fail:

	if (ntdevmode)
		free_nt_devicemode(&ntdevmode);
	if (printer)
		free_a_printer(&printer,2);
	free_dev_mode(devmode);

	return NULL;
}

/********************************************************************
 * construct_printer_info_2
 * fill a printer_info_2 struct
 ********************************************************************/

static BOOL construct_printer_info_2(PRINTER_INFO_2 *printer, int snum)
{
	int count;
	NT_PRINTER_INFO_LEVEL *ntprinter = NULL;

	print_queue_struct *queue=NULL;
	print_status_struct status;
	memset(&status, 0, sizeof(status));	

	if (!W_ERROR_IS_OK(get_a_printer(&ntprinter, 2, lp_servicename(snum))))
		return False;
		
	memset(&status, 0, sizeof(status));		
	count = print_queue_status(snum, &queue, &status);

	init_unistr(&printer->servername, ntprinter->info_2->servername); /* servername*/
	init_unistr(&printer->printername, ntprinter->info_2->printername);				/* printername*/
	init_unistr(&printer->sharename, lp_servicename(snum));			/* sharename */
	init_unistr(&printer->portname, ntprinter->info_2->portname);			/* port */	
	init_unistr(&printer->drivername, ntprinter->info_2->drivername);	/* drivername */

	if (*ntprinter->info_2->comment == '\0')
		init_unistr(&printer->comment, lp_comment(snum));			/* comment */	
	else
		init_unistr(&printer->comment, ntprinter->info_2->comment); /* saved comment. */

	init_unistr(&printer->location, ntprinter->info_2->location);		/* location */	
	init_unistr(&printer->sepfile, ntprinter->info_2->sepfile);		/* separator file */
	init_unistr(&printer->printprocessor, ntprinter->info_2->printprocessor);/* print processor */
	init_unistr(&printer->datatype, ntprinter->info_2->datatype);		/* datatype */	
	init_unistr(&printer->parameters, ntprinter->info_2->parameters);	/* parameters (of print processor) */	

	printer->attributes = ntprinter->info_2->attributes;

	printer->priority = ntprinter->info_2->priority;				/* priority */	
	printer->defaultpriority = ntprinter->info_2->default_priority;		/* default priority */
	printer->starttime = ntprinter->info_2->starttime;			/* starttime */
	printer->untiltime = ntprinter->info_2->untiltime;			/* untiltime */
	printer->status = nt_printq_status(status.status);			/* status */
	printer->cjobs = count;							/* jobs */
	printer->averageppm = ntprinter->info_2->averageppm;			/* average pages per minute */
			
	if((printer->devmode = construct_dev_mode(snum)) == NULL) {
		DEBUG(8, ("Returning NULL Devicemode!\n"));
	}

	if (ntprinter->info_2->secdesc_buf && ntprinter->info_2->secdesc_buf->len != 0) {
		/* steal the printer info sec_desc structure.  [badly done]. */
		printer->secdesc = ntprinter->info_2->secdesc_buf->sec;
		ntprinter->info_2->secdesc_buf->sec = NULL; /* Stolen memory. */
		ntprinter->info_2->secdesc_buf->len = 0; /* Stolen memory. */
		ntprinter->info_2->secdesc_buf->max_len = 0; /* Stolen memory. */
	}
	else {
		printer->secdesc = NULL;
	}

	free_a_printer(&ntprinter, 2);
	SAFE_FREE(queue);
	return True;
}

/********************************************************************
 * construct_printer_info_3
 * fill a printer_info_3 struct
 ********************************************************************/
static BOOL construct_printer_info_3(PRINTER_INFO_3 **pp_printer, int snum)
{
	NT_PRINTER_INFO_LEVEL *ntprinter = NULL;
	PRINTER_INFO_3 *printer = NULL;

	if (!W_ERROR_IS_OK(get_a_printer(&ntprinter, 2, lp_servicename(snum))))
		return False;

	*pp_printer = NULL;
	if ((printer = (PRINTER_INFO_3 *)malloc(sizeof(PRINTER_INFO_3))) == NULL) {
		DEBUG(0,("construct_printer_info_3: malloc fail.\n"));
		return False;
	}

	ZERO_STRUCTP(printer);
	
	printer->flags = 4; /* These are the components of the SD we are returning. */
	if (ntprinter->info_2->secdesc_buf && ntprinter->info_2->secdesc_buf->len != 0) {
		/* steal the printer info sec_desc structure.  [badly done]. */
		printer->secdesc = ntprinter->info_2->secdesc_buf->sec;

#if 0
		/*
		 * Set the flags for the components we are returning.
		 */

		if (printer->secdesc->owner_sid)
			printer->flags |= OWNER_SECURITY_INFORMATION;

		if (printer->secdesc->grp_sid)
			printer->flags |= GROUP_SECURITY_INFORMATION;

		if (printer->secdesc->dacl)
			printer->flags |= DACL_SECURITY_INFORMATION;

		if (printer->secdesc->sacl)
			printer->flags |= SACL_SECURITY_INFORMATION;
#endif

		ntprinter->info_2->secdesc_buf->sec = NULL; /* Stolen the malloced memory. */
		ntprinter->info_2->secdesc_buf->len = 0; /* Stolen the malloced memory. */
		ntprinter->info_2->secdesc_buf->max_len = 0; /* Stolen the malloced memory. */
	}

	free_a_printer(&ntprinter, 2);

	*pp_printer = printer;
	return True;
}

/********************************************************************
 Spoolss_enumprinters.
********************************************************************/
static WERROR enum_all_printers_info_1(uint32 flags, NEW_BUFFER *buffer, uint32 offered, uint32 *needed, uint32 *returned)
{
	int snum;
	int i;
	int n_services=lp_numservices();
	PRINTER_INFO_1 *tp, *printers=NULL;
	PRINTER_INFO_1 current_prt;
	
	DEBUG(4,("enum_all_printers_info_1\n"));	

	for (snum=0; snum<n_services; snum++) {
		if (lp_browseable(snum) && lp_snum_ok(snum) && lp_print_ok(snum) ) {
			DEBUG(4,("Found a printer in smb.conf: %s[%x]\n", lp_servicename(snum), snum));
				
			if (construct_printer_info_1(flags, &current_prt, snum)) {
				if((tp=Realloc(printers, (*returned +1)*sizeof(PRINTER_INFO_1))) == NULL) {
					DEBUG(0,("enum_all_printers_info_1: failed to enlarge printers buffer!\n"));
					SAFE_FREE(printers);
					*returned=0;
					return WERR_NOMEM;
				}
				else printers = tp;
				DEBUG(4,("ReAlloced memory for [%d] PRINTER_INFO_1\n", *returned));		
				memcpy(&printers[*returned], &current_prt, sizeof(PRINTER_INFO_1));
				(*returned)++;
			}
		}
	}
		
	/* check the required size. */	
	for (i=0; i<*returned; i++)
		(*needed) += spoolss_size_printer_info_1(&printers[i]);

	if (!alloc_buffer_size(buffer, *needed))
		return WERR_INSUFFICIENT_BUFFER;

	/* fill the buffer with the structures */
	for (i=0; i<*returned; i++)
		smb_io_printer_info_1("", buffer, &printers[i], 0);	

	/* clear memory */
	SAFE_FREE(printers);

	if (*needed > offered) {
		*returned=0;
		return WERR_INSUFFICIENT_BUFFER;
	}
	else
		return WERR_OK;
}

/********************************************************************
 enum_all_printers_info_1_local.
*********************************************************************/
static WERROR enum_all_printers_info_1_local(NEW_BUFFER *buffer, uint32 offered, uint32 *needed, uint32 *returned)
{
	DEBUG(4,("enum_all_printers_info_1_local\n"));	
	
	return enum_all_printers_info_1(PRINTER_ENUM_ICON8, buffer, offered, needed, returned);
}

/********************************************************************
 enum_all_printers_info_1_name.
*********************************************************************/
static WERROR enum_all_printers_info_1_name(fstring name, NEW_BUFFER *buffer, uint32 offered, uint32 *needed, uint32 *returned)
{
	char *s = name;
	
	DEBUG(4,("enum_all_printers_info_1_name\n"));	
	
	if ((name[0] == '\\') && (name[1] == '\\'))
		s = name + 2;
		
	if (is_myname_or_ipaddr(s)) {
		return enum_all_printers_info_1(PRINTER_ENUM_ICON8, buffer, offered, needed, returned);
	}
	else
		return WERR_INVALID_NAME;
}

/********************************************************************
 enum_all_printers_info_1_remote.
*********************************************************************/
static WERROR enum_all_printers_info_1_remote(fstring name, NEW_BUFFER *buffer, uint32 offered, uint32 *needed, uint32 *returned)
{
	PRINTER_INFO_1 *printer;
	fstring printername;
	fstring desc;
	fstring comment;
	DEBUG(4,("enum_all_printers_info_1_remote\n"));	

	/* JFM: currently it's more a place holder than anything else.
	 * In the spooler world there is a notion of server registration.
	 * the print servers are registring (sp ?) on the PDC (in the same domain)
	 *
	 * We should have a TDB here. The registration is done thru an undocumented RPC call.
	 */
	
	if((printer=(PRINTER_INFO_1 *)malloc(sizeof(PRINTER_INFO_1))) == NULL)
		return WERR_NOMEM;

	*returned=1;
	
	slprintf(printername, sizeof(printername)-1,"Windows NT Remote Printers!!\\\\%s", global_myname);		
	slprintf(desc, sizeof(desc)-1,"%s", global_myname);
	slprintf(comment, sizeof(comment)-1, "Logged on Domain");

	init_unistr(&printer->description, desc);
	init_unistr(&printer->name, printername);	
	init_unistr(&printer->comment, comment);
	printer->flags=PRINTER_ENUM_ICON3|PRINTER_ENUM_CONTAINER;
		
	/* check the required size. */	
	*needed += spoolss_size_printer_info_1(printer);

	if (!alloc_buffer_size(buffer, *needed)) {
		SAFE_FREE(printer);
		return WERR_INSUFFICIENT_BUFFER;
	}

	/* fill the buffer with the structures */
	smb_io_printer_info_1("", buffer, printer, 0);	

	/* clear memory */
	SAFE_FREE(printer);

	if (*needed > offered) {
		*returned=0;
		return WERR_INSUFFICIENT_BUFFER;
	}
	else
		return WERR_OK;
}

/********************************************************************
 enum_all_printers_info_1_network.
*********************************************************************/

static WERROR enum_all_printers_info_1_network(NEW_BUFFER *buffer, uint32 offered, uint32 *needed, uint32 *returned)
{
	DEBUG(4,("enum_all_printers_info_1_network\n"));	
	
	return enum_all_printers_info_1(PRINTER_ENUM_UNKNOWN_8, buffer, offered, needed, returned);
}

/********************************************************************
 * api_spoolss_enumprinters
 *
 * called from api_spoolss_enumprinters (see this to understand)
 ********************************************************************/

static WERROR enum_all_printers_info_2(NEW_BUFFER *buffer, uint32 offered, uint32 *needed, uint32 *returned)
{
	int snum;
	int i;
	int n_services=lp_numservices();
	PRINTER_INFO_2 *tp, *printers=NULL;
	PRINTER_INFO_2 current_prt;

	for (snum=0; snum<n_services; snum++) {
		if (lp_browseable(snum) && lp_snum_ok(snum) && lp_print_ok(snum) ) {
			DEBUG(4,("Found a printer in smb.conf: %s[%x]\n", lp_servicename(snum), snum));
				
			if (construct_printer_info_2(&current_prt, snum)) {
				if((tp=Realloc(printers, (*returned +1)*sizeof(PRINTER_INFO_2))) == NULL) {
					DEBUG(0,("enum_all_printers_info_2: failed to enlarge printers buffer!\n"));
					SAFE_FREE(printers);
					*returned = 0;
					return WERR_NOMEM;
				}
				else printers = tp;
				DEBUG(4,("ReAlloced memory for [%d] PRINTER_INFO_2\n", *returned));		
				memcpy(&printers[*returned], &current_prt, sizeof(PRINTER_INFO_2));
				(*returned)++;
			}
		}
	}
	
	/* check the required size. */	
	for (i=0; i<*returned; i++)
		(*needed) += spoolss_size_printer_info_2(&printers[i]);

	if (!alloc_buffer_size(buffer, *needed)) {
		for (i=0; i<*returned; i++) {
			free_devmode(printers[i].devmode);
		}
		SAFE_FREE(printers);
		return WERR_INSUFFICIENT_BUFFER;
	}

	/* fill the buffer with the structures */
	for (i=0; i<*returned; i++)
		smb_io_printer_info_2("", buffer, &(printers[i]), 0);	
	
	/* clear memory */
	for (i=0; i<*returned; i++) {
		free_devmode(printers[i].devmode);
	}
	SAFE_FREE(printers);

	if (*needed > offered) {
		*returned=0;
		return WERR_INSUFFICIENT_BUFFER;
	}
	else
		return WERR_OK;
}

/********************************************************************
 * handle enumeration of printers at level 1
 ********************************************************************/
static WERROR enumprinters_level1( uint32 flags, fstring name,
			         NEW_BUFFER *buffer, uint32 offered,
			         uint32 *needed, uint32 *returned)
{
	/* Not all the flags are equals */

	if (flags & PRINTER_ENUM_LOCAL)
		return enum_all_printers_info_1_local(buffer, offered, needed, returned);

	if (flags & PRINTER_ENUM_NAME)
		return enum_all_printers_info_1_name(name, buffer, offered, needed, returned);

	if (flags & PRINTER_ENUM_REMOTE)
		return enum_all_printers_info_1_remote(name, buffer, offered, needed, returned);

	if (flags & PRINTER_ENUM_NETWORK)
		return enum_all_printers_info_1_network(buffer, offered, needed, returned);

	return WERR_OK; /* NT4sp5 does that */
}

/********************************************************************
 * handle enumeration of printers at level 2
 ********************************************************************/
static WERROR enumprinters_level2( uint32 flags, fstring servername,
			         NEW_BUFFER *buffer, uint32 offered,
			         uint32 *needed, uint32 *returned)
{
	char *s = servername;

	if (flags & PRINTER_ENUM_LOCAL) {
			return enum_all_printers_info_2(buffer, offered, needed, returned);
	}

	if (flags & PRINTER_ENUM_NAME) {
		if ((servername[0] == '\\') && (servername[1] == '\\'))
			s = servername + 2;
		if (is_myname_or_ipaddr(s))
			return enum_all_printers_info_2(buffer, offered, needed, returned);
		else
			return WERR_INVALID_NAME;
	}

	if (flags & PRINTER_ENUM_REMOTE)
		return WERR_UNKNOWN_LEVEL;

	return WERR_OK;
}

/********************************************************************
 * handle enumeration of printers at level 5
 ********************************************************************/
static WERROR enumprinters_level5( uint32 flags, fstring servername,
			         NEW_BUFFER *buffer, uint32 offered,
			         uint32 *needed, uint32 *returned)
{
/*	return enum_all_printers_info_5(buffer, offered, needed, returned);*/
	return WERR_OK;
}

/********************************************************************
 * api_spoolss_enumprinters
 *
 * called from api_spoolss_enumprinters (see this to understand)
 ********************************************************************/

WERROR _spoolss_enumprinters( pipes_struct *p, SPOOL_Q_ENUMPRINTERS *q_u, SPOOL_R_ENUMPRINTERS *r_u)
{
	uint32 flags = q_u->flags;
	UNISTR2 *servername = &q_u->servername;
	uint32 level = q_u->level;
	NEW_BUFFER *buffer = NULL;
	uint32 offered = q_u->offered;
	uint32 *needed = &r_u->needed;
	uint32 *returned = &r_u->returned;

	fstring name;
	
	/* that's an [in out] buffer */
	spoolss_move_buffer(q_u->buffer, &r_u->buffer);
	buffer = r_u->buffer;

	DEBUG(4,("_spoolss_enumprinters\n"));

	*needed=0;
	*returned=0;
	
	/*
	 * Level 1:
	 *	    flags==PRINTER_ENUM_NAME
	 *	     if name=="" then enumerates all printers
	 *	     if name!="" then enumerate the printer
	 *	    flags==PRINTER_ENUM_REMOTE
	 *	    name is NULL, enumerate printers
	 * Level 2: name!="" enumerates printers, name can't be NULL
	 * Level 3: doesn't exist
	 * Level 4: does a local registry lookup
	 * Level 5: same as Level 2
	 */

	unistr2_to_ascii(name, servername, sizeof(name)-1);
	strupper(name);

	switch (level) {
	case 1:
		return enumprinters_level1(flags, name, buffer, offered, needed, returned);
	case 2:
		return enumprinters_level2(flags, name, buffer, offered, needed, returned);
	case 5:
		return enumprinters_level5(flags, name, buffer, offered, needed, returned);
	case 3:
	case 4:
		break;
	}
	return WERR_UNKNOWN_LEVEL;
}

/****************************************************************************
****************************************************************************/
static WERROR getprinter_level_0(int snum, NEW_BUFFER *buffer, uint32 offered, uint32 *needed)
{
	PRINTER_INFO_0 *printer=NULL;

	if((printer=(PRINTER_INFO_0*)malloc(sizeof(PRINTER_INFO_0))) == NULL)
		return WERR_NOMEM;

	construct_printer_info_0(printer, snum);
	
	/* check the required size. */	
	*needed += spoolss_size_printer_info_0(printer);

	if (!alloc_buffer_size(buffer, *needed)) {
		SAFE_FREE(printer);
		return WERR_INSUFFICIENT_BUFFER;
	}

	/* fill the buffer with the structures */
	smb_io_printer_info_0("", buffer, printer, 0);	
	
	/* clear memory */
	SAFE_FREE(printer);

	if (*needed > offered) {
		return WERR_INSUFFICIENT_BUFFER;
	}

	return WERR_OK;
}

/****************************************************************************
****************************************************************************/
static WERROR getprinter_level_1(int snum, NEW_BUFFER *buffer, uint32 offered, uint32 *needed)
{
	PRINTER_INFO_1 *printer=NULL;

	if((printer=(PRINTER_INFO_1*)malloc(sizeof(PRINTER_INFO_1))) == NULL)
		return WERR_NOMEM;

	construct_printer_info_1(PRINTER_ENUM_ICON8, printer, snum);
	
	/* check the required size. */	
	*needed += spoolss_size_printer_info_1(printer);

	if (!alloc_buffer_size(buffer, *needed)) {
		SAFE_FREE(printer);
		return WERR_INSUFFICIENT_BUFFER;
	}

	/* fill the buffer with the structures */
	smb_io_printer_info_1("", buffer, printer, 0);	
	
	/* clear memory */
	SAFE_FREE(printer);

	if (*needed > offered) {
		return WERR_INSUFFICIENT_BUFFER;
	}

	return WERR_OK;	
}

/****************************************************************************
****************************************************************************/
static WERROR getprinter_level_2(int snum, NEW_BUFFER *buffer, uint32 offered, uint32 *needed)
{
	PRINTER_INFO_2 *printer=NULL;

	if((printer=(PRINTER_INFO_2*)malloc(sizeof(PRINTER_INFO_2)))==NULL)
		return WERR_NOMEM;
	
	construct_printer_info_2(printer, snum);
	
	/* check the required size. */	
	*needed += spoolss_size_printer_info_2(printer);

	if (!alloc_buffer_size(buffer, *needed)) {
		free_printer_info_2(printer);
		return WERR_INSUFFICIENT_BUFFER;
	}

	/* fill the buffer with the structures */
	if (!smb_io_printer_info_2("", buffer, printer, 0)) {
		free_printer_info_2(printer);
		return WERR_NOMEM;
	}
	
	/* clear memory */
	free_printer_info_2(printer);

	if (*needed > offered) {
		return WERR_INSUFFICIENT_BUFFER;
	}

	return WERR_OK;	
}

/****************************************************************************
****************************************************************************/
static WERROR getprinter_level_3(int snum, NEW_BUFFER *buffer, uint32 offered, uint32 *needed)
{
	PRINTER_INFO_3 *printer=NULL;

	if (!construct_printer_info_3(&printer, snum))
		return WERR_NOMEM;
	
	/* check the required size. */	
	*needed += spoolss_size_printer_info_3(printer);

	if (!alloc_buffer_size(buffer, *needed)) {
		free_printer_info_3(printer);
		return WERR_INSUFFICIENT_BUFFER;
	}

	/* fill the buffer with the structures */
	smb_io_printer_info_3("", buffer, printer, 0);	
	
	/* clear memory */
	free_printer_info_3(printer);
	
	if (*needed > offered) {
		return WERR_INSUFFICIENT_BUFFER;
	}

	return WERR_OK;	
}

/****************************************************************************
****************************************************************************/

WERROR _spoolss_getprinter(pipes_struct *p, SPOOL_Q_GETPRINTER *q_u, SPOOL_R_GETPRINTER *r_u)
{
	POLICY_HND *handle = &q_u->handle;
	uint32 level = q_u->level;
	NEW_BUFFER *buffer = NULL;
	uint32 offered = q_u->offered;
	uint32 *needed = &r_u->needed;

	int snum;

	/* that's an [in out] buffer */
	spoolss_move_buffer(q_u->buffer, &r_u->buffer);
	buffer = r_u->buffer;

	*needed=0;

	if (!get_printer_snum(p, handle, &snum))
		return WERR_BADFID;

	switch (level) {
	case 0:
		return getprinter_level_0(snum, buffer, offered, needed);
	case 1:
		return getprinter_level_1(snum, buffer, offered, needed);
	case 2:		
		return getprinter_level_2(snum, buffer, offered, needed);
	case 3:		
		return getprinter_level_3(snum, buffer, offered, needed);
	}
	return WERR_UNKNOWN_LEVEL;
}	
		
/********************************************************************
 * fill a DRIVER_INFO_1 struct
 ********************************************************************/
static void fill_printer_driver_info_1(DRIVER_INFO_1 *info, NT_PRINTER_DRIVER_INFO_LEVEL driver, fstring servername, fstring architecture)
{
	init_unistr( &info->name, driver.info_3->name);
}

/********************************************************************
 * construct_printer_driver_info_1
 ********************************************************************/
static WERROR construct_printer_driver_info_1(DRIVER_INFO_1 *info, int snum, fstring servername, fstring architecture, uint32 version)
{	
	NT_PRINTER_INFO_LEVEL *printer = NULL;
	NT_PRINTER_DRIVER_INFO_LEVEL driver;

	ZERO_STRUCT(driver);

	if (!W_ERROR_IS_OK(get_a_printer(&printer, 2, lp_servicename(snum))))
		return WERR_INVALID_PRINTER_NAME;

	if (!W_ERROR_IS_OK(get_a_printer_driver(&driver, 3, printer->info_2->drivername, architecture, version)))
		return WERR_UNKNOWN_PRINTER_DRIVER;

	fill_printer_driver_info_1(info, driver, servername, architecture);

	free_a_printer(&printer,2);

	return WERR_OK;
}

/********************************************************************
 * construct_printer_driver_info_2
 * fill a printer_info_2 struct
 ********************************************************************/
static void fill_printer_driver_info_2(DRIVER_INFO_2 *info, NT_PRINTER_DRIVER_INFO_LEVEL driver, fstring servername)
{
	pstring temp;

	info->version=driver.info_3->cversion;

	init_unistr( &info->name, driver.info_3->name );
	init_unistr( &info->architecture, driver.info_3->environment );


    if (strlen(driver.info_3->driverpath)) {
		slprintf(temp, sizeof(temp)-1, "\\\\%s%s", servername, driver.info_3->driverpath);
		init_unistr( &info->driverpath, temp );
    } else
        init_unistr( &info->driverpath, "" );

	if (strlen(driver.info_3->datafile)) {
		slprintf(temp, sizeof(temp)-1, "\\\\%s%s", servername, driver.info_3->datafile);
		init_unistr( &info->datafile, temp );
	} else
		init_unistr( &info->datafile, "" );
	
	if (strlen(driver.info_3->configfile)) {
		slprintf(temp, sizeof(temp)-1, "\\\\%s%s", servername, driver.info_3->configfile);
		init_unistr( &info->configfile, temp );	
	} else
		init_unistr( &info->configfile, "" );
}

/********************************************************************
 * construct_printer_driver_info_2
 * fill a printer_info_2 struct
 ********************************************************************/
static WERROR construct_printer_driver_info_2(DRIVER_INFO_2 *info, int snum, fstring servername, fstring architecture, uint32 version)
{
	NT_PRINTER_INFO_LEVEL *printer = NULL;
	NT_PRINTER_DRIVER_INFO_LEVEL driver;

	ZERO_STRUCT(printer);
	ZERO_STRUCT(driver);

	if (!W_ERROR_IS_OK(get_a_printer(&printer, 2, lp_servicename(snum))))
		return WERR_INVALID_PRINTER_NAME;

	if (!W_ERROR_IS_OK(get_a_printer_driver(&driver, 3, printer->info_2->drivername, architecture, version)))
		return WERR_UNKNOWN_PRINTER_DRIVER;

	fill_printer_driver_info_2(info, driver, servername);

	free_a_printer(&printer,2);

	return WERR_OK;
}

/********************************************************************
 * copy a strings array and convert to UNICODE
 *
 * convert an array of ascii string to a UNICODE string
 ********************************************************************/
static void init_unistr_array(uint16 **uni_array, fstring *char_array, char *servername)
{
	int i=0;
	int j=0;
	char *v;
	pstring line;
	uint16 *tuary;

	DEBUG(6,("init_unistr_array\n"));
	*uni_array=NULL;

	while (1) {
		if (char_array == NULL)
			v = "";
		else {
			v = char_array[i];
			if (!v) v = ""; /* hack to handle null lists */
		}
		if (strlen(v) == 0) break;
		slprintf(line, sizeof(line)-1, "\\\\%s%s", servername, v);
		DEBUGADD(6,("%d:%s:%d\n", i, line, strlen(line)));
		if((tuary=Realloc(*uni_array, (j+strlen(line)+2)*sizeof(uint16))) == NULL) {
			DEBUG(0,("init_unistr_array: Realloc error\n" ));
			return;
		} else
			*uni_array = tuary;
		j += (dos_PutUniCode((char *)(*uni_array+j), line , sizeof(uint16)*strlen(line), True) / sizeof(uint16) );
		i++;
	}
	
	if (*uni_array) {
		(*uni_array)[j]=0x0000;
	}
	
	DEBUGADD(6,("last one:done\n"));
}

/********************************************************************
 * construct_printer_info_3
 * fill a printer_info_3 struct
 ********************************************************************/
static void fill_printer_driver_info_3(DRIVER_INFO_3 *info, NT_PRINTER_DRIVER_INFO_LEVEL driver, fstring servername)
{
	pstring temp;

	ZERO_STRUCTP(info);

	info->version=driver.info_3->cversion;

	init_unistr( &info->name, driver.info_3->name );	
	init_unistr( &info->architecture, driver.info_3->environment );

    if (strlen(driver.info_3->driverpath)) {
        slprintf(temp, sizeof(temp)-1, "\\\\%s%s", servername, driver.info_3->driverpath);		
        init_unistr( &info->driverpath, temp );
    } else
        init_unistr( &info->driverpath, "" );
    
    if (strlen(driver.info_3->datafile)) {
        slprintf(temp, sizeof(temp)-1, "\\\\%s%s", servername, driver.info_3->datafile);
        init_unistr( &info->datafile, temp );
    } else
        init_unistr( &info->datafile, "" );

    if (strlen(driver.info_3->configfile)) {
        slprintf(temp, sizeof(temp)-1, "\\\\%s%s", servername, driver.info_3->configfile);
        init_unistr( &info->configfile, temp );	
    } else
        init_unistr( &info->configfile, "" );

    if (strlen(driver.info_3->helpfile)) {
        slprintf(temp, sizeof(temp)-1, "\\\\%s%s", servername, driver.info_3->helpfile);
        init_unistr( &info->helpfile, temp );
    } else
        init_unistr( &info->helpfile, "" );

	init_unistr( &info->monitorname, driver.info_3->monitorname );
	init_unistr( &info->defaultdatatype, driver.info_3->defaultdatatype );

	info->dependentfiles=NULL;
	init_unistr_array(&info->dependentfiles, driver.info_3->dependentfiles, servername);
}

/********************************************************************
 * construct_printer_info_3
 * fill a printer_info_3 struct
 ********************************************************************/
static WERROR construct_printer_driver_info_3(DRIVER_INFO_3 *info, int snum, fstring servername, fstring architecture, uint32 version)
{	
	NT_PRINTER_INFO_LEVEL *printer = NULL;
	NT_PRINTER_DRIVER_INFO_LEVEL driver;
	WERROR status;
	ZERO_STRUCT(driver);

	status=get_a_printer(&printer, 2, lp_servicename(snum) );
	DEBUG(8,("construct_printer_driver_info_3: status: %s\n", werror_str(status)));
	if (!W_ERROR_IS_OK(status))
		return WERR_INVALID_PRINTER_NAME;

	status=get_a_printer_driver(&driver, 3, printer->info_2->drivername, architecture, version);	
	DEBUG(8,("construct_printer_driver_info_3: status: %s\n", werror_str(status)));
	if (!W_ERROR_IS_OK(status)) {
		free_a_printer(&printer,2);
		return WERR_UNKNOWN_PRINTER_DRIVER;
	}

	fill_printer_driver_info_3(info, driver, servername);

	free_a_printer(&printer,2);

	return WERR_OK;
}

/********************************************************************
 * construct_printer_info_6
 * fill a printer_info_6 struct - we know that driver is really level 3. This sucks. JRA.
 ********************************************************************/

static void fill_printer_driver_info_6(DRIVER_INFO_6 *info, NT_PRINTER_DRIVER_INFO_LEVEL driver, fstring servername)
{
	pstring temp;
	fstring nullstr;

	ZERO_STRUCTP(info);
	memset(&nullstr, '\0', sizeof(fstring));

	info->version=driver.info_3->cversion;

	init_unistr( &info->name, driver.info_3->name );	
	init_unistr( &info->architecture, driver.info_3->environment );

	if (strlen(driver.info_3->driverpath)) {
		slprintf(temp, sizeof(temp)-1, "\\\\%s%s", servername, driver.info_3->driverpath);		
		init_unistr( &info->driverpath, temp );
	} else
		init_unistr( &info->driverpath, "" );

	if (strlen(driver.info_3->datafile)) {
		slprintf(temp, sizeof(temp)-1, "\\\\%s%s", servername, driver.info_3->datafile);
		init_unistr( &info->datafile, temp );
	} else
		init_unistr( &info->datafile, "" );

	if (strlen(driver.info_3->configfile)) {
		slprintf(temp, sizeof(temp)-1, "\\\\%s%s", servername, driver.info_3->configfile);
		init_unistr( &info->configfile, temp );	
	} else
		init_unistr( &info->configfile, "" );

	if (strlen(driver.info_3->helpfile)) {
		slprintf(temp, sizeof(temp)-1, "\\\\%s%s", servername, driver.info_3->helpfile);
		init_unistr( &info->helpfile, temp );
	} else
		init_unistr( &info->helpfile, "" );
	
	init_unistr( &info->monitorname, driver.info_3->monitorname );
	init_unistr( &info->defaultdatatype, driver.info_3->defaultdatatype );

	info->dependentfiles=NULL;
	init_unistr_array(&info->dependentfiles, driver.info_3->dependentfiles, servername);

	info->previousdrivernames=NULL;
	init_unistr_array(&info->previousdrivernames, &nullstr, servername);

	info->driver_date.low=0;
	info->driver_date.high=0;

	info->padding=0;
	info->driver_version_low=0;
	info->driver_version_high=0;

	init_unistr( &info->mfgname, "");
	init_unistr( &info->oem_url, "");
	init_unistr( &info->hardware_id, "");
	init_unistr( &info->provider, "");
}

/********************************************************************
 * construct_printer_info_6
 * fill a printer_info_6 struct
 ********************************************************************/
static WERROR construct_printer_driver_info_6(DRIVER_INFO_6 *info, int snum, fstring servername, fstring architecture, uint32 version)
{	
	NT_PRINTER_INFO_LEVEL *printer = NULL;
	NT_PRINTER_DRIVER_INFO_LEVEL driver;
	WERROR status;
	ZERO_STRUCT(driver);

	status=get_a_printer(&printer, 2, lp_servicename(snum) );
	DEBUG(8,("construct_printer_driver_info_6: status: %s\n", werror_str(status)));
	if (!W_ERROR_IS_OK(status))
		return WERR_INVALID_PRINTER_NAME;

	status=get_a_printer_driver(&driver, 3, printer->info_2->drivername, architecture, version);	
	DEBUG(8,("construct_printer_driver_info_6: status: %s\n", werror_str(status)));
	if (!W_ERROR_IS_OK(status)) {
		/*
		 * Is this a W2k client ?
		 */

		if (version < 3) {
			free_a_printer(&printer,2);
			return WERR_UNKNOWN_PRINTER_DRIVER;
		}

		/* Yes - try again with a WinNT driver. */
		version = 2;
		status=get_a_printer_driver(&driver, 3, printer->info_2->drivername, architecture, version);	
		DEBUG(8,("construct_printer_driver_info_6: status: %s\n", werror_str(status)));
		if (!W_ERROR_IS_OK(status)) {
			free_a_printer(&printer,2);
			return WERR_UNKNOWN_PRINTER_DRIVER;
		}
	}

	fill_printer_driver_info_6(info, driver, servername);

	free_a_printer(&printer,2);

	return WERR_OK;
}

/****************************************************************************
****************************************************************************/

static void free_printer_driver_info_3(DRIVER_INFO_3 *info)
{
	SAFE_FREE(info->dependentfiles);
}

/****************************************************************************
****************************************************************************/

static void free_printer_driver_info_6(DRIVER_INFO_6 *info)
{
	SAFE_FREE(info->dependentfiles);
	
}

/****************************************************************************
****************************************************************************/
static WERROR getprinterdriver2_level1(fstring servername, fstring architecture, uint32 version, int snum, NEW_BUFFER *buffer, uint32 offered, uint32 *needed)
{
	DRIVER_INFO_1 *info=NULL;
	WERROR status;
	
	if((info=(DRIVER_INFO_1 *)malloc(sizeof(DRIVER_INFO_1))) == NULL)
		return WERR_NOMEM;
	
	status=construct_printer_driver_info_1(info, snum, servername, architecture, version);
	if (!W_ERROR_IS_OK(status)) {
		SAFE_FREE(info);
		return status;
	}

	/* check the required size. */	
	*needed += spoolss_size_printer_driver_info_1(info);

	if (!alloc_buffer_size(buffer, *needed)) {
		SAFE_FREE(info);
		return WERR_INSUFFICIENT_BUFFER;
	}

	/* fill the buffer with the structures */
	smb_io_printer_driver_info_1("", buffer, info, 0);	

	/* clear memory */
	SAFE_FREE(info);

	if (*needed > offered)
		return WERR_INSUFFICIENT_BUFFER;

	return WERR_OK;
}

/****************************************************************************
****************************************************************************/
static WERROR getprinterdriver2_level2(fstring servername, fstring architecture, uint32 version, int snum, NEW_BUFFER *buffer, uint32 offered, uint32 *needed)
{
	DRIVER_INFO_2 *info=NULL;
	WERROR status;
	
	if((info=(DRIVER_INFO_2 *)malloc(sizeof(DRIVER_INFO_2))) == NULL)
		return WERR_NOMEM;
	
	status=construct_printer_driver_info_2(info, snum, servername, architecture, version);
	if (!W_ERROR_IS_OK(status)) {
		SAFE_FREE(info);
		return status;
	}

	/* check the required size. */	
	*needed += spoolss_size_printer_driver_info_2(info);

	if (!alloc_buffer_size(buffer, *needed)) {
		SAFE_FREE(info);
		return WERR_INSUFFICIENT_BUFFER;
	}

	/* fill the buffer with the structures */
	smb_io_printer_driver_info_2("", buffer, info, 0);	

	/* clear memory */
	SAFE_FREE(info);

	if (*needed > offered)
		return WERR_INSUFFICIENT_BUFFER;
	
	return WERR_OK;
}

/****************************************************************************
****************************************************************************/
static WERROR getprinterdriver2_level3(fstring servername, fstring architecture, uint32 version, int snum, NEW_BUFFER *buffer, uint32 offered, uint32 *needed)
{
	DRIVER_INFO_3 info;
	WERROR status;

	ZERO_STRUCT(info);

	status=construct_printer_driver_info_3(&info, snum, servername, architecture, version);
	if (!W_ERROR_IS_OK(status)) {
		return status;
	}

	/* check the required size. */	
	*needed += spoolss_size_printer_driver_info_3(&info);

	if (!alloc_buffer_size(buffer, *needed)) {
		free_printer_driver_info_3(&info);
		return WERR_INSUFFICIENT_BUFFER;
	}

	/* fill the buffer with the structures */
	smb_io_printer_driver_info_3("", buffer, &info, 0);

	free_printer_driver_info_3(&info);

	if (*needed > offered)
		return WERR_INSUFFICIENT_BUFFER;

	return WERR_OK;
}

/****************************************************************************
****************************************************************************/
static WERROR getprinterdriver2_level6(fstring servername, fstring architecture, uint32 version, int snum, NEW_BUFFER *buffer, uint32 offered, uint32 *needed)
{
	DRIVER_INFO_6 info;
	WERROR status;

	ZERO_STRUCT(info);

	status=construct_printer_driver_info_6(&info, snum, servername, architecture, version);
	if (!W_ERROR_IS_OK(status)) {
		return status;
	}

	/* check the required size. */	
	*needed += spoolss_size_printer_driver_info_6(&info);

	if (!alloc_buffer_size(buffer, *needed)) {
		free_printer_driver_info_6(&info);
		return WERR_INSUFFICIENT_BUFFER;
	}

	/* fill the buffer with the structures */
	smb_io_printer_driver_info_6("", buffer, &info, 0);

	free_printer_driver_info_6(&info);

	if (*needed > offered)
		return WERR_INSUFFICIENT_BUFFER;
	
	return WERR_OK;
}

/****************************************************************************
****************************************************************************/

WERROR _spoolss_getprinterdriver2(pipes_struct *p, SPOOL_Q_GETPRINTERDRIVER2 *q_u, SPOOL_R_GETPRINTERDRIVER2 *r_u)
{
	POLICY_HND *handle = &q_u->handle;
	UNISTR2 *uni_arch = &q_u->architecture;
	uint32 level = q_u->level;
	uint32 clientmajorversion = q_u->clientmajorversion;
/*	uint32 clientminorversion = q_u->clientminorversion; - notused. */
	NEW_BUFFER *buffer = NULL;
	uint32 offered = q_u->offered;
	uint32 *needed = &r_u->needed;
	uint32 *servermajorversion = &r_u->servermajorversion;
	uint32 *serverminorversion = &r_u->serverminorversion;

	fstring servername;
	fstring architecture;
	int snum;

	/* that's an [in out] buffer */
	spoolss_move_buffer(q_u->buffer, &r_u->buffer);
	buffer = r_u->buffer;

	DEBUG(4,("_spoolss_getprinterdriver2\n"));

	*needed=0;
	*servermajorversion=0;
	*serverminorversion=0;

	pstrcpy(servername, global_myname);
	unistr2_to_ascii(architecture, uni_arch, sizeof(architecture)-1);

	if (!get_printer_snum(p, handle, &snum))
		return WERR_BADFID;

	switch (level) {
	case 1:
		return getprinterdriver2_level1(servername, architecture, clientmajorversion, snum, buffer, offered, needed);
	case 2:
		return getprinterdriver2_level2(servername, architecture, clientmajorversion, snum, buffer, offered, needed);
	case 3:
		return getprinterdriver2_level3(servername, architecture, clientmajorversion, snum, buffer, offered, needed);
	case 6:
		return getprinterdriver2_level6(servername, architecture, clientmajorversion, snum, buffer, offered, needed);
	}

	return WERR_UNKNOWN_LEVEL;
}

/****************************************************************************
****************************************************************************/

WERROR _spoolss_startpageprinter(pipes_struct *p, SPOOL_Q_STARTPAGEPRINTER *q_u, SPOOL_R_STARTPAGEPRINTER *r_u)
{
	POLICY_HND *handle = &q_u->handle;

	Printer_entry *Printer = find_printer_index_by_hnd(p, handle);

	if (Printer) {
		Printer->page_started=True;
		return WERR_OK;
	}

	DEBUG(3,("Error in startpageprinter printer handle\n"));
	return WERR_BADFID;
}

/****************************************************************************
****************************************************************************/

WERROR _spoolss_endpageprinter(pipes_struct *p, SPOOL_Q_ENDPAGEPRINTER *q_u, SPOOL_R_ENDPAGEPRINTER *r_u)
{
	POLICY_HND *handle = &q_u->handle;

	Printer_entry *Printer = find_printer_index_by_hnd(p, handle);

	if (!Printer) {
		DEBUG(0,("_spoolss_endpageprinter: Invalid handle (%s).\n",OUR_HANDLE(handle)));
		return WERR_BADFID;
	}
	
	Printer->page_started=False;

	return WERR_OK;
}

/********************************************************************
 * api_spoolss_getprinter
 * called from the spoolss dispatcher
 *
 ********************************************************************/

WERROR _spoolss_startdocprinter(pipes_struct *p, SPOOL_Q_STARTDOCPRINTER *q_u, SPOOL_R_STARTDOCPRINTER *r_u)
{
	POLICY_HND *handle = &q_u->handle;
/* 	uint32 level = q_u->doc_info_container.level; - notused. */
	DOC_INFO *docinfo = &q_u->doc_info_container.docinfo;
	uint32 *jobid = &r_u->jobid;

	DOC_INFO_1 *info_1 = &docinfo->doc_info_1;
	int snum;
	pstring jobname;
	fstring datatype;
	Printer_entry *Printer = find_printer_index_by_hnd(p, handle);
	struct current_user user;

	if (!Printer) {
		DEBUG(0,("_spoolss_startdocprinter: Invalid handle (%s)\n", OUR_HANDLE(handle)));
		return WERR_BADFID;
	}

	get_current_user(&user, p);

	/*
	 * a nice thing with NT is it doesn't listen to what you tell it.
	 * when asked to send _only_ RAW datas, it tries to send datas
	 * in EMF format.
	 *
	 * So I add checks like in NT Server ...
	 *
	 * lkclXXXX jean-francois, i love this kind of thing.  oh, well,
	 * there's a bug in NT client-side code, so we'll fix it in the
	 * server-side code. *nnnnnggggh!*
	 */
	
	if (info_1->p_datatype != 0) {
		unistr2_to_ascii(datatype, &info_1->datatype, sizeof(datatype));
		if (strcmp(datatype, "RAW") != 0) {
			(*jobid)=0;
			return WERR_INVALID_DATATYPE;
		}		
	}		
	
	/* get the share number of the printer */
	if (!get_printer_snum(p, handle, &snum)) {
		return WERR_BADFID;
	}

	unistr2_to_ascii(jobname, &info_1->docname, sizeof(jobname));
	
	Printer->jobid = print_job_start(&user, snum, jobname);

	/* An error occured in print_job_start() so return an appropriate
	   NT error code. */

	if (Printer->jobid == -1) {
		return map_werror_from_unix(errno);
	}
	
	Printer->document_started=True;
	(*jobid) = Printer->jobid;

	return WERR_OK;
}

/********************************************************************
 * api_spoolss_getprinter
 * called from the spoolss dispatcher
 *
 ********************************************************************/

WERROR _spoolss_enddocprinter(pipes_struct *p, SPOOL_Q_ENDDOCPRINTER *q_u, SPOOL_R_ENDDOCPRINTER *r_u)
{
	POLICY_HND *handle = &q_u->handle;

	return _spoolss_enddocprinter_internal(p, handle);
}

/****************************************************************************
****************************************************************************/

WERROR _spoolss_writeprinter(pipes_struct *p, SPOOL_Q_WRITEPRINTER *q_u, SPOOL_R_WRITEPRINTER *r_u)
{
	POLICY_HND *handle = &q_u->handle;
	uint32 buffer_size = q_u->buffer_size;
	uint8 *buffer = q_u->buffer;
	uint32 *buffer_written = &q_u->buffer_size2;

	Printer_entry *Printer = find_printer_index_by_hnd(p, handle);
	
	if (!Printer) {
		DEBUG(0,("_spoolss_writeprinter: Invalid handle (%s)\n",OUR_HANDLE(handle)));
		r_u->buffer_written = q_u->buffer_size2;
		return WERR_BADFID;
	}

	(*buffer_written) = print_job_write(Printer->jobid, (char *)buffer, buffer_size);


	r_u->buffer_written = q_u->buffer_size2;

	return WERR_OK;
}

/********************************************************************
 * api_spoolss_getprinter
 * called from the spoolss dispatcher
 *
 ********************************************************************/
static WERROR control_printer(POLICY_HND *handle, uint32 command,
			      pipes_struct *p)
{
	struct current_user user;
	int snum;
	WERROR errcode = WERR_BADFUNC;
	Printer_entry *Printer = find_printer_index_by_hnd(p, handle);

	get_current_user(&user, p);

	if (!Printer) {
		DEBUG(0,("control_printer: Invalid handle (%s)\n", OUR_HANDLE(handle)));
		return WERR_BADFID;
	}

	if (!get_printer_snum(p, handle, &snum))
		return WERR_BADFID;

	switch (command) {
	case PRINTER_CONTROL_PAUSE:
		if (print_queue_pause(&user, snum, &errcode)) {
			errcode = WERR_OK;
		}
		break;
	case PRINTER_CONTROL_RESUME:
	case PRINTER_CONTROL_UNPAUSE:
		if (print_queue_resume(&user, snum, &errcode)) {
			errcode = WERR_OK;
		}
		break;
	case PRINTER_CONTROL_PURGE:
		if (print_queue_purge(&user, snum, &errcode)) {
			errcode = WERR_OK;
		}
		break;
	default:
		return WERR_UNKNOWN_LEVEL;
	}

	return errcode;
}

/********************************************************************
 * api_spoolss_abortprinter
 ********************************************************************/

WERROR _spoolss_abortprinter(pipes_struct *p, SPOOL_Q_ABORTPRINTER *q_u, SPOOL_R_ABORTPRINTER *r_u)
{
	POLICY_HND *handle = &q_u->handle;

	return control_printer(handle, PRINTER_CONTROL_PURGE, p);
}

/********************************************************************
 * called by spoolss_api_setprinter
 * when updating a printer description
 ********************************************************************/
static WERROR update_printer_sec(POLICY_HND *handle, uint32 level,
				 const SPOOL_PRINTER_INFO_LEVEL *info,
				 pipes_struct *p, SEC_DESC_BUF *secdesc_ctr)
{
	SEC_DESC_BUF *new_secdesc_ctr = NULL, *old_secdesc_ctr = NULL;
	struct current_user user;
	WERROR result;
	int snum;

	Printer_entry *Printer = find_printer_index_by_hnd(p, handle);

	if (!Printer || !get_printer_snum(p, handle, &snum)) {
		DEBUG(0,("update_printer_sec: Invalid handle (%s)\n",
			 OUR_HANDLE(handle)));

		result = WERR_BADFID;
		goto done;
	}

	/* NT seems to like setting the security descriptor even though
	   nothing may have actually changed.  This causes annoying
	   dialog boxes when the user doesn't have permission to change
	   the security descriptor. */

	nt_printing_getsec(p->mem_ctx, Printer->dev.handlename, &old_secdesc_ctr);

	if (DEBUGLEVEL >= 10) {
		SEC_ACL *the_acl;
		int i;

		the_acl = old_secdesc_ctr->sec->dacl;
		DEBUG(10, ("old_secdesc_ctr for %s has %d aces:\n", 
			   PRINTERNAME(snum), the_acl->num_aces));

		for (i = 0; i < the_acl->num_aces; i++) {
			fstring sid_str;

			sid_to_string(sid_str, &the_acl->ace[i].trustee);

			DEBUG(10, ("%s 0x%08x\n", sid_str, 
				  the_acl->ace[i].info.mask));
		}

		the_acl = secdesc_ctr->sec->dacl;

		if (the_acl) {
			DEBUG(10, ("secdesc_ctr for %s has %d aces:\n", 
				   PRINTERNAME(snum), the_acl->num_aces));

			for (i = 0; i < the_acl->num_aces; i++) {
				fstring sid_str;
				
				sid_to_string(sid_str, &the_acl->ace[i].trustee);
				
				DEBUG(10, ("%s 0x%08x\n", sid_str, 
					   the_acl->ace[i].info.mask));
			}
		} else {
			DEBUG(10, ("dacl for secdesc_ctr is NULL\n"));
		}
	}

	new_secdesc_ctr = sec_desc_merge(p->mem_ctx, secdesc_ctr, old_secdesc_ctr);

	if (sec_desc_equal(new_secdesc_ctr->sec, old_secdesc_ctr->sec)) {
		result = WERR_OK;
		goto done;
	}

	/* Work out which user is performing the operation */

	get_current_user(&user, p);

	/* Check the user has permissions to change the security
	   descriptor.  By experimentation with two NT machines, the user
	   requires Full Access to the printer to change security
	   information. */

	if (!print_access_check(&user, snum, PRINTER_ACCESS_ADMINISTER)) {
		result = WERR_ACCESS_DENIED;
		goto done;
	}

	result = nt_printing_setsec(Printer->dev.handlename, new_secdesc_ctr);

 done:

	return result;
}

/********************************************************************
 Do Samba sanity checks on a printer info struct.
 this has changed purpose: it now "canonicalises" printer
 info from a client rather than just checking it is correct
 ********************************************************************/

static BOOL check_printer_ok(NT_PRINTER_INFO_LEVEL_2 *info, int snum)
{
	DEBUG(5,("check_printer_ok: servername=%s printername=%s sharename=%s portname=%s drivername=%s comment=%s location=%s\n",
		 info->servername, info->printername, info->sharename, info->portname, info->drivername, info->comment, info->location));

	/* we force some elements to "correct" values */
	slprintf(info->servername, sizeof(info->servername)-1, "\\\\%s", global_myname);
	slprintf(info->printername, sizeof(info->printername)-1, "\\\\%s\\%s",
		 global_myname, lp_servicename(snum));
	fstrcpy(info->sharename, lp_servicename(snum));
	info->attributes = PRINTER_ATTRIBUTE_SHARED   \
		| PRINTER_ATTRIBUTE_LOCAL  \
		| PRINTER_ATTRIBUTE_RAW_ONLY \
		| PRINTER_ATTRIBUTE_QUEUED ;
	
	return True;
}

/****************************************************************************
****************************************************************************/
static BOOL add_printer_hook(NT_PRINTER_INFO_LEVEL *printer)
{
	char *cmd = lp_addprinter_cmd();
	char **qlines;
	pstring command;
	pstring driverlocation;
	int numlines;
	int ret;
	int fd;

	/* build driver path... only 9X architecture is needed for legacy reasons */
	slprintf(driverlocation, sizeof(driverlocation)-1, "\\\\%s\\print$\\WIN40\\0",
			global_myname);
	/* change \ to \\ for the shell */
	all_string_sub(driverlocation,"\\","\\\\",sizeof(pstring));

	slprintf(command, sizeof(command)-1, "%s \"%s\" \"%s\" \"%s\" \"%s\" \"%s\" \"%s\"",
			cmd, printer->info_2->printername, printer->info_2->sharename,
			printer->info_2->portname, printer->info_2->drivername,
			printer->info_2->location, driverlocation);

	/* Convert script args to unix-codepage */
	dos_to_unix(command, True);
	DEBUG(10,("Running [%s]\n", command));
	ret = smbrun(command, &fd);
	DEBUGADD(10,("returned [%d]\n", ret));

	if ( ret != 0 ) {
		if (fd != -1)
			close(fd);
		return False;
	}

	numlines = 0;
	/* Get lines and convert them back to dos-codepage */
	qlines = fd_lines_load(fd, &numlines, True);
	DEBUGADD(10,("Lines returned = [%d]\n", numlines));
	close(fd);

	if(numlines) {
		/* Set the portname to what the script says the portname should be. */
		strncpy(printer->info_2->portname, qlines[0], sizeof(printer->info_2->portname));
		DEBUGADD(6,("Line[0] = [%s]\n", qlines[0]));

		/* Send SIGHUP to process group... is there a better way? */
		kill(0, SIGHUP);
		add_all_printers();
	}

	file_lines_free(qlines);
	return True;
}

/* Return true if two devicemodes are equal */

#define DEVMODE_CHECK_INT(field) \
    if (d1->field != d2->field) { \
        DEBUG(10, ("nt_devicemode_equal(): " #field " not equal (%d != %d)\n", \
            d1->field, d2->field)); \
        return False; \
    }

static BOOL nt_devicemode_equal(NT_DEVICEMODE *d1, NT_DEVICEMODE *d2)
{
	if (!d1 && !d2) goto equal;  /* if both are NULL they are equal */

	if (!d1 ^ !d2) {
		DEBUG(10, ("nt_devicemode_equal(): pointers not equal\n"));
		return False; /* if either is exclusively NULL are not equal */
	}

	if (!strequal(d1->devicename, d2->devicename)) {
		DEBUG(10, ("nt_devicemode_equal(): device not equal (%s != %s)\n", d1->devicename, d2->devicename));
		return False;
	}

	if (!strequal(d1->formname, d2->formname)) {
		DEBUG(10, ("nt_devicemode_equal(): formname not equal (%s != %s)\n", d1->formname, d2->formname));
		return False;
	}

	DEVMODE_CHECK_INT(specversion);
	DEVMODE_CHECK_INT(driverversion);
	DEVMODE_CHECK_INT(driverextra);
	DEVMODE_CHECK_INT(orientation);
	DEVMODE_CHECK_INT(papersize);
	DEVMODE_CHECK_INT(paperlength);
	DEVMODE_CHECK_INT(paperwidth);
	DEVMODE_CHECK_INT(scale);
	DEVMODE_CHECK_INT(copies);
	DEVMODE_CHECK_INT(defaultsource);
	DEVMODE_CHECK_INT(printquality);
	DEVMODE_CHECK_INT(color);
	DEVMODE_CHECK_INT(duplex);
	DEVMODE_CHECK_INT(yresolution);
	DEVMODE_CHECK_INT(ttoption);
	DEVMODE_CHECK_INT(collate);
	DEVMODE_CHECK_INT(logpixels);

	DEVMODE_CHECK_INT(fields);
	DEVMODE_CHECK_INT(bitsperpel);
	DEVMODE_CHECK_INT(pelswidth);
	DEVMODE_CHECK_INT(pelsheight);
	DEVMODE_CHECK_INT(displayflags);
	DEVMODE_CHECK_INT(displayfrequency);
	DEVMODE_CHECK_INT(icmmethod);
	DEVMODE_CHECK_INT(icmintent);
	DEVMODE_CHECK_INT(mediatype);
	DEVMODE_CHECK_INT(dithertype);
	DEVMODE_CHECK_INT(reserved1);
	DEVMODE_CHECK_INT(reserved2);
	DEVMODE_CHECK_INT(panningwidth);
	DEVMODE_CHECK_INT(panningheight);

	/* compare the private data if it exists */
	if (!d1->driverextra && !d2->driverextra) goto equal;


	DEVMODE_CHECK_INT(driverextra);

	if (memcmp(d1->private, d2->private, d1->driverextra)) {
		DEBUG(10, ("nt_devicemode_equal(): private data not equal\n"));
		return False;
	}

 equal:
	DEBUG(10, ("nt_devicemode_equal(): devicemodes identical\n"));
	return True;
}

/* Return true if two NT_PRINTER_PARAM structures are equal */

static BOOL nt_printer_param_equal(NT_PRINTER_PARAM *p1,
				   NT_PRINTER_PARAM *p2)
{
	if (!p1 && !p2) goto equal;

	if ((!p1 && p2) || (p1 && !p2)) {
		DEBUG(10, ("nt_printer_param_equal(): pointers differ\n"));
		return False;
	}

	/* Compare lists of printer parameters */

	while (p1) {
		BOOL found = False;
		NT_PRINTER_PARAM *q = p1;

		/* Find the parameter in the second structure */

		while(q) {

			if (strequal(p1->value, q->value)) {

				if (p1->type != q->type) {
					DEBUG(10, ("nt_printer_param_equal():"
						   "types for %s differ (%d != %d)\n",
						   p1->value, p1->type,
						   q->type));
					break;
				}

				if (p1->data_len != q->data_len) {
					DEBUG(10, ("nt_printer_param_equal():"
						   "len for %s differs (%d != %d)\n",
						   p1->value, p1->data_len,
						   q->data_len));
					break;
				}

				if (memcmp(p1->data, q->data, p1->data_len) == 0) {
					found = True;
				} else {
					DEBUG(10, ("nt_printer_param_equal():"
						   "data for %s differs\n", p1->value));
				}

				break;
			}

			q = q->next;
		}

		if (!found) {
			DEBUG(10, ("nt_printer_param_equal(): param %s "
				   "does not exist\n", p1->value));
			return False;
		}

		p1 = p1->next;
	}

	equal:

	DEBUG(10, ("nt_printer_param_equal(): printer params identical\n"));
	return True;
}

/********************************************************************
 * Called by update_printer when trying to work out whether to
 * actually update printer info.
 ********************************************************************/

#define PI_CHECK_INT(field) \
    if (pi1->field != pi2->field) { \
        DEBUG(10, ("nt_printer_info_level_equal(): " #field " not equal (%d != %d)\n", \
            pi1->field, pi2->field)); \
        return False; \
    }

#define PI_CHECK_STR(field) \
    if (!strequal(pi1->field, pi2->field)) { \
        DEBUG(10, ("nt_printer_info_level_equal(): " #field " not equal (%s != %s)\n", \
            pi1->field, pi2->field)); \
        return False; \
    }

static BOOL nt_printer_info_level_equal(NT_PRINTER_INFO_LEVEL *p1,
					NT_PRINTER_INFO_LEVEL *p2)
{
	NT_PRINTER_INFO_LEVEL_2 *pi1, *pi2;

	/* Trivial conditions */

	if ((!p1 && !p2) || (!p1->info_2 && !p2->info_2)) {
		goto equal;
	}

	if ((!p1 && p2) || (p1 && !p2) ||
	    (!p1->info_2 && p2->info_2) ||
	    (p1->info_2 && !p2->info_2)) {
		DEBUG(10, ("nt_printer_info_level_equal(): info levels "
			   "differ\n"));
		return False;
	}

	/* Compare two nt_printer_info_level structures.  Don't compare
	   status or cjobs as they seem to have something to do with the
	   printer queue. */

	pi1 = p1->info_2;
	pi2 = p2->info_2;

	/* Don't check the attributes as we stomp on the value in
	   check_printer_ok() anyway. */

#if 0
	PI_CHECK_INT(attributes);
#endif

	PI_CHECK_INT(priority);
	PI_CHECK_INT(default_priority);
	PI_CHECK_INT(starttime);
	PI_CHECK_INT(untiltime);
	PI_CHECK_INT(averageppm);

	/* Yuck - don't check the printername or servername as the
	   add_a_printer() code plays games with them.  You can't
	   change the printername or the sharename through this interface
	   in Samba. */

	PI_CHECK_STR(sharename);
	PI_CHECK_STR(portname);
	PI_CHECK_STR(drivername);
	PI_CHECK_STR(comment);
	PI_CHECK_STR(location);

	if (!nt_devicemode_equal(pi1->devmode, pi2->devmode)) {
		return False;
	}

	PI_CHECK_STR(sepfile);
	PI_CHECK_STR(printprocessor);
	PI_CHECK_STR(datatype);
	PI_CHECK_STR(parameters);

	if (!nt_printer_param_equal(pi1->specific, pi2->specific)) {
		return False;
	}

	if (!sec_desc_equal(pi1->secdesc_buf->sec, pi2->secdesc_buf->sec)) {
		return False;
	}

	PI_CHECK_INT(changeid);
	PI_CHECK_INT(c_setprinter);
	PI_CHECK_INT(setuptime);

 equal:
	DEBUG(10, ("nt_printer_info_level_equal(): infos are identical\n"));
	return True;
}

/********************************************************************
 * called by spoolss_api_setprinter
 * when updating a printer description
 ********************************************************************/

static WERROR update_printer(pipes_struct *p, POLICY_HND *handle, uint32 level,
                           const SPOOL_PRINTER_INFO_LEVEL *info,
                           DEVICEMODE *devmode)
{
	int snum;
	NT_PRINTER_INFO_LEVEL *printer = NULL, *old_printer = NULL;
	Printer_entry *Printer = find_printer_index_by_hnd(p, handle);
	WERROR result;

	DEBUG(8,("update_printer\n"));
	
	result = WERR_OK;

	if (level!=2) {
		DEBUG(0,("Send a mail to samba@samba.org\n"));
		DEBUGADD(0,("with the following message: update_printer: level!=2\n"));
		result = WERR_UNKNOWN_LEVEL;
		goto done;
	}

	if (!Printer) {
		result = WERR_BADFID;
		goto done;
	}

	if (!get_printer_snum(p, handle, &snum)) {
		result = WERR_BADFID;
		goto done;
	}

	if (!W_ERROR_IS_OK(get_a_printer(&printer, 2, lp_servicename(snum))) ||
	    (!W_ERROR_IS_OK(get_a_printer(&old_printer, 2, lp_servicename(snum))))) {
		result = WERR_BADFID;
		goto done;
	}

	DEBUGADD(8,("Converting info_2 struct\n"));

	/*
	 * convert_printer_info converts the incoming
	 * info from the client and overwrites the info
	 * just read from the tdb in the pointer 'printer'.
	 */

	convert_printer_info(info, printer, level);

	if (info->info_2->devmode_ptr != 0) {
		/* we have a valid devmode
		   convert it and link it*/

		DEBUGADD(8,("Converting the devicemode struct\n"));
		if (!convert_devicemode(printer->info_2->printername, devmode,
				&printer->info_2->devmode)) {
			result =  WERR_NOMEM;
			goto done;
		}
	}

	/* Do sanity check on the requested changes for Samba */

	if (!check_printer_ok(printer->info_2, snum)) {
		result = WERR_INVALID_PARAM;
		goto done;
	}

	/* NT likes to call this function even though nothing has actually
	   changed.  Check this so the user doesn't end up with an
	   annoying permission denied dialog box. */

	if (nt_printer_info_level_equal(printer, old_printer)) {
		DEBUG(3, ("printer info has not changed\n"));
		result = WERR_OK;
		goto done;
	}

	/* Check calling user has permission to update printer description */

	if (!print_access_check(NULL, snum, PRINTER_ACCESS_ADMINISTER)) {
		DEBUG(3, ("printer property change denied by security "
			  "descriptor\n"));
		result = WERR_ACCESS_DENIED;
		goto done;
	}

	/* Call addprinter hook */

	if (*lp_addprinter_cmd()) {
		if ( !add_printer_hook(printer) ) {
			result = WERR_ACCESS_DENIED;
			goto done;
		}
	}
	
	/* Update printer info */
	result = add_a_printer(*printer, 2);

 done:
	free_a_printer(&printer, 2);
	free_a_printer(&old_printer, 2);

	srv_spoolss_sendnotify(p, handle);

	return result;
}

/****************************************************************************
****************************************************************************/

WERROR _spoolss_setprinter(pipes_struct *p, SPOOL_Q_SETPRINTER *q_u, SPOOL_R_SETPRINTER *r_u)
{
	POLICY_HND *handle = &q_u->handle;
	uint32 level = q_u->level;
	SPOOL_PRINTER_INFO_LEVEL *info = &q_u->info;
	DEVMODE_CTR devmode_ctr = q_u->devmode_ctr;
	SEC_DESC_BUF *secdesc_ctr = q_u->secdesc_ctr;
	uint32 command = q_u->command;

	Printer_entry *Printer = find_printer_index_by_hnd(p, handle);
	
	if (!Printer) {
		DEBUG(0,("_spoolss_setprinter: Invalid handle (%s)\n", OUR_HANDLE(handle)));
		return WERR_BADFID;
	}

	/* check the level */	
	switch (level) {
		case 0:
			return control_printer(handle, command, p);
		case 2:
			return update_printer(p, handle, level, info, devmode_ctr.devmode);
		case 3:
			return update_printer_sec(handle, level, info, p,
						  secdesc_ctr);
		default:
			return WERR_UNKNOWN_LEVEL;
	}
}

/****************************************************************************
****************************************************************************/

WERROR _spoolss_fcpn(pipes_struct *p, SPOOL_Q_FCPN *q_u, SPOOL_R_FCPN *r_u)
{
	POLICY_HND *handle = &q_u->handle;

	Printer_entry *Printer= find_printer_index_by_hnd(p, handle);
	
	if (!Printer) {
		DEBUG(0,("_spoolss_fcpn: Invalid handle (%s)\n", OUR_HANDLE(handle)));
		return WERR_BADFID;
	}

	if (Printer->notify.client_connected==True)
		srv_spoolss_replycloseprinter(&Printer->notify.client_hnd);

	Printer->notify.flags=0;
	Printer->notify.options=0;
	Printer->notify.localmachine[0]='\0';
	Printer->notify.printerlocal=0;
	if (Printer->notify.option)
		free_spool_notify_option(&Printer->notify.option);
	Printer->notify.client_connected=False;

	return WERR_OK;
}

/****************************************************************************
****************************************************************************/

WERROR _spoolss_addjob(pipes_struct *p, SPOOL_Q_ADDJOB *q_u, SPOOL_R_ADDJOB *r_u)
{
	/* that's an [in out] buffer (despite appearences to the contrary) */
	spoolss_move_buffer(q_u->buffer, &r_u->buffer);

	r_u->needed = 0;
	return WERR_INVALID_PARAM; /* this is what a NT server
                                           returns for AddJob. AddJob
                                           must fail on non-local
                                           printers */
}

/****************************************************************************
****************************************************************************/
static void fill_job_info_1(JOB_INFO_1 *job_info, print_queue_struct *queue,
                            int position, int snum)
{
	pstring temp_name;
	
	struct tm *t;
	
	t=gmtime(&queue->time);
	slprintf(temp_name, sizeof(temp_name)-1, "\\\\%s", global_myname);

	job_info->jobid=queue->job;	
	init_unistr(&job_info->printername, lp_servicename(snum));
	init_unistr(&job_info->machinename, temp_name);
	init_unistr(&job_info->username, queue->user);
	init_unistr(&job_info->document, queue->file);
	init_unistr(&job_info->datatype, "RAW");
	init_unistr(&job_info->text_status, "");
	job_info->status=nt_printj_status(queue->status);
	job_info->priority=queue->priority;
	job_info->position=position;
	job_info->totalpages=0;
	job_info->pagesprinted=0;

	make_systemtime(&job_info->submitted, t);
}

/****************************************************************************
****************************************************************************/
static BOOL fill_job_info_2(JOB_INFO_2 *job_info, print_queue_struct *queue,
                            int position, int snum, 
			    NT_PRINTER_INFO_LEVEL *ntprinter)
{
	pstring temp_name;
	pstring chaine;
	struct tm *t;

	t=gmtime(&queue->time);
	slprintf(temp_name, sizeof(temp_name)-1, "\\\\%s", global_myname);

	job_info->jobid=queue->job;
	
	slprintf(chaine, sizeof(chaine)-1, "\\\\%s\\%s", global_myname, ntprinter->info_2->printername);

	init_unistr(&job_info->printername, chaine);
	
	init_unistr(&job_info->machinename, temp_name);
	init_unistr(&job_info->username, queue->user);
	init_unistr(&job_info->document, queue->file);
	init_unistr(&job_info->notifyname, queue->user);
	init_unistr(&job_info->datatype, "RAW");
	init_unistr(&job_info->printprocessor, "winprint");
	init_unistr(&job_info->parameters, "");
	init_unistr(&job_info->drivername, ntprinter->info_2->drivername);
	init_unistr(&job_info->text_status, "");
	
/* and here the security descriptor */

	job_info->status=nt_printj_status(queue->status);
	job_info->priority=queue->priority;
	job_info->position=position;
	job_info->starttime=0;
	job_info->untiltime=0;
	job_info->totalpages=0;
	job_info->size=queue->size;
	make_systemtime(&(job_info->submitted), t);
	job_info->timeelapsed=0;
	job_info->pagesprinted=0;

	if((job_info->devmode = construct_dev_mode(snum)) == NULL) {
		return False;
	}

	return (True);
}

/****************************************************************************
 Enumjobs at level 1.
****************************************************************************/
static WERROR enumjobs_level1(print_queue_struct *queue, int snum,
			      NEW_BUFFER *buffer, uint32 offered,
			      uint32 *needed, uint32 *returned)
{
	JOB_INFO_1 *info;
	int i;
	
	info=(JOB_INFO_1 *)malloc(*returned*sizeof(JOB_INFO_1));
	if (info==NULL) {
		SAFE_FREE(queue);
		*returned=0;
		return WERR_NOMEM;
	}
	
	for (i=0; i<*returned; i++)
		fill_job_info_1(&info[i], &queue[i], i, snum);

	SAFE_FREE(queue);

	/* check the required size. */	
	for (i=0; i<*returned; i++)
		(*needed) += spoolss_size_job_info_1(&info[i]);

	if (!alloc_buffer_size(buffer, *needed)) {
		SAFE_FREE(info);
		return WERR_INSUFFICIENT_BUFFER;
	}

	/* fill the buffer with the structures */
	for (i=0; i<*returned; i++)
		smb_io_job_info_1("", buffer, &info[i], 0);	

	/* clear memory */
	SAFE_FREE(info);

	if (*needed > offered) {
		*returned=0;
		return WERR_INSUFFICIENT_BUFFER;
	}

	return WERR_OK;
}

/****************************************************************************
 Enumjobs at level 2.
****************************************************************************/
static WERROR enumjobs_level2(print_queue_struct *queue, int snum,
			      NEW_BUFFER *buffer, uint32 offered,
			      uint32 *needed, uint32 *returned)
{
	NT_PRINTER_INFO_LEVEL *ntprinter = NULL;
	JOB_INFO_2 *info;
	int i;
	WERROR result;
	
	info=(JOB_INFO_2 *)malloc(*returned*sizeof(JOB_INFO_2));
	if (info==NULL) {
		*returned=0;
		return WERR_NOMEM;
	}

	result = get_a_printer(&ntprinter, 2, lp_servicename(snum));
	if (!W_ERROR_IS_OK(result)) {
		*returned = 0;
		return result;
	}
		
	for (i=0; i<*returned; i++)
		fill_job_info_2(&(info[i]), &queue[i], i, snum, ntprinter);

	free_a_printer(&ntprinter, 2);
	SAFE_FREE(queue);

	/* check the required size. */	
	for (i=0; i<*returned; i++)
		(*needed) += spoolss_size_job_info_2(&info[i]);

	if (!alloc_buffer_size(buffer, *needed)) {
		SAFE_FREE(info);
		return WERR_INSUFFICIENT_BUFFER;
	}

	/* fill the buffer with the structures */
	for (i=0; i<*returned; i++)
		smb_io_job_info_2("", buffer, &info[i], 0);	

	/* clear memory */
	for (i = 0; i < *returned; i++)
		free_job_info_2(&info[i]);

	SAFE_FREE(info);

	if (*needed > offered) {
		*returned=0;
		return WERR_INSUFFICIENT_BUFFER;
	}

	return WERR_OK;
}

/****************************************************************************
 Enumjobs.
****************************************************************************/

WERROR _spoolss_enumjobs( pipes_struct *p, SPOOL_Q_ENUMJOBS *q_u, SPOOL_R_ENUMJOBS *r_u)
{	
	POLICY_HND *handle = &q_u->handle;
/*	uint32 firstjob = q_u->firstjob; - notused. */
/*	uint32 numofjobs = q_u->numofjobs; - notused. */
	uint32 level = q_u->level;
	NEW_BUFFER *buffer = NULL;
	uint32 offered = q_u->offered;
	uint32 *needed = &r_u->needed;
	uint32 *returned = &r_u->returned;

	int snum;
	print_queue_struct *queue=NULL;
	print_status_struct prt_status;

	/* that's an [in out] buffer */
	spoolss_move_buffer(q_u->buffer, &r_u->buffer);
	buffer = r_u->buffer;

	DEBUG(4,("_spoolss_enumjobs\n"));

	ZERO_STRUCT(prt_status);

	*needed=0;
	*returned=0;

	if (!get_printer_snum(p, handle, &snum))
		return WERR_BADFID;

	*returned = print_queue_status(snum, &queue, &prt_status);
	DEBUGADD(4,("count:[%d], status:[%d], [%s]\n", *returned, prt_status.status, prt_status.message));

	if (*returned == 0) {
		SAFE_FREE(queue);
		return WERR_OK;
	}

	switch (level) {
	case 1:
		return enumjobs_level1(queue, snum, buffer, offered, needed, returned);
	case 2:
		return enumjobs_level2(queue, snum, buffer, offered, needed, returned);
	default:
		SAFE_FREE(queue);
		*returned=0;
		return WERR_UNKNOWN_LEVEL;
	}
}

/****************************************************************************
****************************************************************************/

WERROR _spoolss_schedulejob( pipes_struct *p, SPOOL_Q_SCHEDULEJOB *q_u, SPOOL_R_SCHEDULEJOB *r_u)
{
	return WERR_OK;
}

/****************************************************************************
****************************************************************************/

WERROR _spoolss_setjob(pipes_struct *p, SPOOL_Q_SETJOB *q_u, SPOOL_R_SETJOB *r_u)
{
	POLICY_HND *handle = &q_u->handle;
	uint32 jobid = q_u->jobid;
/*	uint32 level = q_u->level; - notused. */
/*	JOB_INFO *ctr = &q_u->ctr; - notused. */
	uint32 command = q_u->command;

	struct current_user user;
	print_status_struct prt_status;
	int snum;
	WERROR errcode = WERR_BADFUNC;
		
	memset(&prt_status, 0, sizeof(prt_status));

	if (!get_printer_snum(p, handle, &snum)) {
		return WERR_BADFID;
	}

	if (!print_job_exists(jobid)) {
		return WERR_INVALID_PRINTER_NAME;
	}

	get_current_user(&user, p);	

	switch (command) {
	case JOB_CONTROL_CANCEL:
	case JOB_CONTROL_DELETE:
		if (print_job_delete(&user, jobid, &errcode)) {
			errcode = WERR_OK;
		}
		break;
	case JOB_CONTROL_PAUSE:
		if (print_job_pause(&user, jobid, &errcode)) {
			errcode = WERR_OK;
		}		
		break;
	case JOB_CONTROL_RESTART:
	case JOB_CONTROL_RESUME:
		if (print_job_resume(&user, jobid, &errcode)) {
			errcode = WERR_OK;
		}
		break;
	default:
		return WERR_UNKNOWN_LEVEL;
	}

	return errcode;
}

/****************************************************************************
 Enumerates all printer drivers at level 1.
****************************************************************************/
static WERROR enumprinterdrivers_level1(fstring servername, fstring architecture, NEW_BUFFER *buffer, uint32 offered, uint32 *needed, uint32 *returned)
{
	int i;
	int ndrivers;
	uint32 version;
	fstring *list = NULL;

	NT_PRINTER_DRIVER_INFO_LEVEL driver;
	DRIVER_INFO_1 *tdi1, *driver_info_1=NULL;

	*returned=0;

#define MAX_VERSION 4

	for (version=0; version<MAX_VERSION; version++) {
		list=NULL;
		ndrivers=get_ntdrivers(&list, architecture, version);
		DEBUGADD(4,("we have:[%d] drivers in environment [%s] and version [%d]\n", ndrivers, architecture, version));

		if(ndrivers == -1)
			return WERR_NOMEM;

		if(ndrivers != 0) {
			if((tdi1=(DRIVER_INFO_1 *)Realloc(driver_info_1, (*returned+ndrivers) * sizeof(DRIVER_INFO_1))) == NULL) {
				DEBUG(0,("enumprinterdrivers_level1: failed to enlarge driver info buffer!\n"));
				SAFE_FREE(driver_info_1);
				SAFE_FREE(list);
				return WERR_NOMEM;
			}
			else driver_info_1 = tdi1;
		}

		for (i=0; i<ndrivers; i++) {
			WERROR status;
			DEBUGADD(5,("\tdriver: [%s]\n", list[i]));
			ZERO_STRUCT(driver);
			status = get_a_printer_driver(&driver, 3, list[i], 
						      architecture, version);
			if (!W_ERROR_IS_OK(status)) {
				SAFE_FREE(list);
				return status;
			}
			fill_printer_driver_info_1(&driver_info_1[*returned+i], driver, servername, architecture );		
			free_a_printer_driver(driver, 3);
		}	

		*returned+=ndrivers;
		SAFE_FREE(list);
	}
	
	/* check the required size. */
	for (i=0; i<*returned; i++) {
		DEBUGADD(6,("adding driver [%d]'s size\n",i));
		*needed += spoolss_size_printer_driver_info_1(&driver_info_1[i]);
	}

	if (!alloc_buffer_size(buffer, *needed)) {
		SAFE_FREE(driver_info_1);
		return WERR_INSUFFICIENT_BUFFER;
	}

	/* fill the buffer with the driver structures */
	for (i=0; i<*returned; i++) {
		DEBUGADD(6,("adding driver [%d] to buffer\n",i));
		smb_io_printer_driver_info_1("", buffer, &driver_info_1[i], 0);
	}

	SAFE_FREE(driver_info_1);

	if (*needed > offered) {
		*returned=0;
		return WERR_INSUFFICIENT_BUFFER;
	}

	return WERR_OK;
}

/****************************************************************************
 Enumerates all printer drivers at level 2.
****************************************************************************/
static WERROR enumprinterdrivers_level2(fstring servername, fstring architecture, NEW_BUFFER *buffer, uint32 offered, uint32 *needed, uint32 *returned)
{
	int i;
	int ndrivers;
	uint32 version;
	fstring *list = NULL;

	NT_PRINTER_DRIVER_INFO_LEVEL driver;
	DRIVER_INFO_2 *tdi2, *driver_info_2=NULL;

	*returned=0;

#define MAX_VERSION 4

	for (version=0; version<MAX_VERSION; version++) {
		list=NULL;
		ndrivers=get_ntdrivers(&list, architecture, version);
		DEBUGADD(4,("we have:[%d] drivers in environment [%s] and version [%d]\n", ndrivers, architecture, version));

		if(ndrivers == -1)
			return WERR_NOMEM;

		if(ndrivers != 0) {
			if((tdi2=(DRIVER_INFO_2 *)Realloc(driver_info_2, (*returned+ndrivers) * sizeof(DRIVER_INFO_2))) == NULL) {
				DEBUG(0,("enumprinterdrivers_level2: failed to enlarge driver info buffer!\n"));
				SAFE_FREE(driver_info_2);
				SAFE_FREE(list);
				return WERR_NOMEM;
			}
			else driver_info_2 = tdi2;
		}
		
		for (i=0; i<ndrivers; i++) {
			WERROR status;

			DEBUGADD(5,("\tdriver: [%s]\n", list[i]));
			ZERO_STRUCT(driver);
			status = get_a_printer_driver(&driver, 3, list[i], 
						      architecture, version);
			if (!W_ERROR_IS_OK(status)) {
				SAFE_FREE(list);
				return status;
			}
			fill_printer_driver_info_2(&driver_info_2[*returned+i], driver, servername);		
			free_a_printer_driver(driver, 3);
		}	

		*returned+=ndrivers;
		SAFE_FREE(list);
	}
	
	/* check the required size. */
	for (i=0; i<*returned; i++) {
		DEBUGADD(6,("adding driver [%d]'s size\n",i));
		*needed += spoolss_size_printer_driver_info_2(&(driver_info_2[i]));
	}

	if (!alloc_buffer_size(buffer, *needed)) {
		SAFE_FREE(driver_info_2);
		return WERR_INSUFFICIENT_BUFFER;
	}

	/* fill the buffer with the form structures */
	for (i=0; i<*returned; i++) {
		DEBUGADD(6,("adding driver [%d] to buffer\n",i));
		smb_io_printer_driver_info_2("", buffer, &(driver_info_2[i]), 0);
	}

	SAFE_FREE(driver_info_2);

	if (*needed > offered) {
		*returned=0;
		return WERR_INSUFFICIENT_BUFFER;
	}

	return WERR_OK;
}

/****************************************************************************
 Enumerates all printer drivers at level 3.
****************************************************************************/
static WERROR enumprinterdrivers_level3(fstring servername, fstring architecture, NEW_BUFFER *buffer, uint32 offered, uint32 *needed, uint32 *returned)
{
	int i;
	int ndrivers;
	uint32 version;
	fstring *list = NULL;

	NT_PRINTER_DRIVER_INFO_LEVEL driver;
	DRIVER_INFO_3 *tdi3, *driver_info_3=NULL;

	*returned=0;

#define MAX_VERSION 4

	for (version=0; version<MAX_VERSION; version++) {
		list=NULL;
		ndrivers=get_ntdrivers(&list, architecture, version);
		DEBUGADD(4,("we have:[%d] drivers in environment [%s] and version [%d]\n", ndrivers, architecture, version));

		if(ndrivers == -1)
			return WERR_NOMEM;

		if(ndrivers != 0) {
			if((tdi3=(DRIVER_INFO_3 *)Realloc(driver_info_3, (*returned+ndrivers) * sizeof(DRIVER_INFO_3))) == NULL) {
				DEBUG(0,("enumprinterdrivers_level3: failed to enlarge driver info buffer!\n"));
				SAFE_FREE(driver_info_3);
				SAFE_FREE(list);
				return WERR_NOMEM;
			}
			else driver_info_3 = tdi3;
		}

		for (i=0; i<ndrivers; i++) {
			WERROR status;

			DEBUGADD(5,("\tdriver: [%s]\n", list[i]));
			ZERO_STRUCT(driver);
			status = get_a_printer_driver(&driver, 3, list[i], 
						      architecture, version);
			if (!W_ERROR_IS_OK(status)) {
				SAFE_FREE(list);
				return status;
			}
			fill_printer_driver_info_3(&driver_info_3[*returned+i], driver, servername);		
			free_a_printer_driver(driver, 3);
		}	

		*returned+=ndrivers;
		SAFE_FREE(list);
	}

	/* check the required size. */
	for (i=0; i<*returned; i++) {
		DEBUGADD(6,("adding driver [%d]'s size\n",i));
		*needed += spoolss_size_printer_driver_info_3(&driver_info_3[i]);
	}

	if (!alloc_buffer_size(buffer, *needed)) {
		SAFE_FREE(driver_info_3);
		return WERR_INSUFFICIENT_BUFFER;
	}
	
	/* fill the buffer with the driver structures */
	for (i=0; i<*returned; i++) {
		DEBUGADD(6,("adding driver [%d] to buffer\n",i));
		smb_io_printer_driver_info_3("", buffer, &driver_info_3[i], 0);
	}

	for (i=0; i<*returned; i++)
		SAFE_FREE(driver_info_3[i].dependentfiles);
	
	SAFE_FREE(driver_info_3);
	
	if (*needed > offered) {
		*returned=0;
		return WERR_INSUFFICIENT_BUFFER;
	}

	return WERR_OK;
}

/****************************************************************************
 Enumerates all printer drivers.
****************************************************************************/

WERROR _spoolss_enumprinterdrivers( pipes_struct *p, SPOOL_Q_ENUMPRINTERDRIVERS *q_u, SPOOL_R_ENUMPRINTERDRIVERS *r_u)
{
/*	UNISTR2 *name = &q_u->name; - notused. */
	UNISTR2 *environment = &q_u->environment;
	uint32 level = q_u->level;
	NEW_BUFFER *buffer = NULL;
	uint32 offered = q_u->offered;
	uint32 *needed = &r_u->needed;
	uint32 *returned = &r_u->returned;

	fstring *list = NULL;
	fstring servername;
	fstring architecture;

	/* that's an [in out] buffer */
	spoolss_move_buffer(q_u->buffer, &r_u->buffer);
	buffer = r_u->buffer;

	DEBUG(4,("_spoolss_enumprinterdrivers\n"));
	fstrcpy(servername, global_myname);
	*needed=0;
	*returned=0;

	unistr2_to_ascii(architecture, environment, sizeof(architecture)-1);

	switch (level) {
	case 1:
		return enumprinterdrivers_level1(servername, architecture, buffer, offered, needed, returned);
	case 2:
		return enumprinterdrivers_level2(servername, architecture, buffer, offered, needed, returned);
	case 3:
		return enumprinterdrivers_level3(servername, architecture, buffer, offered, needed, returned);
	default:
		*returned=0;
		SAFE_FREE(list);
		return WERR_UNKNOWN_LEVEL;
	}
}

/****************************************************************************
****************************************************************************/

static void fill_form_1(FORM_1 *form, nt_forms_struct *list)
{
	form->flag=list->flag;
	init_unistr(&form->name, list->name);
	form->width=list->width;
	form->length=list->length;
	form->left=list->left;
	form->top=list->top;
	form->right=list->right;
	form->bottom=list->bottom;	
}
	
/****************************************************************************
****************************************************************************/

WERROR _spoolss_enumforms(pipes_struct *p, SPOOL_Q_ENUMFORMS *q_u, SPOOL_R_ENUMFORMS *r_u)
{
/*	POLICY_HND *handle = &q_u->handle; - notused. */
	uint32 level = q_u->level;
	NEW_BUFFER *buffer = NULL;
	uint32 offered = q_u->offered;
	uint32 *needed = &r_u->needed;
	uint32 *numofforms = &r_u->numofforms;
	uint32 numbuiltinforms;

	nt_forms_struct *list=NULL;
	nt_forms_struct *builtinlist=NULL;
	FORM_1 *forms_1;
	int buffer_size=0;
	int i;

	/* that's an [in out] buffer */
	spoolss_move_buffer(q_u->buffer, &r_u->buffer);
	buffer = r_u->buffer;

	DEBUG(4,("_spoolss_enumforms\n"));
	DEBUGADD(5,("Offered buffer size [%d]\n", offered));
	DEBUGADD(5,("Info level [%d]\n",          level));

	numbuiltinforms = get_builtin_ntforms(&builtinlist);
	DEBUGADD(5,("Number of builtin forms [%d]\n",     numbuiltinforms));
	*numofforms = get_ntforms(&list);
	DEBUGADD(5,("Number of user forms [%d]\n",     *numofforms));
	*numofforms += numbuiltinforms;

	if (*numofforms == 0) return WERR_NO_MORE_ITEMS;

	switch (level) {
	case 1:
		if ((forms_1=(FORM_1 *)malloc(*numofforms * sizeof(FORM_1))) == NULL) {
			*numofforms=0;
			return WERR_NOMEM;
		}

		/* construct the list of form structures */
		for (i=0; i<numbuiltinforms; i++) {
			DEBUGADD(6,("Filling form number [%d]\n",i));
			fill_form_1(&forms_1[i], &builtinlist[i]);
		}
		
		SAFE_FREE(builtinlist);

		for (; i<*numofforms; i++) {
			DEBUGADD(6,("Filling form number [%d]\n",i));
			fill_form_1(&forms_1[i], &list[i-numbuiltinforms]);
		}
		
		SAFE_FREE(list);

		/* check the required size. */
		for (i=0; i<numbuiltinforms; i++) {
			DEBUGADD(6,("adding form [%d]'s size\n",i));
			buffer_size += spoolss_size_form_1(&forms_1[i]);
		}
		for (; i<*numofforms; i++) {
			DEBUGADD(6,("adding form [%d]'s size\n",i));
			buffer_size += spoolss_size_form_1(&forms_1[i]);
		}

		*needed=buffer_size;		
		
		if (!alloc_buffer_size(buffer, buffer_size)){
			SAFE_FREE(forms_1);
			return WERR_INSUFFICIENT_BUFFER;
		}

		/* fill the buffer with the form structures */
		for (i=0; i<numbuiltinforms; i++) {
			DEBUGADD(6,("adding form [%d] to buffer\n",i));
			smb_io_form_1("", buffer, &forms_1[i], 0);
		}
		for (; i<*numofforms; i++) {
			DEBUGADD(6,("adding form [%d] to buffer\n",i));
			smb_io_form_1("", buffer, &forms_1[i], 0);
		}

		SAFE_FREE(forms_1);

		if (*needed > offered) {
			*numofforms=0;
			return WERR_INSUFFICIENT_BUFFER;
		}
		else
			return WERR_OK;
			
	default:
		SAFE_FREE(list);
		SAFE_FREE(builtinlist);
		return WERR_UNKNOWN_LEVEL;
	}

}

/****************************************************************************
****************************************************************************/

WERROR _spoolss_getform(pipes_struct *p, SPOOL_Q_GETFORM *q_u, SPOOL_R_GETFORM *r_u)
{
/*	POLICY_HND *handle = &q_u->handle; - notused. */
	uint32 level = q_u->level;
	UNISTR2 *uni_formname = &q_u->formname;
	NEW_BUFFER *buffer = NULL;
	uint32 offered = q_u->offered;
	uint32 *needed = &r_u->needed;

	nt_forms_struct *list=NULL;
	nt_forms_struct builtin_form;
	BOOL foundBuiltin;
	FORM_1 form_1;
	fstring form_name;
	int buffer_size=0;
	int numofforms=0, i=0;

	/* that's an [in out] buffer */
	spoolss_move_buffer(q_u->buffer, &r_u->buffer);
	buffer = r_u->buffer;

	unistr2_to_ascii(form_name, uni_formname, sizeof(form_name)-1);

	DEBUG(4,("_spoolss_getform\n"));
	DEBUGADD(5,("Offered buffer size [%d]\n", offered));
	DEBUGADD(5,("Info level [%d]\n",          level));

	foundBuiltin = get_a_builtin_ntform(uni_formname,&builtin_form);
	if (!foundBuiltin) {
		numofforms = get_ntforms(&list);
		DEBUGADD(5,("Number of forms [%d]\n",     numofforms));

		if (numofforms == 0)
			return WERR_BADFID;
	}

	switch (level) {
	case 1:
		if (foundBuiltin) {
			fill_form_1(&form_1, &builtin_form);
		} else {

			/* Check if the requested name is in the list of form structures */
			for (i=0; i<numofforms; i++) {

				DEBUG(4,("_spoolss_getform: checking form %s (want %s)\n", list[i].name, form_name));

				if (strequal(form_name, list[i].name)) {
					DEBUGADD(6,("Found form %s number [%d]\n", form_name, i));
					fill_form_1(&form_1, &list[i]);
					break;
				}
			}
			
			SAFE_FREE(list);
			if (i == numofforms) {
				return WERR_BADFID;
			}
		}
		/* check the required size. */

		*needed=spoolss_size_form_1(&form_1);
		
		if (!alloc_buffer_size(buffer, buffer_size)){
			return WERR_INSUFFICIENT_BUFFER;
		}

		if (*needed > offered) {
			return WERR_INSUFFICIENT_BUFFER;
		}

		/* fill the buffer with the form structures */
		DEBUGADD(6,("adding form %s [%d] to buffer\n", form_name, i));
		smb_io_form_1("", buffer, &form_1, 0);

		return WERR_OK;
			
	default:
		SAFE_FREE(list);
		return WERR_UNKNOWN_LEVEL;
	}
}

/****************************************************************************
****************************************************************************/
static void fill_port_1(PORT_INFO_1 *port, char *name)
{
	init_unistr(&port->port_name, name);
}

/****************************************************************************
****************************************************************************/
static void fill_port_2(PORT_INFO_2 *port, char *name)
{
	init_unistr(&port->port_name, name);
	init_unistr(&port->monitor_name, "Local Monitor");
	init_unistr(&port->description, "Local Port");
#define PORT_TYPE_WRITE 1
	port->port_type=PORT_TYPE_WRITE;
	port->reserved=0x0;	
}

/****************************************************************************
 enumports level 1.
****************************************************************************/
static WERROR enumports_level_1(NEW_BUFFER *buffer, uint32 offered, uint32 *needed, uint32 *returned)
{
	PORT_INFO_1 *ports=NULL;
	int i=0;

	if (*lp_enumports_cmd()) {
		char *cmd = lp_enumports_cmd();
		char **qlines;
		pstring command;
		int numlines;
		int ret;
		int fd;

		slprintf(command, sizeof(command)-1, "%s \"%d\"", cmd, 1);

		DEBUG(10,("Running [%s]\n", command));
		ret = smbrun(command, &fd);
		DEBUG(10,("Returned [%d]\n", ret));
		if (ret != 0) {
			if (fd != -1)
				close(fd);
			/* Is this the best error to return here? */
			return WERR_ACCESS_DENIED;
		}

		numlines = 0;
		qlines = fd_lines_load(fd, &numlines,True);
		DEBUGADD(10,("Lines returned = [%d]\n", numlines));
		close(fd);

		if(numlines) {
			if((ports=(PORT_INFO_1 *)malloc( numlines * sizeof(PORT_INFO_1) )) == NULL) {
				DEBUG(10,("Returning WERR_NOMEM [%s]\n", 
					  werror_str(WERR_NOMEM)));
				file_lines_free(qlines);
				return WERR_NOMEM;
			}

			for (i=0; i<numlines; i++) {
				DEBUG(6,("Filling port number [%d] with port [%s]\n", i, qlines[i]));
				fill_port_1(&ports[i], qlines[i]);
			}

			file_lines_free(qlines);
		}

		*returned = numlines;

	} else {
		*returned = 1; /* Sole Samba port returned. */

		if((ports=(PORT_INFO_1 *)malloc( sizeof(PORT_INFO_1) )) == NULL)
			return WERR_NOMEM;
	
		DEBUG(10,("enumports_level_1: port name %s\n", SAMBA_PRINTER_PORT_NAME));

		fill_port_1(&ports[0], SAMBA_PRINTER_PORT_NAME);
	}

	/* check the required size. */
	for (i=0; i<*returned; i++) {
		DEBUGADD(6,("adding port [%d]'s size\n", i));
		*needed += spoolss_size_port_info_1(&ports[i]);
	}
		
	if (!alloc_buffer_size(buffer, *needed)) {
		SAFE_FREE(ports);
		return WERR_INSUFFICIENT_BUFFER;
	}

	/* fill the buffer with the ports structures */
	for (i=0; i<*returned; i++) {
		DEBUGADD(6,("adding port [%d] to buffer\n", i));
		smb_io_port_1("", buffer, &ports[i], 0);
	}

	SAFE_FREE(ports);

	if (*needed > offered) {
		*returned=0;
		return WERR_INSUFFICIENT_BUFFER;
	}

	return WERR_OK;
}

/****************************************************************************
 enumports level 2.
****************************************************************************/

static WERROR enumports_level_2(NEW_BUFFER *buffer, uint32 offered, uint32 *needed, uint32 *returned)
{
	PORT_INFO_2 *ports=NULL;
	int i=0;

	if (*lp_enumports_cmd()) {
		char *cmd = lp_enumports_cmd();
		char *path;
		char **qlines;
		pstring tmp_file;
		pstring command;
		int numlines;
		int ret;
		int fd;

		if (*lp_pathname(lp_servicenumber(PRINTERS_NAME)))
			path = lp_pathname(lp_servicenumber(PRINTERS_NAME));
		else
			path = lp_lockdir();

		slprintf(tmp_file, sizeof(tmp_file)-1, "%s/smbcmd.%u.", path, (unsigned int)sys_getpid());
		slprintf(command, sizeof(command)-1, "%s \"%d\"", cmd, 2);

		unlink(tmp_file);
		DEBUG(10,("Running [%s > %s]\n", command,tmp_file));
		ret = smbrun(command, &fd);
		DEBUGADD(10,("returned [%d]\n", ret));
		if (ret != 0) {
			if (fd != -1)
				close(fd);
			/* Is this the best error to return here? */
			return WERR_ACCESS_DENIED;
		}

		numlines = 0;
		qlines = fd_lines_load(fd, &numlines,True);
		DEBUGADD(10,("Lines returned = [%d]\n", numlines));
		close(fd);

		if(numlines) {
			if((ports=(PORT_INFO_2 *)malloc( numlines * sizeof(PORT_INFO_2) )) == NULL) {
				file_lines_free(qlines);
				return WERR_NOMEM;
			}

			for (i=0; i<numlines; i++) {
				DEBUG(6,("Filling port number [%d] with port [%s]\n", i, qlines[i]));
				fill_port_2(&(ports[i]), qlines[i]);
			}

			file_lines_free(qlines);
		}

		*returned = numlines;

	} else {

		*returned = 1;

		if((ports=(PORT_INFO_2 *)malloc( sizeof(PORT_INFO_2) )) == NULL)
			return WERR_NOMEM;
	
		DEBUG(10,("enumports_level_2: port name %s\n", SAMBA_PRINTER_PORT_NAME));

		fill_port_2(&ports[0], SAMBA_PRINTER_PORT_NAME);
	}

	/* check the required size. */
	for (i=0; i<*returned; i++) {
		DEBUGADD(6,("adding port [%d]'s size\n", i));
		*needed += spoolss_size_port_info_2(&ports[i]);
	}
		
	if (!alloc_buffer_size(buffer, *needed)) {
		SAFE_FREE(ports);
		return WERR_INSUFFICIENT_BUFFER;
	}

	/* fill the buffer with the ports structures */
	for (i=0; i<*returned; i++) {
		DEBUGADD(6,("adding port [%d] to buffer\n", i));
		smb_io_port_2("", buffer, &ports[i], 0);
	}

	SAFE_FREE(ports);

	if (*needed > offered) {
		*returned=0;
		return WERR_INSUFFICIENT_BUFFER;
	}

	return WERR_OK;
}

/****************************************************************************
 enumports.
****************************************************************************/

WERROR _spoolss_enumports( pipes_struct *p, SPOOL_Q_ENUMPORTS *q_u, SPOOL_R_ENUMPORTS *r_u)
{
/*	UNISTR2 *name = &q_u->name; - notused. */
	uint32 level = q_u->level;
	NEW_BUFFER *buffer = NULL;
	uint32 offered = q_u->offered;
	uint32 *needed = &r_u->needed;
	uint32 *returned = &r_u->returned;

	/* that's an [in out] buffer */
	spoolss_move_buffer(q_u->buffer, &r_u->buffer);
	buffer = r_u->buffer;

	DEBUG(4,("_spoolss_enumports\n"));
	
	*returned=0;
	*needed=0;
	
	switch (level) {
	case 1:
		return enumports_level_1(buffer, offered, needed, returned);
	case 2:
		return enumports_level_2(buffer, offered, needed, returned);
	default:
		return WERR_UNKNOWN_LEVEL;
	}
}

/****************************************************************************
****************************************************************************/
static WERROR spoolss_addprinterex_level_2( pipes_struct *p, const UNISTR2 *uni_srv_name,
				const SPOOL_PRINTER_INFO_LEVEL *info,
				uint32 unk0, uint32 unk1, uint32 unk2, uint32 unk3,
				uint32 user_switch, const SPOOL_USER_CTR *user,
				POLICY_HND *handle)
{
	NT_PRINTER_INFO_LEVEL *printer = NULL;
	fstring	name;
	int	snum;
	WERROR err = WERR_OK;

	if ((printer = (NT_PRINTER_INFO_LEVEL *)malloc(sizeof(NT_PRINTER_INFO_LEVEL))) == NULL) {
		DEBUG(0,("spoolss_addprinterex_level_2: malloc fail.\n"));
		return WERR_NOMEM;
	}

	ZERO_STRUCTP(printer);

	/* convert from UNICODE to ASCII - this allocates the info_2 struct inside *printer.*/
	convert_printer_info(info, printer, 2);

	/* check to see if the printer already exists */

	if ((snum = print_queue_snum(printer->info_2->sharename)) != -1) {
		DEBUG(5, ("_spoolss_addprinterex: Attempted to add a printer named [%s] when one already existed!\n", 
			printer->info_2->sharename));
		free_a_printer(&printer, 2);
		return WERR_PRINTER_ALREADY_EXISTS;
	}

	if (*lp_addprinter_cmd() )
		if ( !add_printer_hook(printer) ) {
			free_a_printer(&printer,2);
			return WERR_ACCESS_DENIED;
	}

	slprintf(name, sizeof(name)-1, "\\\\%s\\%s", global_myname,
             printer->info_2->sharename);

	if ((snum = print_queue_snum(printer->info_2->sharename)) == -1) {
		free_a_printer(&printer,2);
		return WERR_ACCESS_DENIED;
	}

	/* you must be a printer admin to add a new printer */
	if (!print_access_check(NULL, snum, PRINTER_ACCESS_ADMINISTER)) {
		free_a_printer(&printer,2);
		return WERR_ACCESS_DENIED;		
	}
	
	/*
	 * Do sanity check on the requested changes for Samba.
	 */

	if (!check_printer_ok(printer->info_2, snum)) {
		free_a_printer(&printer,2);
		return WERR_INVALID_PARAM;
	}

    /*
	 * When a printer is created, the drivername bound to the printer is used
	 * to lookup previously saved driver initialization info, which is then 
	 * bound to the new printer, simulating what happens in the Windows arch.
	 */
	set_driver_init(printer, 2);
	
	/* write the ASCII on disk */
	err = add_a_printer(*printer, 2);
	if (!W_ERROR_IS_OK(err)) {
		free_a_printer(&printer,2);
		return err;
	}

	if (!open_printer_hnd(p, handle, name)) {
		/* Handle open failed - remove addition. */
		del_a_printer(printer->info_2->sharename);
		free_a_printer(&printer,2);
		return WERR_ACCESS_DENIED;
	}

	free_a_printer(&printer,2);

	srv_spoolss_sendnotify(p, handle);

	return WERR_OK;
}

/****************************************************************************
****************************************************************************/

WERROR _spoolss_addprinterex( pipes_struct *p, SPOOL_Q_ADDPRINTEREX *q_u, SPOOL_R_ADDPRINTEREX *r_u)
{
	UNISTR2 *uni_srv_name = &q_u->server_name;
	uint32 level = q_u->level;
	SPOOL_PRINTER_INFO_LEVEL *info = &q_u->info;
	uint32 unk0 = q_u->unk0;
	uint32 unk1 = q_u->unk1;
	uint32 unk2 = q_u->unk2;
	uint32 unk3 = q_u->unk3;
	uint32 user_switch = q_u->user_switch;
	SPOOL_USER_CTR *user = &q_u->user_ctr;
	POLICY_HND *handle = &r_u->handle;

	switch (level) {
		case 1:
			/* we don't handle yet */
			/* but I know what to do ... */
			return WERR_UNKNOWN_LEVEL;
		case 2:
			return spoolss_addprinterex_level_2(p, uni_srv_name, info,
							    unk0, unk1, unk2, unk3,
							    user_switch, user, handle);
		default:
			return WERR_UNKNOWN_LEVEL;
	}
}

/****************************************************************************
****************************************************************************/

WERROR _spoolss_addprinterdriver(pipes_struct *p, SPOOL_Q_ADDPRINTERDRIVER *q_u, SPOOL_R_ADDPRINTERDRIVER *r_u)
{
/*	UNISTR2 *server_name = &q_u->server_name; - notused. */
	uint32 level = q_u->level;
	SPOOL_PRINTER_DRIVER_INFO_LEVEL *info = &q_u->info;
	WERROR err = WERR_OK;
	NT_PRINTER_DRIVER_INFO_LEVEL driver;
	struct current_user user;
	
	ZERO_STRUCT(driver);

	get_current_user(&user, p);	
	
	if (!convert_printer_driver_info(info, &driver, level)) {
		err = WERR_NOMEM;
		goto done;
	}

	DEBUG(5,("Cleaning driver's information\n"));
	err = clean_up_driver_struct(driver, level, &user);
	if (!W_ERROR_IS_OK(err))
		goto done;

	DEBUG(5,("Moving driver to final destination\n"));
	if(!move_driver_to_download_area(driver, level, &user, &err)) {
		if (W_ERROR_IS_OK(err))
			err = WERR_ACCESS_DENIED;
		goto done;
	}

	if (add_a_printer_driver(driver, level)!=0) {
		err = WERR_ACCESS_DENIED;
		goto done;
	}

 done:
	free_a_printer_driver(driver, level);
	return err;
}

/****************************************************************************
****************************************************************************/
static void fill_driverdir_1(DRIVER_DIRECTORY_1 *info, char *name)
{
	init_unistr(&info->name, name);
}

/****************************************************************************
****************************************************************************/
static WERROR getprinterdriverdir_level_1(UNISTR2 *name, UNISTR2 *uni_environment, NEW_BUFFER *buffer, uint32 offered, uint32 *needed)
{
	pstring path;
	pstring long_archi;
	pstring short_archi;
	DRIVER_DIRECTORY_1 *info=NULL;

	unistr2_to_ascii(long_archi, uni_environment, sizeof(long_archi)-1);

	if (get_short_archi(short_archi, long_archi)==False)
		return WERR_INVALID_ENVIRONMENT;

	if((info=(DRIVER_DIRECTORY_1 *)malloc(sizeof(DRIVER_DIRECTORY_1))) == NULL)
		return WERR_NOMEM;

	slprintf(path, sizeof(path)-1, "\\\\%s\\print$\\%s", global_myname, short_archi);

	DEBUG(4,("printer driver directory: [%s]\n", path));

	fill_driverdir_1(info, path);
	
	*needed += spoolss_size_driverdir_info_1(info);

	if (!alloc_buffer_size(buffer, *needed)) {
		SAFE_FREE(info);
		return WERR_INSUFFICIENT_BUFFER;
	}

	smb_io_driverdir_1("", buffer, info, 0);

	SAFE_FREE(info);
	
	if (*needed > offered)
		return WERR_INSUFFICIENT_BUFFER;

	return WERR_OK;
}

/****************************************************************************
****************************************************************************/

WERROR _spoolss_getprinterdriverdirectory(pipes_struct *p, SPOOL_Q_GETPRINTERDRIVERDIR *q_u, SPOOL_R_GETPRINTERDRIVERDIR *r_u)
{
	UNISTR2 *name = &q_u->name;
	UNISTR2 *uni_environment = &q_u->environment;
	uint32 level = q_u->level;
	NEW_BUFFER *buffer = NULL;
	uint32 offered = q_u->offered;
	uint32 *needed = &r_u->needed;

	/* that's an [in out] buffer */
	spoolss_move_buffer(q_u->buffer, &r_u->buffer);
	buffer = r_u->buffer;

	DEBUG(4,("_spoolss_getprinterdriverdirectory\n"));

	*needed=0;

	switch(level) {
	case 1:
		return getprinterdriverdir_level_1(name, uni_environment, buffer, offered, needed);
	default:
		return WERR_UNKNOWN_LEVEL;
	}
}
	
/****************************************************************************
****************************************************************************/

WERROR _spoolss_enumprinterdata(pipes_struct *p, SPOOL_Q_ENUMPRINTERDATA *q_u, SPOOL_R_ENUMPRINTERDATA *r_u)
{
	POLICY_HND *handle = &q_u->handle;
	uint32 idx = q_u->index;
	uint32 in_value_len = q_u->valuesize;
	uint32 in_data_len = q_u->datasize;
	uint32 *out_max_value_len = &r_u->valuesize;
	uint16 **out_value = &r_u->value;
	uint32 *out_value_len = &r_u->realvaluesize;
	uint32 *out_type = &r_u->type;
	uint32 *out_max_data_len = &r_u->datasize;
	uint8  **data_out = &r_u->data;
	uint32 *out_data_len = &r_u->realdatasize;

	NT_PRINTER_INFO_LEVEL *printer = NULL;
	
	fstring value;
	
	uint32 param_index;
	uint32 biggest_valuesize;
	uint32 biggest_datasize;
	uint32 data_len;
	Printer_entry *Printer = find_printer_index_by_hnd(p, handle);
	int snum;
	uint8 *data=NULL;
	uint32 type;
	WERROR result;

	ZERO_STRUCT(printer);
	
	*out_max_value_len=0;
	*out_value=NULL;
	*out_value_len=0;

	*out_type=0;

	*out_max_data_len=0;
	*data_out=NULL;
	*out_data_len=0;

	DEBUG(5,("spoolss_enumprinterdata\n"));

	if (!Printer) {
		DEBUG(0,("_spoolss_enumprinterdata: Invalid handle (%s).\n", OUR_HANDLE(handle)));
		return WERR_BADFID;
	}

	if (!get_printer_snum(p,handle, &snum))
		return WERR_BADFID;
	
	result = get_a_printer(&printer, 2, lp_servicename(snum));
	if (!W_ERROR_IS_OK(result))
		return result;

	/*
	 * The NT machine wants to know the biggest size of value and data
	 *
	 * cf: MSDN EnumPrinterData remark section
	 */
	if ( (in_value_len==0) && (in_data_len==0) ) {
		DEBUGADD(6,("Activating NT mega-hack to find sizes\n"));

#if 0
		/*
		 * NT can ask for a specific parameter size - we need to return NO_MORE_ITEMS
		 * if this parameter size doesn't exist.
		 * Ok - my opinion here is that the client is not asking for the greatest
		 * possible size of all the parameters, but is asking specifically for the size needed
		 * for this specific parameter. In that case we can remove the loop below and
		 * simplify this lookup code considerably. JF - comments welcome. JRA.
		 */

		if (!get_specific_param_by_index(*printer, 2, idx, value, &data, &type, &data_len)) {
			SAFE_FREE(data);
			free_a_printer(&printer, 2);
			return WERR_NO_MORE_ITEMS;
		}
#endif

		SAFE_FREE(data);

		param_index=0;
		biggest_valuesize=0;
		biggest_datasize=0;
		
		while (get_specific_param_by_index(*printer, 2, param_index, value, &data, &type, &data_len)) {
			if (strlen(value) > biggest_valuesize) biggest_valuesize=strlen(value);
			if (data_len > biggest_datasize) biggest_datasize=data_len;

			DEBUG(6,("current values: [%d], [%d]\n", biggest_valuesize, biggest_datasize));

			SAFE_FREE(data);
			param_index++;
		}

		/*
		 * I think this is correct, it doesn't break APW and
		 * allows Gerald's Win32 test programs to work correctly,
		 * but may need altering.... JRA.
		 */

		if (param_index == 0) {
			/* No parameters found. */
			free_a_printer(&printer, 2);
			return WERR_NO_MORE_ITEMS;
		}

		/* the value is an UNICODE string but realvaluesize is the length in bytes including the leading 0 */
		*out_value_len=2*(1+biggest_valuesize);
		*out_data_len=biggest_datasize;

		DEBUG(6,("final values: [%d], [%d]\n", *out_value_len, *out_data_len));

		free_a_printer(&printer, 2);
		return WERR_OK;
	}
	
	/*
	 * the value len is wrong in NT sp3
	 * that's the number of bytes not the number of unicode chars
	 */

	if (!get_specific_param_by_index(*printer, 2, idx, value, &data, &type, &data_len)) {
		SAFE_FREE(data);
		free_a_printer(&printer, 2);
		return WERR_NO_MORE_ITEMS;
	}

	free_a_printer(&printer, 2);

	/*
	 * the value is:
	 * - counted in bytes in the request
	 * - counted in UNICODE chars in the max reply
	 * - counted in bytes in the real size
	 *
	 * take a pause *before* coding not *during* coding
	 */
	
	*out_max_value_len=(in_value_len/sizeof(uint16));
	if((*out_value=(uint16 *)talloc_zero(p->mem_ctx,in_value_len*sizeof(uint8))) == NULL) {
		SAFE_FREE(data);
		return WERR_NOMEM;
	}
	
	*out_value_len = (uint32)dos_PutUniCode((char *)*out_value, value, in_value_len, True);

	*out_type=type;

	/* the data is counted in bytes */
	*out_max_data_len=in_data_len;
	if((*data_out=(uint8 *)talloc_zero(p->mem_ctx, in_data_len*sizeof(uint8))) == NULL) {
		SAFE_FREE(data);
		return WERR_NOMEM;
	}
	
	memcpy(*data_out, data, (size_t)data_len);
	*out_data_len=data_len;

	SAFE_FREE(data);
	
	return WERR_OK;
}

/****************************************************************************
****************************************************************************/

WERROR _spoolss_setprinterdata( pipes_struct *p, SPOOL_Q_SETPRINTERDATA *q_u, SPOOL_R_SETPRINTERDATA *r_u)
{
	POLICY_HND *handle = &q_u->handle;
	UNISTR2 *value = &q_u->value;
	uint32 type = q_u->type;
/*	uint32 max_len = q_u->max_len; - notused. */
	uint8 *data = q_u->data;
	uint32 real_len = q_u->real_len;
/*	uint32 numeric_data = q_u->numeric_data; - notused. */

	NT_PRINTER_INFO_LEVEL *printer = NULL;
	NT_PRINTER_PARAM *param = NULL, old_param;
	int snum=0;
	WERROR status = WERR_OK;
	Printer_entry *Printer=find_printer_index_by_hnd(p, handle);
	
	DEBUG(5,("spoolss_setprinterdata\n"));

	if (!Printer) {
		DEBUG(0,("_spoolss_setprinterdata: Invalid handle (%s).\n", OUR_HANDLE(handle)));
		return WERR_BADFID;
	}

	if (!get_printer_snum(p,handle, &snum))
		return WERR_BADFID;

	ZERO_STRUCT(old_param);

	/* 
	 * Access check : NT returns "access denied" if you make a 
	 * SetPrinterData call without the necessary privildge.
	 * we were originally returning OK if nothing changed
	 * which made Win2k issue **a lot** of SetPrinterData
	 * when connecting to a printer  --jerry
	 */

	if (!print_access_check(NULL, snum, PRINTER_ACCESS_ADMINISTER)) {
		DEBUG(3, ("security descriptor change denied by existing "
			  "security descriptor\n"));
		status = WERR_ACCESS_DENIED;
		goto done;
	}

	/* Check if we are making any changes or not.  Return true if
	   nothing is actually changing.  This is not needed anymore but
	   has been left in as an optimization to keep from from
	   writing to disk as often  --jerry  */

	status = get_a_printer(&printer, 2, lp_servicename(snum));
	if (!W_ERROR_IS_OK(status))
		return status;

	convert_specific_param(&param, value , type, data, real_len);


	if (get_specific_param(*printer, 2, param->value, &old_param.data,
			       &old_param.type, (uint32 *)&old_param.data_len)) {

		if (param->type == old_param.type &&
		    param->data_len == old_param.data_len &&
		    memcmp(param->data, old_param.data,
			   old_param.data_len) == 0) {

			DEBUG(3, ("setprinterdata hasn't changed\n"));
			status = WERR_OK;
			goto done;
		}
	}

	unlink_specific_param_if_exist(printer->info_2, param);
	
	/*
	 * When client side code sets a magic printer data key, detect it and save
	 * the current printer data and the magic key's data (its the DEVMODE) for
	 * future printer/driver initializations.
	 */
	if (param->type==3 && !strcmp( param->value, PHANTOM_DEVMODE_KEY)) {
		/*
		 * Set devmode and printer initialization info
		 */
		status = save_driver_init(printer, 2, param);
	}
	else {
		add_a_specific_param(printer->info_2, &param);
		status = mod_a_printer(*printer, 2);
	}

 done:
	free_a_printer(&printer, 2);
	if (param)
		free_nt_printer_param(&param);
	SAFE_FREE(old_param.data);

	return status;
}

/****************************************************************************
****************************************************************************/

WERROR _spoolss_deleteprinterdata(pipes_struct *p, SPOOL_Q_DELETEPRINTERDATA *q_u, SPOOL_R_DELETEPRINTERDATA *r_u)
{
	POLICY_HND *handle = &q_u->handle;
	UNISTR2 *value = &q_u->valuename;

	NT_PRINTER_INFO_LEVEL *printer = NULL;
	NT_PRINTER_PARAM param;
	int snum=0;
	WERROR status = WERR_OK;
	Printer_entry *Printer=find_printer_index_by_hnd(p, handle);
	
	DEBUG(5,("spoolss_deleteprinterdata\n"));
	
	if (!Printer) {
		DEBUG(0,("_spoolss_deleteprinterdata: Invalid handle (%s).\n", OUR_HANDLE(handle)));
		return WERR_BADFID;
	}

	if (!get_printer_snum(p, handle, &snum))
		return WERR_BADFID;

	if (!print_access_check(NULL, snum, PRINTER_ACCESS_ADMINISTER)) {
		DEBUG(3, ("_spoolss_deleteprinterdata: printer properties "
			  "change denied by existing security descriptor\n"));
		return WERR_ACCESS_DENIED;
	}

	status = get_a_printer(&printer, 2, lp_servicename(snum));
	if (!W_ERROR_IS_OK(status))
		return status;

	ZERO_STRUCTP(&param);
	unistr2_to_ascii(param.value, value, sizeof(param.value)-1);

	if(!unlink_specific_param_if_exist(printer->info_2, &param))
		status = WERR_INVALID_PARAM;
	else
		status = mod_a_printer(*printer, 2);

	free_a_printer(&printer, 2);
	return status;
}

/****************************************************************************
****************************************************************************/

WERROR _spoolss_addform( pipes_struct *p, SPOOL_Q_ADDFORM *q_u, SPOOL_R_ADDFORM *r_u)
{
	POLICY_HND *handle = &q_u->handle;
/*	uint32 level = q_u->level; - notused. */
	FORM *form = &q_u->form;
	nt_forms_struct tmpForm;

	int count=0;
	nt_forms_struct *list=NULL;
	Printer_entry *Printer = find_printer_index_by_hnd(p, handle);

	DEBUG(5,("spoolss_addform\n"));

	if (!Printer) {
		DEBUG(0,("_spoolss_addform: Invalid handle (%s).\n", OUR_HANDLE(handle)));
		return WERR_BADFID;
	}

	/* can't add if builtin */
	if (get_a_builtin_ntform(&form->name,&tmpForm)) {
		return WERR_INVALID_PARAM;
	}

	count=get_ntforms(&list);
	if(!add_a_form(&list, form, &count))
		return WERR_NOMEM;
	write_ntforms(&list, count);

	SAFE_FREE(list);

	return WERR_OK;
}

/****************************************************************************
****************************************************************************/

WERROR _spoolss_deleteform( pipes_struct *p, SPOOL_Q_DELETEFORM *q_u, SPOOL_R_DELETEFORM *r_u)
{
	POLICY_HND *handle = &q_u->handle;
	UNISTR2 *form_name = &q_u->name;
	nt_forms_struct tmpForm;
	int count=0;
	WERROR ret = WERR_OK;
	nt_forms_struct *list=NULL;
	Printer_entry *Printer = find_printer_index_by_hnd(p, handle);

	DEBUG(5,("spoolss_deleteform\n"));

	if (!Printer) {
		DEBUG(0,("_spoolss_deleteform: Invalid handle (%s).\n", OUR_HANDLE(handle)));
		return WERR_BADFID;
	}

	/* can't delete if builtin */
	if (get_a_builtin_ntform(form_name,&tmpForm)) {
		return WERR_INVALID_PARAM;
	}

	count = get_ntforms(&list);
	if(!delete_a_form(&list, form_name, &count, &ret))
		return WERR_INVALID_PARAM;

	SAFE_FREE(list);

	return ret;
}

/****************************************************************************
****************************************************************************/

WERROR _spoolss_setform(pipes_struct *p, SPOOL_Q_SETFORM *q_u, SPOOL_R_SETFORM *r_u)
{
	POLICY_HND *handle = &q_u->handle;
/*	UNISTR2 *uni_name = &q_u->name; - notused. */
/*	uint32 level = q_u->level; - notused. */
	FORM *form = &q_u->form;
	nt_forms_struct tmpForm;

	int count=0;
	nt_forms_struct *list=NULL;
	Printer_entry *Printer = find_printer_index_by_hnd(p, handle);

 	DEBUG(5,("spoolss_setform\n"));

	if (!Printer) {
		DEBUG(0,("_spoolss_setform: Invalid handle (%s).\n", OUR_HANDLE(handle)));
		return WERR_BADFID;
	}
	/* can't set if builtin */
	if (get_a_builtin_ntform(&form->name,&tmpForm)) {
		return WERR_INVALID_PARAM;
	}

	count=get_ntforms(&list);
	update_a_form(&list, form, count);
	write_ntforms(&list, count);

	SAFE_FREE(list);

	return WERR_OK;
}

/****************************************************************************
 enumprintprocessors level 1.
****************************************************************************/
static WERROR enumprintprocessors_level_1(NEW_BUFFER *buffer, uint32 offered, uint32 *needed, uint32 *returned)
{
	PRINTPROCESSOR_1 *info_1=NULL;
	
	if((info_1 = (PRINTPROCESSOR_1 *)malloc(sizeof(PRINTPROCESSOR_1))) == NULL)
		return WERR_NOMEM;

	(*returned) = 0x1;
	
	init_unistr(&info_1->name, "winprint");

	*needed += spoolss_size_printprocessor_info_1(info_1);

	if (!alloc_buffer_size(buffer, *needed))
		return WERR_INSUFFICIENT_BUFFER;

	smb_io_printprocessor_info_1("", buffer, info_1, 0);

	SAFE_FREE(info_1);

	if (*needed > offered) {
		*returned=0;
		return WERR_INSUFFICIENT_BUFFER;
	}

	return WERR_OK;
}

/****************************************************************************
****************************************************************************/

WERROR _spoolss_enumprintprocessors(pipes_struct *p, SPOOL_Q_ENUMPRINTPROCESSORS *q_u, SPOOL_R_ENUMPRINTPROCESSORS *r_u)
{
/*	UNISTR2 *name = &q_u->name; - notused. */
/*	UNISTR2 *environment = &q_u->environment; - notused. */
	uint32 level = q_u->level;
    NEW_BUFFER *buffer = NULL;
	uint32 offered = q_u->offered;
    uint32 *needed = &r_u->needed;
	uint32 *returned = &r_u->returned;

	/* that's an [in out] buffer */
	spoolss_move_buffer(q_u->buffer, &r_u->buffer);
	buffer = r_u->buffer;

 	DEBUG(5,("spoolss_enumprintprocessors\n"));

	/*
	 * Enumerate the print processors ...
	 *
	 * Just reply with "winprint", to keep NT happy
	 * and I can use my nice printer checker.
	 */
	
	*returned=0;
	*needed=0;
	
	switch (level) {
	case 1:
		return enumprintprocessors_level_1(buffer, offered, needed, returned);
	default:
		return WERR_UNKNOWN_LEVEL;
	}
}

/****************************************************************************
 enumprintprocdatatypes level 1.
****************************************************************************/
static WERROR enumprintprocdatatypes_level_1(NEW_BUFFER *buffer, uint32 offered, uint32 *needed, uint32 *returned)
{
	PRINTPROCDATATYPE_1 *info_1=NULL;
	
	if((info_1 = (PRINTPROCDATATYPE_1 *)malloc(sizeof(PRINTPROCDATATYPE_1))) == NULL)
		return WERR_NOMEM;

	(*returned) = 0x1;
	
	init_unistr(&info_1->name, "RAW");

	*needed += spoolss_size_printprocdatatype_info_1(info_1);

	if (!alloc_buffer_size(buffer, *needed))
		return WERR_INSUFFICIENT_BUFFER;

	smb_io_printprocdatatype_info_1("", buffer, info_1, 0);

	SAFE_FREE(info_1);

	if (*needed > offered) {
		*returned=0;
		return WERR_INSUFFICIENT_BUFFER;
	}

	return WERR_OK;
}

/****************************************************************************
****************************************************************************/

WERROR _spoolss_enumprintprocdatatypes(pipes_struct *p, SPOOL_Q_ENUMPRINTPROCDATATYPES *q_u, SPOOL_R_ENUMPRINTPROCDATATYPES *r_u)
{
/*	UNISTR2 *name = &q_u->name; - notused. */
/*	UNISTR2 *processor = &q_u->processor; - notused. */
	uint32 level = q_u->level;
	NEW_BUFFER *buffer = NULL;
	uint32 offered = q_u->offered;
	uint32 *needed = &r_u->needed;
	uint32 *returned = &r_u->returned;

	/* that's an [in out] buffer */
	spoolss_move_buffer(q_u->buffer, &r_u->buffer);
	buffer = r_u->buffer;

 	DEBUG(5,("_spoolss_enumprintprocdatatypes\n"));
	
	*returned=0;
	*needed=0;
	
	switch (level) {
	case 1:
		return enumprintprocdatatypes_level_1(buffer, offered, needed, returned);
	default:
		return WERR_UNKNOWN_LEVEL;
	}
}

/****************************************************************************
 enumprintmonitors level 1.
****************************************************************************/

static WERROR enumprintmonitors_level_1(NEW_BUFFER *buffer, uint32 offered, uint32 *needed, uint32 *returned)
{
	PRINTMONITOR_1 *info_1=NULL;
	
	if((info_1 = (PRINTMONITOR_1 *)malloc(sizeof(PRINTMONITOR_1))) == NULL)
		return WERR_NOMEM;

	(*returned) = 0x1;
	
	init_unistr(&info_1->name, "Local Port");

	*needed += spoolss_size_printmonitor_info_1(info_1);

	if (!alloc_buffer_size(buffer, *needed))
		return WERR_INSUFFICIENT_BUFFER;

	smb_io_printmonitor_info_1("", buffer, info_1, 0);

	SAFE_FREE(info_1);

	if (*needed > offered) {
		*returned=0;
		return WERR_INSUFFICIENT_BUFFER;
	}

	return WERR_OK;
}

/****************************************************************************
 enumprintmonitors level 2.
****************************************************************************/
static WERROR enumprintmonitors_level_2(NEW_BUFFER *buffer, uint32 offered, uint32 *needed, uint32 *returned)
{
	PRINTMONITOR_2 *info_2=NULL;
	
	if((info_2 = (PRINTMONITOR_2 *)malloc(sizeof(PRINTMONITOR_2))) == NULL)
		return WERR_NOMEM;

	(*returned) = 0x1;
	
	init_unistr(&info_2->name, "Local Port");
	init_unistr(&info_2->environment, "Windows NT X86");
	init_unistr(&info_2->dll_name, "localmon.dll");

	*needed += spoolss_size_printmonitor_info_2(info_2);

	if (!alloc_buffer_size(buffer, *needed))
		return WERR_INSUFFICIENT_BUFFER;

	smb_io_printmonitor_info_2("", buffer, info_2, 0);

	SAFE_FREE(info_2);

	if (*needed > offered) {
		*returned=0;
		return WERR_INSUFFICIENT_BUFFER;
	}

	return WERR_OK;
}

/****************************************************************************
****************************************************************************/

WERROR _spoolss_enumprintmonitors(pipes_struct *p, SPOOL_Q_ENUMPRINTMONITORS *q_u, SPOOL_R_ENUMPRINTMONITORS *r_u)
{
/*	UNISTR2 *name = &q_u->name; - notused. */
	uint32 level = q_u->level;
    NEW_BUFFER *buffer = NULL;
	uint32 offered = q_u->offered;
    uint32 *needed = &r_u->needed;
	uint32 *returned = &r_u->returned;

	/* that's an [in out] buffer */
	spoolss_move_buffer(q_u->buffer, &r_u->buffer);
	buffer = r_u->buffer;

 	DEBUG(5,("spoolss_enumprintmonitors\n"));

	/*
	 * Enumerate the print monitors ...
	 *
	 * Just reply with "Local Port", to keep NT happy
	 * and I can use my nice printer checker.
	 */
	
	*returned=0;
	*needed=0;
	
	switch (level) {
	case 1:
		return enumprintmonitors_level_1(buffer, offered, needed, returned);
	case 2:
		return enumprintmonitors_level_2(buffer, offered, needed, returned);
	default:
		return WERR_UNKNOWN_LEVEL;
	}
}

/****************************************************************************
****************************************************************************/
static WERROR getjob_level_1(print_queue_struct *queue, int count, int snum, uint32 jobid, NEW_BUFFER *buffer, uint32 offered, uint32 *needed)
{
	int i=0;
	BOOL found=False;
	JOB_INFO_1 *info_1=NULL;

	info_1=(JOB_INFO_1 *)malloc(sizeof(JOB_INFO_1));

	if (info_1 == NULL) {
		SAFE_FREE(queue);
		return WERR_NOMEM;
	}
		
	for (i=0; i<count && found==False; i++) {
		if (queue[i].job==(int)jobid)
			found=True;
	}
	
	if (found==False) {
		SAFE_FREE(queue);
		SAFE_FREE(info_1);
		/* NT treats not found as bad param... yet another bad choice */
		return WERR_INVALID_PARAM;
	}
	
	fill_job_info_1(info_1, &(queue[i-1]), i, snum);
	
	SAFE_FREE(queue);
	
	*needed += spoolss_size_job_info_1(info_1);

	if (!alloc_buffer_size(buffer, *needed)) {
		SAFE_FREE(info_1);
		return WERR_INSUFFICIENT_BUFFER;
	}

	smb_io_job_info_1("", buffer, info_1, 0);

	SAFE_FREE(info_1);

	if (*needed > offered)
		return WERR_INSUFFICIENT_BUFFER;

	return WERR_OK;
}


/****************************************************************************
****************************************************************************/
static WERROR getjob_level_2(print_queue_struct *queue, int count, int snum, uint32 jobid, NEW_BUFFER *buffer, uint32 offered, uint32 *needed)
{
	int i=0;
	BOOL found=False;
	JOB_INFO_2 *info_2;
	NT_PRINTER_INFO_LEVEL *ntprinter = NULL;
	WERROR ret;

	info_2=(JOB_INFO_2 *)malloc(sizeof(JOB_INFO_2));

	ZERO_STRUCTP(info_2);

	if (info_2 == NULL) {
		SAFE_FREE(queue);
		return WERR_NOMEM;
	}

	for (i=0; i<count && found==False; i++) {
		if (queue[i].job==(int)jobid)
			found=True;
	}
	
	if (found==False) {
		SAFE_FREE(queue);
		SAFE_FREE(info_2);
		/* NT treats not found as bad param... yet another bad choice */
		return WERR_INVALID_PARAM;
	}
	
	ret = get_a_printer(&ntprinter, 2, lp_servicename(snum));
	if (!W_ERROR_IS_OK(ret)) {
		SAFE_FREE(queue);
		return ret;
	}

	fill_job_info_2(info_2, &(queue[i-1]), i, snum, ntprinter);
	
	free_a_printer(&ntprinter, 2);
	SAFE_FREE(queue);
	
	*needed += spoolss_size_job_info_2(info_2);

	if (!alloc_buffer_size(buffer, *needed)) {
		SAFE_FREE(info_2);
		return WERR_INSUFFICIENT_BUFFER;
	}

	smb_io_job_info_2("", buffer, info_2, 0);

	free_job_info_2(info_2);
	SAFE_FREE(info_2);

	if (*needed > offered)
		return WERR_INSUFFICIENT_BUFFER;

	return WERR_OK;
}

/****************************************************************************
****************************************************************************/

WERROR _spoolss_getjob( pipes_struct *p, SPOOL_Q_GETJOB *q_u, SPOOL_R_GETJOB *r_u)
{
	POLICY_HND *handle = &q_u->handle;
	uint32 jobid = q_u->jobid;
	uint32 level = q_u->level;
	NEW_BUFFER *buffer = NULL;
	uint32 offered = q_u->offered;
	uint32 *needed = &r_u->needed;

	int snum;
	int count;
	print_queue_struct *queue=NULL;
	print_status_struct prt_status;

	/* that's an [in out] buffer */
	spoolss_move_buffer(q_u->buffer, &r_u->buffer);
	buffer = r_u->buffer;

	DEBUG(5,("spoolss_getjob\n"));
	
	memset(&prt_status, 0, sizeof(prt_status));

	*needed=0;
	
	if (!get_printer_snum(p, handle, &snum))
		return WERR_BADFID;
	
	count = print_queue_status(snum, &queue, &prt_status);
	
	DEBUGADD(4,("count:[%d], prt_status:[%d], [%s]\n",
	             count, prt_status.status, prt_status.message));
		
	switch (level) {
	case 1:
		return getjob_level_1(queue, count, snum, jobid, buffer, offered, needed);
	case 2:
		return getjob_level_2(queue, count, snum, jobid, buffer, offered, needed);
	default:
		SAFE_FREE(queue);
		return WERR_UNKNOWN_LEVEL;
	}
}

/********************************************************************
 * spoolss_getprinterdataex
 ********************************************************************/

WERROR _spoolss_getprinterdataex(pipes_struct *p, SPOOL_Q_GETPRINTERDATAEX *q_u, SPOOL_R_GETPRINTERDATAEX *r_u)
{
	POLICY_HND	*handle = &q_u->handle;
	uint32 		in_size = q_u->size;
	uint32 		*type = &r_u->type;
	uint32 		*out_size = &r_u->size;
	uint8 		**data = &r_u->data;
	uint32 		*needed = &r_u->needed;

	fstring 	key, value;
	Printer_entry 	*Printer = find_printer_index_by_hnd(p, handle);
	BOOL 		found = False;

	DEBUG(4,("_spoolss_getprinterdataex\n"));

        unistr2_to_ascii(key, &q_u->keyname, sizeof(key) - 1);
        unistr2_to_ascii(value, &q_u->valuename, sizeof(value) - 1);

	/* in case of problem, return some default values */
	*needed=0;
	*type=0;
	*out_size=0;

		
	if (!Printer) {
		if((*data=(uint8 *)talloc_zero(p->mem_ctx, 4*sizeof(uint8))) == NULL)
			return WERR_NOMEM;
		DEBUG(0,("_spoolss_getprinterdata: Invalid handle (%s).\n", OUR_HANDLE(handle)));
		return WERR_BADFID;
	}

		
	/* Is the handle to a printer or to the server? */

	if (Printer->printer_type == PRINTER_HANDLE_IS_PRINTSERVER)
	{
		DEBUG(10,("_spoolss_getprinterdatex: Not implemented for server handles yet\n"));
		return WERR_INVALID_PARAM;
	}
	else
	{
	        /* 
		 * From MSDN documentation of GetPrinterDataEx: pass request
		 * to GetPrinterData if key is "PrinterDriverData". This is 
		 * the only key we really support. Other keys to implement:
		 * (a) DsDriver
		 * (b) DsSpooler
		 * (c) PnPData
		 */
	   
		if (strcmp(key, "PrinterDriverData") != 0)
			return WERR_INVALID_PARAM;

		DEBUG(10, ("_spoolss_getprinterdataex: pass me to getprinterdata\n"));
		found = getprinterdata_printer(p, p->mem_ctx, handle, value, 
			type, data, needed, in_size);
		
	}
	 
	if (!found) {
		DEBUG(5, ("value not found, allocating %d\n", *out_size));
		
		/* reply this param doesn't exist */
		if (*out_size) {
			if((*data=(uint8 *)talloc_zero(p->mem_ctx, *out_size*sizeof(uint8))) == NULL)
				return WERR_NOMEM;
		} else {
			*data = NULL;
		}

		return WERR_INVALID_PARAM;
	}
	
	if (*needed > *out_size)
		return WERR_MORE_DATA;
	else
		return WERR_OK;
}

/********************************************************************
 * spoolss_setprinterdata
 ********************************************************************/

WERROR _spoolss_setprinterdataex(pipes_struct *p, SPOOL_Q_SETPRINTERDATAEX *q_u, SPOOL_R_SETPRINTERDATAEX *r_u)
{
	SPOOL_Q_SETPRINTERDATA q_u_local;
	SPOOL_R_SETPRINTERDATA r_u_local;
        fstring key;

	DEBUG(4,("_spoolss_setprinterdataex\n"));

        /* From MSDN documentation of SetPrinterDataEx: pass request to
           SetPrinterData if key is "PrinterDriverData" */

        unistr2_to_ascii(key, &q_u->key, sizeof(key) - 1);

        if (strcmp(key, "PrinterDriverData") == 0)
	        return WERR_INVALID_PARAM;
		
	ZERO_STRUCT(q_u_local);	
	ZERO_STRUCT(r_u_local);	
	
	/* make a copy to call _spoolss_setprinterdata() */

	memcpy(&q_u_local.handle, &q_u->handle, sizeof(POLICY_HND));
	copy_unistr2(&q_u_local.value, &q_u->value);
	q_u_local.type = q_u->type;
	q_u_local.max_len = q_u->max_len;
	q_u_local.data = q_u->data;
	q_u_local.real_len = q_u->real_len;
	q_u_local.numeric_data = q_u->numeric_data;
		
	return _spoolss_setprinterdata(p, &q_u_local, &r_u_local);
}

/********************************************************************
 * spoolss_enumprinterkey
 ********************************************************************/

/* constants for EnumPrinterKey() */
#define ENUMERATED_KEY_SIZE	19

WERROR _spoolss_enumprinterkey(pipes_struct *p, SPOOL_Q_ENUMPRINTERKEY *q_u, SPOOL_R_ENUMPRINTERKEY *r_u)
{
	fstring key;
	uint16  enumkeys[ENUMERATED_KEY_SIZE+1];
	char*   ptr = NULL;
	int     i;
	char 	*PrinterKey = "PrinterDriverData";

	DEBUG(4,("_spoolss_enumprinterkey\n"));

	unistr2_to_ascii(key, &q_u->key, sizeof(key) - 1);

	/* 
	 * we only support enumating all keys (key == "")
	 * Of course, the only key we support is the "PrinterDriverData" 
	 * key
	 */	
	if (strlen(key) == 0)
	{
		r_u->needed = ENUMERATED_KEY_SIZE *2;
		if (q_u->size < r_u->needed)
			return WERR_MORE_DATA;
	
		ptr = PrinterKey;
		for (i=0; i<ENUMERATED_KEY_SIZE-2; i++)
		{
			enumkeys[i] = (uint16)(*ptr);
			ptr++;
		}
	
		if (!make_spoolss_buffer5(p->mem_ctx, &r_u->keys, ENUMERATED_KEY_SIZE, enumkeys))
			return WERR_BADFILE;
			
		return WERR_OK;
	}
	
	/* The "PrinterDriverData" key should have no subkeys */
	if (strcmp(key, PrinterKey) == 0)
	{
		r_u-> needed = 2;
		if (q_u->size < r_u->needed)
			return WERR_MORE_DATA;
		enumkeys[0] = 0x0;
		if (!make_spoolss_buffer5(p->mem_ctx, &r_u->keys, 1, enumkeys))
			return WERR_BADFILE;
			
		return WERR_OK;
	}
	

	/* The return value for an unknown key is documented in MSDN
	   EnumPrinterKey description */
        return WERR_BADFILE;
}

/********************************************************************
 * spoolss_enumprinterdataex
 ********************************************************************/

WERROR _spoolss_enumprinterdataex(pipes_struct *p, SPOOL_Q_ENUMPRINTERDATAEX *q_u, SPOOL_R_ENUMPRINTERDATAEX *r_u)
{
	POLICY_HND	*handle = &q_u->handle; 
	uint32 		in_size = q_u->size;
	uint32 		num_entries, 
			needed;
	NT_PRINTER_INFO_LEVEL 	*printer = NULL;
	PRINTER_ENUM_VALUES	*enum_values = NULL;
	fstring 	key, value;
	Printer_entry 	*Printer = find_printer_index_by_hnd(p, handle);
	int 		snum;
	uint32 		param_index, 
			data_len,
			type;
	WERROR 		result;
	uint8 		*data=NULL;
	

	DEBUG(4,("_spoolss_enumprinterdataex\n"));

	if (!Printer) {
		DEBUG(0,("_spoolss_enumprinterdata: Invalid handle (%s).\n", OUR_HANDLE(handle)));
		return WERR_BADFID;
	}

		
        /* 
	 * The only key we support is "PrinterDriverData". This should return 
	 > an array of all the key/value pairs returned by EnumPrinterDataSee 
	 * _spoolss_getprinterdataex() for details    --jerry
	 */
   
	unistr2_to_ascii(key, &q_u->key, sizeof(key) - 1);
	if (strcmp(key, "PrinterDriverData") != 0)
	{
		DEBUG(10,("_spoolss_enumprinterdataex: Unknown keyname [%s]\n", key));
		return WERR_INVALID_PARAM;
	}


	if (!get_printer_snum(p,handle, &snum))
		return WERR_BADFID;
	
	ZERO_STRUCT(printer);
	result = get_a_printer(&printer, 2, lp_servicename(snum));
	if (!W_ERROR_IS_OK(result))
		return result;

	
	/* 
	 * loop through all params and build the array to pass 
	 * back to the  client 
	 */
	result = WERR_OK;
	param_index		= 0;
	needed 			= 0;
	num_entries		= 0;
	
	while (get_specific_param_by_index(*printer, 2, param_index, value, &data, &type, &data_len)) 
	{
		PRINTER_ENUM_VALUES	*ptr;
		uint32			add_len = 0;

		DEBUG(10,("retrieved value number [%d] [%s]\n", num_entries, value));

		if ((ptr=talloc_realloc(p->mem_ctx, enum_values, (num_entries+1) * sizeof(PRINTER_ENUM_VALUES))) == NULL)
		{
			DEBUG(0,("talloc_realloc failed to allocate more memory!\n"));
			result = WERR_NOMEM;
			goto done;
		}
		enum_values = ptr;

		/* copy the data */
		init_unistr(&enum_values[num_entries].valuename, value);
		enum_values[num_entries].value_len = (strlen(value)+1) * 2;
		enum_values[num_entries].type      = type;
		
		/* 
		 * NULL terminate REG_SZ
		 * FIXME!!!  We should not be correctly problems in the way
		 * we store PrinterData here.  Need to investogate 
		 * SetPrinterData[Ex]   --jerry
		 */
		
		if (type == REG_SZ) {
			/* fix alignment if the string was stored 
			   in a bizarre fashion */
			if ((data_len % 2) == 0)
				add_len = 2;
			else
				add_len = data_len % 2;
		}
		
		if (!(enum_values[num_entries].data=talloc_zero(p->mem_ctx, data_len+add_len))) {
			DEBUG(0,("talloc_realloc failed to allocate more memory for data!\n"));
			result = WERR_NOMEM;
			goto done;
		}
		memcpy(enum_values[num_entries].data, data, data_len);
		enum_values[num_entries].data_len = data_len + add_len;

		/* keep track of the size of the array in bytes */
		
		needed += spoolss_size_printer_enum_values(&enum_values[num_entries]);
		
		num_entries++;
		param_index++;
	}
	
	r_u->needed 		= needed;
	r_u->returned 		= num_entries;

	if (needed > in_size) {
		result = WERR_MORE_DATA;
		goto done;
	}
		
	/* copy data into the reply */
	
	r_u->ctr.size        	= r_u->needed;
	r_u->ctr.size_of_array 	= r_u->returned;
	r_u->ctr.values 	= enum_values;
	
	
		
done:	
	free_a_printer(&printer, 2);

	return result;
}


