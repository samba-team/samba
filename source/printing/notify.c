/* 
   Unix SMB/Netbios implementation.
   Version 2.2
   printing backend routines
   Copyright (C) Tim Potter,            2002
   Copyright (C) Gerald Carter,         2002
   Copyright (C) Jeremy Allison.	2002
   
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

#include "printing.h"

static TALLOC_CTX *send_ctx;

static struct notify_queue {
	struct notify_queue *next, *prev;
	char *unix_printername;
	void *buf;
	size_t buflen;
} *notify_queue_head = NULL;

/****************************************************************************
 Turn a DOS queue name into a snum.
****************************************************************************/

int print_queue_snum_dos(const char *dos_qname)
{
	int snum = lp_servicenumber_dos(dos_qname);
	if (snum == -1 || !lp_print_ok(snum))
		return -1;
	return snum;
}

/*******************************************************************
 Used to decide if we need a short select timeout.
*******************************************************************/

BOOL print_notify_messages_pending(void)
{
	return (notify_queue_head != NULL);
}

/*******************************************************************
 Send the batched messages - on a per-printer basis.
*******************************************************************/

static void print_notify_send_messages_to_printer(const char *unix_printer)
{
	char *buf;
	struct notify_queue *pq, *pq_next;
	size_t msg_count = 0, offset = 0;
	size_t num_pids = 0;
	size_t i;
	pid_t *pid_list = NULL;

	/* Count the space needed to send the messages. */
	for (pq = notify_queue_head; pq; pq = pq->next) {
		if (strequal_unix(unix_printer, pq->unix_printername)) {
			offset += (pq->buflen + 4);
			msg_count++;
		}	
	}
	offset += 4; /* For count. */

	buf = talloc(send_ctx, offset);
	if (!buf) {
		DEBUG(0,("print_notify_send_messages: Out of memory\n"));
		talloc_destroy_pool(send_ctx);
		return;
	}

	offset = 0;
	SIVAL(buf,offset,msg_count);
	offset += 4;
	for (pq = notify_queue_head; pq; pq = pq_next) {
		pq_next = pq->next;

		if (strequal(unix_printer, pq->unix_printername)) {
			SIVAL(buf,offset,pq->buflen);
			offset += 4;
			memcpy(buf + offset, pq->buf, pq->buflen);
			offset += pq->buflen;

			/* Remove from list. */
			DLIST_REMOVE(notify_queue_head, pq);
		}
	}

	DEBUG(5, ("print_notify_send_messages_to_printer: sending %d print notify message%s to printer %s\n", 
		  msg_count, msg_count != 1 ? "s" : "", unix_printer));

	/*
	 * Get the list of PID's to send to.
	 */

	if (!print_notify_pid_list(unix_printer, send_ctx, &num_pids, &pid_list))
		return;

	for (i = 0; i < num_pids; i++)
		message_send_pid(pid_list[i], MSG_PRINTER_NOTIFY2, buf, offset, True);
}

/*******************************************************************
 Actually send the batched messages.
*******************************************************************/

void print_notify_send_messages(void)
{
	if (!print_notify_messages_pending())
		return;

	if (!send_ctx)
		return;

	while (print_notify_messages_pending())
		print_notify_send_messages_to_printer(notify_queue_head->unix_printername);

	talloc_destroy_pool(send_ctx);
}

/*******************************************************************
 Batch up print notify messages.
*******************************************************************/

static void send_spoolss_notify2_msg(struct spoolss_notify_msg *msg)
{
	char *buf = NULL;
	size_t buflen = 0, len;
	struct notify_queue *pnqueue, *tmp_ptr;

	/* Let's not waste any time with this */

	if (lp_disable_spoolss())
		return;

	if (!send_ctx)
		send_ctx = talloc_init_named("print notify queue");

	if (!send_ctx)
		goto fail;

	/* Flatten data into a message */

again:
	len = 0;

	/* Pack header */

	len += tdb_pack(buf + len, buflen - len, "f", msg->printer);

	len += tdb_pack(buf + len, buflen - len, "ddddd",
			msg->type, msg->field, msg->id, msg->len, msg->flags);

	/* Pack data */

	if (msg->len == 0)
		len += tdb_pack(buf + len, buflen - len, "dd",
				msg->notify.value[0], msg->notify.value[1]);
	else
		len += tdb_pack(buf + len, buflen - len, "B",
				msg->len, msg->notify.data);

	if (buflen != len) {
		buf = talloc_realloc(send_ctx, buf, len);
		if (!buf)
			goto fail;
		buflen = len;
		goto again;
	}

	/* Store the message on the pending queue. */

	pnqueue = talloc(send_ctx, sizeof(*pnqueue));
	if (!pnqueue)
		goto fail;

	pnqueue->unix_printername = talloc_strdup(send_ctx, msg->printer);
	if (!pnqueue->unix_printername)
		 goto fail;

	pnqueue->buf = buf;
	pnqueue->buflen = buflen;

	DEBUG(5, ("send_spoolss_notify2_msg: appending message 0x%02x/0x%02x for printer %s \
to notify_queue_head\n", msg->type, msg->field, msg->printer));
		  
	/* Note we add to the end of the list to ensure
	 * the messages are sent in the order they were received. JRA.
	 */
	DLIST_ADD_END(notify_queue_head, pnqueue, tmp_ptr);
	return;

  fail:

	DEBUG(0,("send_spoolss_notify2_msg: Out of memory.\n"));
}

static void send_notify_field_values(const char *unix_printer_name, uint32 type,
				     uint32 field, uint32 id, uint32 value1, 
				     uint32 value2, uint32 flags)
{
	struct spoolss_notify_msg msg;

	ZERO_STRUCT(msg);

	fstrcpy(msg.printer, unix_printer_name);
	msg.type = type;
	msg.field = field;
	msg.id = id;
	msg.notify.value[0] = value1;
	msg.notify.value[1] = value2;
	msg.flags = flags;

	send_spoolss_notify2_msg(&msg);
}

static void send_notify_field_buffer(const char *unix_printer_name, uint32 type,
				     uint32 field, uint32 id, uint32 len,
				     char *buffer)
{
	struct spoolss_notify_msg msg;

	ZERO_STRUCT(msg);

	fstrcpy(msg.printer, unix_printer_name);
	msg.type = type;
	msg.field = field;
	msg.id = id;
	msg.len = len;
	msg.notify.data = buffer;

	send_spoolss_notify2_msg(&msg);
}

/* Send a message that the printer status has changed */

void notify_printer_status_byname(const char *unix_printer_name, uint32 status)
{
	/* Printer status stored in value1 */

	send_notify_field_values(unix_printer_name, PRINTER_NOTIFY_TYPE, 
				 PRINTER_NOTIFY_STATUS, 0, 
				 status, 0, 0);
}

void notify_printer_status(int snum, uint32 status)
{
	const char *printer_name = lp_const_servicename_unix(snum);

	if (printer_name)
		notify_printer_status_byname(printer_name, status);
}

void notify_job_status_byname(const char *unix_printer_name, uint32 jobid, uint32 status,
			      uint32 flags)
{
	/* Job id stored in id field, status in value1 */

	send_notify_field_values(unix_printer_name, JOB_NOTIFY_TYPE,
				 JOB_NOTIFY_STATUS, jobid,
				 status, 0, flags);
}

void notify_job_status(int snum, uint32 jobid, uint32 status)
{
	const char *printer_name = lp_const_servicename_unix(snum);

	notify_job_status_byname(printer_name, jobid, status, 0);
}

void notify_job_total_bytes(int snum, uint32 jobid, uint32 size)
{
	const char *printer_name = lp_const_servicename_unix(snum);

	/* Job id stored in id field, status in value1 */

	send_notify_field_values(printer_name, JOB_NOTIFY_TYPE,
				 JOB_NOTIFY_TOTAL_BYTES, jobid,
				 size, 0, 0);
}

void notify_job_total_pages(int snum, uint32 jobid, uint32 pages)
{
	const char *printer_name = lp_const_servicename_unix(snum);

	/* Job id stored in id field, status in value1 */

	send_notify_field_values(printer_name, JOB_NOTIFY_TYPE,
				 JOB_NOTIFY_TOTAL_PAGES, jobid,
				 pages, 0, 0);
}

void notify_job_username(int snum, uint32 jobid, char *name)
{
	const char *printer_name = lp_const_servicename_unix(snum);

	send_notify_field_buffer(
		printer_name, JOB_NOTIFY_TYPE, JOB_NOTIFY_USER_NAME,
		jobid, strlen(name) + 1, name);
}

void notify_job_name(int snum, uint32 jobid, char *name)
{
	const char *printer_name = lp_const_servicename_unix(snum);

	send_notify_field_buffer(
		printer_name, JOB_NOTIFY_TYPE, JOB_NOTIFY_DOCUMENT,
		jobid, strlen(name) + 1, name);
}

void notify_job_submitted(int snum, uint32 jobid, time_t submitted)
{
	const char *printer_name = lp_const_servicename_unix(snum);

	send_notify_field_buffer(
		printer_name, JOB_NOTIFY_TYPE, JOB_NOTIFY_SUBMITTED,
		jobid, sizeof(submitted), (char *)&submitted);
}

void notify_printer_driver(int snum, char *driver_name)
{
	const char *printer_name = lp_const_servicename_unix(snum);

	send_notify_field_buffer(
		printer_name, PRINTER_NOTIFY_TYPE, PRINTER_NOTIFY_DRIVER_NAME,
		snum, strlen(driver_name) + 1, driver_name);
}

void notify_printer_comment(int snum, char *comment)
{
	const char *printer_name = lp_const_servicename_unix(snum);

	send_notify_field_buffer(
		printer_name, PRINTER_NOTIFY_TYPE, PRINTER_NOTIFY_COMMENT,
		snum, strlen(comment) + 1, comment);
}

void notify_printer_sharename(int snum, char *share_name)
{
	const char *printer_name = lp_const_servicename_unix(snum);

	send_notify_field_buffer(
		printer_name, PRINTER_NOTIFY_TYPE, PRINTER_NOTIFY_SHARE_NAME,
		snum, strlen(share_name) + 1, share_name);
}

void notify_printer_port(int snum, char *port_name)
{
	const char *printer_name = lp_const_servicename_unix(snum);

	send_notify_field_buffer(
		printer_name, PRINTER_NOTIFY_TYPE, PRINTER_NOTIFY_PORT_NAME,
		snum, strlen(port_name) + 1, port_name);
}

void notify_printer_location(int snum, char *location)
{
	const char *printer_name = lp_const_servicename_unix(snum);

	send_notify_field_buffer(
		printer_name, PRINTER_NOTIFY_TYPE, PRINTER_NOTIFY_LOCATION,
		snum, strlen(location) + 1, location);
}

void notify_printer_byname( char *printername, uint32 change, char *value )
{
	int snum = print_queue_snum_dos(printername);
	int type = PRINTER_NOTIFY_TYPE;
	
	if ( snum == -1 )
		return;
		
	send_notify_field_buffer( printername, type, change, snum, strlen(value), value );
} 


/****************************************************************************
 Return a malloced list of pid_t's that are interested in getting update
 messages on this print queue. Used in printing/notify to send the messages.
****************************************************************************/

BOOL print_notify_pid_list(const char *unix_printername, TALLOC_CTX *mem_ctx, size_t *p_num_pids, pid_t **pp_pid_list)
{
	struct tdb_print_db *pdb = NULL;
	TDB_CONTEXT *tdb = NULL;
	TDB_DATA data;
	BOOL ret = True;
	size_t i, num_pids, offset;
	pid_t *pid_list;

	*p_num_pids = 0;
	*pp_pid_list = NULL;

	pdb = get_print_db_byname(unix_printername);
	if (!pdb)
		return False;
	tdb = pdb->tdb;

	if (tdb_read_lock_bystring(tdb, NOTIFY_PID_LIST_KEY, 10) == -1) {
		DEBUG(0,("print_notify_pid_list: Failed to lock printer %s database\n",
					unix_printername ));
		if (pdb)
			release_print_db(pdb);
		return False;
	}

	data = get_printer_notify_pid_list( tdb, unix_printername, True );

	if (!data.dptr) {
		ret = True;
		goto done;
	}

	num_pids = data.dsize / 8;

	if ((pid_list = (pid_t *)talloc(mem_ctx, sizeof(pid_t) * num_pids)) == NULL) {
		ret = False;
		goto done;
	}

	for( i = 0, offset = 0; offset < data.dsize; offset += 8, i++)
		pid_list[i] = (pid_t)IVAL(data.dptr, offset);

	*pp_pid_list = pid_list;
	*p_num_pids = num_pids;

	ret = True;

  done:

	tdb_read_unlock_bystring(tdb, NOTIFY_PID_LIST_KEY);
	if (pdb)
		release_print_db(pdb);
	SAFE_FREE(data.dptr);
	return ret;
}


