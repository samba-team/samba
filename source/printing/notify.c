/* 
   Unix SMB/Netbios implementation.
   Version 2.2
   printing backend routines
   Copyright (C) Tim Potter,            2002
   Copyright (C) Gerald Carter,         2002
   
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
	void *buf;
	size_t buflen;
} *notify_queue_head = NULL;

/*******************************************************************
 Used to decide if we need a short select timeout.
*******************************************************************/

BOOL print_notify_messages_pending(void)
{
	return (notify_queue_head != NULL);
}

/*******************************************************************
 Actually send the batched messages.
*******************************************************************/

void print_notify_send_messages(void)
{
	TDB_CONTEXT *tdb;
	char *buf;
	struct notify_queue *pq;
	size_t msg_count = 0, offset = 0;

	if (!print_notify_messages_pending())
		return;

	if (!send_ctx)
		return;

	tdb = conn_tdb_ctx();

	if (!tdb) {
		DEBUG(3, ("Failed to open connections database in send_spoolss_notify2_msg\n"));
		return;
	}
	
	/* Count the space needed to send the messages. */
	for (pq = notify_queue_head; pq; pq = pq->next, msg_count++)
		offset += (pq->buflen + 4);
		
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
	for (pq = notify_queue_head; pq; pq = pq->next) {
		SIVAL(buf,offset,pq->buflen);
		offset += 4;
		memcpy(buf + offset, pq->buf, pq->buflen);
		offset += pq->buflen;
	}

	DEBUG(5, ("print_notify_send_messages: sending %d print notify message%s\n", 
		  msg_count, msg_count != 1 ? "s" : ""));

	message_send_all(tdb, MSG_PRINTER_NOTIFY2, buf, offset, False, NULL);
	talloc_destroy_pool(send_ctx);
	notify_queue_head = NULL;
}

/*******************************************************************
 Batch up print notify messages.
*******************************************************************/

static void send_spoolss_notify2_msg(struct spoolss_notify_msg *msg)
{
	char *buf = NULL;
	size_t buflen = 0, len;
	struct notify_queue *pnqueue;

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

	pnqueue->buf = buf;
	pnqueue->buflen = buflen;

	DEBUG(5, ("send_spoolss_notify2_msg: appending message 0x%02x/0x%02x to notify_queue_head\n", msg->type, msg->field));
		  
	DLIST_ADD(notify_queue_head, pnqueue);
	return;

  fail:

	DEBUG(0,("send_spoolss_notify2_msg: Out of memory.\n"));
}

static void send_notify_field_values(const char *printer_name, uint32 type,
				     uint32 field, uint32 id, uint32 value1, 
				     uint32 value2, uint32 flags)
{
	struct spoolss_notify_msg msg;

	ZERO_STRUCT(msg);

	fstrcpy(msg.printer, printer_name);
	msg.type = type;
	msg.field = field;
	msg.id = id;
	msg.notify.value[0] = value1;
	msg.notify.value[1] = value2;
	msg.flags = flags;

	send_spoolss_notify2_msg(&msg);
}

static void send_notify_field_buffer(const char *printer_name, uint32 type,
				     uint32 field, uint32 id, uint32 len,
				     char *buffer)
{
	struct spoolss_notify_msg msg;

	ZERO_STRUCT(msg);

	fstrcpy(msg.printer, printer_name);
	msg.type = type;
	msg.field = field;
	msg.id = id;
	msg.len = len;
	msg.notify.data = buffer;

	send_spoolss_notify2_msg(&msg);
}

/* Send a message that the printer status has changed */

void notify_printer_status_byname(const char *printer_name, uint32 status)
{
	/* Printer status stored in value1 */

	send_notify_field_values(printer_name, PRINTER_NOTIFY_TYPE, 
				 PRINTER_NOTIFY_STATUS, 0, 
				 status, 0, 0);
}

void notify_printer_status(int snum, uint32 status)
{
	const char *printer_name = SERVICE(snum); 

	if (printer_name)
		notify_printer_status_byname(printer_name, status);
}

void notify_job_status_byname(const char *printer_name, uint32 jobid, uint32 status,
			      uint32 flags)
{
	/* Job id stored in id field, status in value1 */

	send_notify_field_values(printer_name, JOB_NOTIFY_TYPE,
				 JOB_NOTIFY_STATUS, jobid,
				 status, 0, flags);
}

void notify_job_status(int snum, uint32 jobid, uint32 status)
{
	const char *printer_name = SERVICE(snum);

	notify_job_status_byname(printer_name, jobid, status, 0);
}

void notify_job_total_bytes(int snum, uint32 jobid, uint32 size)
{
	const char *printer_name = SERVICE(snum);

	/* Job id stored in id field, status in value1 */

	send_notify_field_values(printer_name, JOB_NOTIFY_TYPE,
				 JOB_NOTIFY_TOTAL_BYTES, jobid,
				 size, 0, 0);
}

void notify_job_total_pages(int snum, uint32 jobid, uint32 pages)
{
	const char *printer_name = SERVICE(snum);

	/* Job id stored in id field, status in value1 */

	send_notify_field_values(printer_name, JOB_NOTIFY_TYPE,
				 JOB_NOTIFY_TOTAL_PAGES, jobid,
				 pages, 0, 0);
}

void notify_job_username(int snum, uint32 jobid, char *name)
{
	const char *printer_name = SERVICE(snum);

	send_notify_field_buffer(
		printer_name, JOB_NOTIFY_TYPE, JOB_NOTIFY_USER_NAME,
		jobid, strlen(name) + 1, name);
}

void notify_job_name(int snum, uint32 jobid, char *name)
{
	const char *printer_name = SERVICE(snum);

	send_notify_field_buffer(
		printer_name, JOB_NOTIFY_TYPE, JOB_NOTIFY_DOCUMENT,
		jobid, strlen(name) + 1, name);
}

void notify_job_submitted(int snum, uint32 jobid, time_t submitted)
{
	const char *printer_name = SERVICE(snum);

	send_notify_field_buffer(
		printer_name, JOB_NOTIFY_TYPE, JOB_NOTIFY_SUBMITTED,
		jobid, sizeof(submitted), (char *)&submitted);
}

void notify_printer_driver(int snum, char *driver_name)
{
	const char *printer_name = SERVICE(snum);

	send_notify_field_buffer(
		printer_name, PRINTER_NOTIFY_TYPE, PRINTER_NOTIFY_DRIVER_NAME,
		snum, strlen(driver_name) + 1, driver_name);
}

void notify_printer_comment(int snum, char *comment)
{
	const char *printer_name = SERVICE(snum);

	send_notify_field_buffer(
		printer_name, PRINTER_NOTIFY_TYPE, PRINTER_NOTIFY_COMMENT,
		snum, strlen(comment) + 1, comment);
}

void notify_printer_sharename(int snum, char *share_name)
{
	const char *printer_name = SERVICE(snum);

	send_notify_field_buffer(
		printer_name, PRINTER_NOTIFY_TYPE, PRINTER_NOTIFY_SHARE_NAME,
		snum, strlen(share_name) + 1, share_name);
}

void notify_printer_port(int snum, char *port_name)
{
	const char *printer_name = SERVICE(snum);

	send_notify_field_buffer(
		printer_name, PRINTER_NOTIFY_TYPE, PRINTER_NOTIFY_PORT_NAME,
		snum, strlen(port_name) + 1, port_name);
}

void notify_printer_location(int snum, char *location)
{
	const char *printer_name = SERVICE(snum);

	send_notify_field_buffer(
		printer_name, PRINTER_NOTIFY_TYPE, PRINTER_NOTIFY_LOCATION,
		snum, strlen(location) + 1, location);
}
