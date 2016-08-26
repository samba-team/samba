/*
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-2000,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-2000,
 *  Copyright (C) Jean François Micouleau      1998-2000,
 *  Copyright (C) Jeremy Allison               2001-2002,
 *  Copyright (C) Gerald Carter		       2000-2004,
 *  Copyright (C) Tim Potter                   2001-2002.
 *  Copyright (C) Guenther Deschner            2009-2010.
 *  Copyright (C) Andreas Schneider            2010.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/* Since the SPOOLSS rpc routines are basically DOS 16-bit calls wrapped
   up, all the errors returned are DOS errors, not NT status codes. */

#include "includes.h"
#include "../librpc/gen_ndr/spoolss.h"

struct notify_back_channel;

#define SPLHND_PRINTER		1
#define SPLHND_SERVER	 	2
#define SPLHND_PORTMON_TCP	3
#define SPLHND_PORTMON_LOCAL	4

/* structure to store the printer handles */
/* and a reference to what it's pointing to */
/* and the notify info asked about */
/* that's the central struct */
struct printer_handle {
	struct printer_handle *prev, *next;
	bool document_started;
	bool page_started;
	uint32_t jobid; /* jobid in printing backend */
	int printer_type;
	const char *servername;
	fstring sharename;
	uint32_t access_granted;
	struct {
		uint32_t flags;
		uint32_t options;
		fstring localmachine;
		uint32_t printerlocal;
		struct spoolss_NotifyOption *option;
		struct policy_handle cli_hnd;
		struct notify_back_channel *cli_chan;
		uint32_t change;
		/* are we in a FindNextPrinterChangeNotify() call? */
		bool fnpcn;
		struct messaging_context *msg_ctx;
	} notify;
	struct {
		fstring machine;
		fstring user;
	} client;

	/* devmode sent in the OpenPrinter() call */
	struct spoolss_DeviceMode *devmode;

	/* TODO cache the printer info2 structure */
	struct spoolss_PrinterInfo2 *info2;

};
