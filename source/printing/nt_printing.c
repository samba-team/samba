#define OLD_NTDOMAIN 1
/*
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-2000,
 *  Copyright (C) Jean François Micouleau      1998-2000.
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

#include "includes.h"

extern int DEBUGLEVEL;
extern pstring global_myname;
extern DOM_SID global_sid_World;

static TDB_CONTEXT *tdb; /* used for driver files */

#define FORMS_PREFIX "FORMS/"
#define DRIVERS_PREFIX "DRIVERS/"
#define DRIVER_INIT_PREFIX "DRIVER_INIT/"
#define PRINTERS_PREFIX "PRINTERS/"
#define GLOBAL_C_SETPRINTER "GLOBALS/c_setprinter"

#define NTDRIVERS_DATABASE_VERSION 1

/* Map generic permissions to printer object specific permissions */

struct generic_mapping printer_generic_mapping = {
	PRINTER_READ,
	PRINTER_WRITE,
	PRINTER_EXECUTE,
	PRINTER_ALL_ACCESS
};


#define FORM_USER    0	/* Forms defined by user... unclear how this works */
#define FORM_BUILTIN 1  /* Forms defined (built-in) in the spooler. */
#define FORM_PRINTER 2  /* Forms defined (added by) by a printer driver */

/* Msoft defines spooler 'built-in' forms in a specific order. The DEVMODE
'papersize' member variable is an array index to the entries in this structure.
Note: NT4 defines the forms "Letter" through "German Legal Fanfold", and W2K
adds the rest. JRR */
static nt_forms_struct default_forms[] = {
	{"Letter", FORM_BUILTIN, 0x34b5c, 0x44368, 0x0, 0x0, 0x34b5c, 0x44368},
	{"Letter Small", FORM_BUILTIN, 0x34b5c, 0x44368, 0x0, 0x0, 0x34b5c, 0x44368},
	{"Tabloid", FORM_BUILTIN, 0x44368, 0x696b8, 0x0, 0x0, 0x44368, 0x696b8},
	{"Ledger", FORM_BUILTIN, 0x696b8, 0x44368, 0x0, 0x0, 0x696b8, 0x44368},
	{"Legal", FORM_BUILTIN, 0x34b5c, 0x56d10, 0x0, 0x0, 0x34b5c, 0x56d10},
	{"Statement", FORM_BUILTIN, 0x221b4, 0x34b5c, 0x0, 0x0, 0x221b4, 0x34b5c},
	{"Executive", FORM_BUILTIN, 0x2cf56, 0x411cc, 0x0, 0x0, 0x2cf56, 0x411cc},
	{"A3", FORM_BUILTIN, 0x48828, 0x668a0, 0x0, 0x0, 0x48828, 0x668a0},
	{"A4", FORM_BUILTIN, 0x33450, 0x48828, 0x0, 0x0, 0x33450, 0x48828},
	{"A4 Small", FORM_BUILTIN, 0x33450, 0x48828, 0x0, 0x0, 0x33450, 0x48828},
	{"A5", FORM_BUILTIN, 0x24220, 0x33450, 0x0, 0x0, 0x24220, 0x33450},
	{"B4 (JIS)", FORM_BUILTIN, 0x3ebe8, 0x58de0, 0x0, 0x0, 0x3ebe8, 0x58de0},
	{"B5 (JIS)", FORM_BUILTIN, 0x2c6f0, 0x3ebe8, 0x0, 0x0, 0x2c6f0, 0x3ebe8},
	{"Folio", FORM_BUILTIN, 0x34b5c, 0x509d8, 0x0, 0x0, 0x34b5c, 0x509d8},
	{"Quarto", FORM_BUILTIN, 0x347d8, 0x43238, 0x0, 0x0, 0x347d8, 0x43238},
	{"10x14", FORM_BUILTIN, 0x3e030, 0x56d10, 0x0, 0x0, 0x3e030, 0x56d10},
	{"11x17", FORM_BUILTIN, 0x44368, 0x696b8, 0x0, 0x0, 0x44368, 0x696b8},
	{"Note", FORM_BUILTIN, 0x34b5c, 0x44368, 0x0, 0x0, 0x34b5c, 0x44368},
	{"Envelope #9", FORM_BUILTIN, 0x18079, 0x37091, 0x0, 0x0, 0x18079, 0x37091},
	{"Envelope #10", FORM_BUILTIN, 0x19947, 0x3ae94, 0x0, 0x0, 0x19947, 0x3ae94},
	{"Envelope #11", FORM_BUILTIN, 0x1be7c, 0x40565, 0x0, 0x0, 0x1be7c, 0x40565},
	{"Envelope #12", FORM_BUILTIN, 0x1d74a, 0x44368, 0x0, 0x0, 0x1d74a, 0x44368},
	{"Envelope #14", FORM_BUILTIN, 0x1f018, 0x47504, 0x0, 0x0, 0x1f018, 0x47504},
	{"C size sheet", FORM_BUILTIN, 0x696b8, 0x886d0, 0x0, 0x0, 0x696b8, 0x886d0},
	{"D size sheet", FORM_BUILTIN, 0x886d0, 0xd2d70, 0x0, 0x0, 0x886d0, 0xd2d70},
	{"E size sheet", FORM_BUILTIN, 0xd2d70, 0x110da0, 0x0, 0x0, 0xd2d70, 0x110da0},
	{"Envelope DL", FORM_BUILTIN, 0x1adb0, 0x35b60, 0x0, 0x0, 0x1adb0, 0x35b60},
	{"Envelope C5", FORM_BUILTIN, 0x278d0, 0x37e88, 0x0, 0x0, 0x278d0, 0x37e88},
	{"Envelope C3", FORM_BUILTIN, 0x4f1a0, 0x6fd10, 0x0, 0x0, 0x4f1a0, 0x6fd10},
	{"Envelope C4", FORM_BUILTIN, 0x37e88, 0x4f1a0, 0x0, 0x0, 0x37e88, 0x4f1a0},
	{"Envelope C6", FORM_BUILTIN, 0x1bd50, 0x278d0, 0x0, 0x0, 0x1bd50, 0x278d0},
	{"Envelope C65", FORM_BUILTIN, 0x1bd50, 0x37e88, 0x0, 0x0, 0x1bd50, 0x37e88},
	{"Envelope B4", FORM_BUILTIN, 0x3d090, 0x562e8, 0x0, 0x0, 0x3d090, 0x562e8},
	{"Envelope B5", FORM_BUILTIN, 0x2af80, 0x3d090, 0x0, 0x0, 0x2af80, 0x3d090},
	{"Envelope B6", FORM_BUILTIN, 0x2af80, 0x1e848, 0x0, 0x0, 0x2af80, 0x1e848},
	{"Envelope", FORM_BUILTIN, 0x1adb0, 0x38270, 0x0, 0x0, 0x1adb0, 0x38270},
	{"Envelope Monarch", FORM_BUILTIN, 0x18079, 0x2e824, 0x0, 0x0, 0x18079, 0x2e824},
	{"6 3/4 Envelope", FORM_BUILTIN, 0x167ab, 0x284ec, 0x0, 0x0, 0x167ab, 0x284ec},
	{"US Std Fanfold", FORM_BUILTIN, 0x5c3e1, 0x44368, 0x0, 0x0, 0x5c3e1, 0x44368},
	{"German Std Fanfold", FORM_BUILTIN, 0x34b5c, 0x4a6a0, 0x0, 0x0, 0x34b5c, 0x4a6a0},
	{"German Legal Fanfold", FORM_BUILTIN, 0x34b5c, 0x509d8, 0x0, 0x0, 0x34b5c, 0x509d8},
	{"B4 (ISO)", 0x1, 0x3d090, 0x562e8, 0x0, 0x0, 0x3d090, 0x562e8},
	{"Japanese Postcard", 0x1, 0x186a0, 0x24220, 0x0, 0x0, 0x186a0, 0x24220},
	{"9x11", 0x1, 0x37cf8, 0x44368, 0x0, 0x0, 0x37cf8, 0x44368},
	{"10x11", 0x1, 0x3e030, 0x44368, 0x0, 0x0, 0x3e030, 0x44368},
	{"15x11", 0x1, 0x5d048, 0x44368, 0x0, 0x0, 0x5d048, 0x44368},
	{"Envelope Invite", 0x1, 0x35b60, 0x35b60, 0x0, 0x0, 0x35b60, 0x35b60},
	{"Reserved48", 0x1, 0x1, 0x1, 0x0, 0x0, 0x1, 0x1},
	{"Reserved49", 0x1, 0x1, 0x1, 0x0, 0x0, 0x1, 0x1},
	{"Letter Extra", 0x1, 0x3ae94, 0x4a6a0, 0x0, 0x0, 0x3ae94, 0x4a6a0},
	{"Legal Extra", 0x1, 0x3ae94, 0x5d048, 0x0, 0x0, 0x3ae94, 0x5d048},
	{"Tabloid Extra", 0x1, 0x4a6a0, 0x6f9f0, 0x0, 0x0, 0x4a6a0, 0x6f9f0},
	{"A4 Extra", 0x1, 0x397c2, 0x4eb16, 0x0, 0x0, 0x397c2, 0x4eb16},
	{"Letter Transverse", 0x1, 0x34b5c, 0x44368, 0x0, 0x0, 0x34b5c, 0x44368},
	{"A4 Transverse", 0x1, 0x33450, 0x48828, 0x0, 0x0, 0x33450, 0x48828},
	{"Letter Extra Transverse", 0x1, 0x3ae94, 0x4a6a0, 0x0, 0x0, 0x3ae94, 0x4a6a0},
	{"Super A", 0x1, 0x376b8, 0x56ea0, 0x0, 0x0, 0x376b8, 0x56ea0},
	{"Super B", 0x1, 0x4a768, 0x76e58, 0x0, 0x0, 0x4a768, 0x76e58},
	{"Letter Plus", 0x1, 0x34b5c, 0x4eb16, 0x0, 0x0, 0x34b5c, 0x4eb16},
	{"A4 Plus", 0x1, 0x33450, 0x50910, 0x0, 0x0, 0x33450, 0x50910},
	{"A5 Transverse", 0x1, 0x24220, 0x33450, 0x0, 0x0, 0x24220, 0x33450},
	{"B5 (JIS) Transverse", 0x1, 0x2c6f0, 0x3ebe8, 0x0, 0x0, 0x2c6f0, 0x3ebe8},
	{"A3 Extra", 0x1, 0x4e9d0, 0x6ca48, 0x0, 0x0, 0x4e9d0, 0x6ca48},
	{"A5 Extra", 0x1, 0x2a7b0, 0x395f8, 0x0, 0x0, 0x2a7b0, 0x395f8},
	{"B5 (ISO) Extra", 0x1, 0x31128, 0x43620, 0x0, 0x0, 0x31128, 0x43620},
	{"A2", 0x1, 0x668a0, 0x91050, 0x0, 0x0, 0x668a0, 0x91050},
	{"A3 Transverse", 0x1, 0x48828, 0x668a0, 0x0, 0x0, 0x48828, 0x668a0},
	{"A3 Extra Transverse", 0x1, 0x4e9d0, 0x6ca48, 0x0, 0x0, 0x4e9d0, 0x6ca48},
	{"Japanese Double Postcard", 0x1, 0x30d40, 0x24220, 0x0, 0x0, 0x30d40, 0x24220},
	{"A6", 0x1, 0x19a28, 0x24220, 0x0, 0x0, 0x19a28, 0x24220},
	{"Japanese Envelope Kaku #2", 0x1, 0x3a980, 0x510e0, 0x0, 0x0, 0x3a980, 0x510e0},
	{"Japanese Envelope Kaku #3", 0x1, 0x34bc0, 0x43a08, 0x0, 0x0, 0x34bc0, 0x43a08},
	{"Japanese Envelope Chou #3", 0x1, 0x1d4c0, 0x395f8, 0x0, 0x0, 0x1d4c0, 0x395f8},
	{"Japanese Envelope Chou #4", 0x1, 0x15f90, 0x320c8, 0x0, 0x0, 0x15f90, 0x320c8},
	{"Letter Rotated", 0x1, 0x44368, 0x34b5c, 0x0, 0x0, 0x44368, 0x34b5c},
	{"A3 Rotated", 0x1, 0x668a0, 0x48828, 0x0, 0x0, 0x668a0, 0x48828},
	{"A4 Rotated", 0x1, 0x48828, 0x33450, 0x0, 0x0, 0x48828, 0x33450},
	{"A5 Rotated", 0x1, 0x33450, 0x24220, 0x0, 0x0, 0x33450, 0x24220},
	{"B4 (JIS) Rotated", 0x1, 0x58de0, 0x3ebe8, 0x0, 0x0, 0x58de0, 0x3ebe8},
	{"B5 (JIS) Rotated", 0x1, 0x3ebe8, 0x2c6f0, 0x0, 0x0, 0x3ebe8, 0x2c6f0},
	{"Japanese Postcard Rotated", 0x1, 0x24220, 0x186a0, 0x0, 0x0, 0x24220, 0x186a0},
	{"Double Japan Postcard Rotated", 0x1, 0x24220, 0x30d40, 0x0, 0x0, 0x24220, 0x30d40},
	{"A6 Rotated", 0x1, 0x24220, 0x19a28, 0x0, 0x0, 0x24220, 0x19a28},
	{"Japan Envelope Kaku #2 Rotated", 0x1, 0x510e0, 0x3a980, 0x0, 0x0, 0x510e0, 0x3a980},
	{"Japan Envelope Kaku #3 Rotated", 0x1, 0x43a08, 0x34bc0, 0x0, 0x0, 0x43a08, 0x34bc0},
	{"Japan Envelope Chou #3 Rotated", 0x1, 0x395f8, 0x1d4c0, 0x0, 0x0, 0x395f8, 0x1d4c0},
	{"Japan Envelope Chou #4 Rotated", 0x1, 0x320c8, 0x15f90, 0x0, 0x0, 0x320c8, 0x15f90},
	{"B6 (JIS)", 0x1, 0x1f400, 0x2c6f0, 0x0, 0x0, 0x1f400, 0x2c6f0},
	{"B6 (JIS) Rotated", 0x1, 0x2c6f0, 0x1f400, 0x0, 0x0, 0x2c6f0, 0x1f400},
	{"12x11", 0x1, 0x4a724, 0x443e1, 0x0, 0x0, 0x4a724, 0x443e1},
	{"Japan Envelope You #4", 0x1, 0x19a28, 0x395f8, 0x0, 0x0, 0x19a28, 0x395f8},
	{"Japan Envelope You #4 Rotated", 0x1, 0x395f8, 0x19a28, 0x0, 0x0, 0x395f8, 0x19a28},
	{"PRC 16K", 0x1, 0x2de60, 0x3f7a0, 0x0, 0x0, 0x2de60, 0x3f7a0},
	{"PRC 32K", 0x1, 0x1fbd0, 0x2cec0, 0x0, 0x0, 0x1fbd0, 0x2cec0},
	{"PRC 32K(Big)", 0x1, 0x222e0, 0x318f8, 0x0, 0x0, 0x222e0, 0x318f8},
	{"PRC Envelope #1", 0x1, 0x18e70, 0x28488, 0x0, 0x0, 0x18e70, 0x28488},
	{"PRC Envelope #2", 0x1, 0x18e70, 0x2af80, 0x0, 0x0, 0x18e70, 0x2af80},
	{"PRC Envelope #3", 0x1, 0x1e848, 0x2af80, 0x0, 0x0, 0x1e848, 0x2af80},
	{"PRC Envelope #4", 0x1, 0x1adb0, 0x32c80, 0x0, 0x0, 0x1adb0, 0x32c80},
	{"PRC Envelope #5", 0x1, 0x1adb0, 0x35b60, 0x0, 0x0, 0x1adb0, 0x35b60},
	{"PRC Envelope #6", 0x1, 0x1d4c0, 0x38270, 0x0, 0x0, 0x1d4c0, 0x38270},
	{"PRC Envelope #7", 0x1, 0x27100, 0x38270, 0x0, 0x0, 0x27100, 0x38270},
	{"PRC Envelope #8", 0x1, 0x1d4c0, 0x4b708, 0x0, 0x0, 0x1d4c0, 0x4b708},
	{"PRC Envelope #9", 0x1, 0x37e88, 0x4f1a0, 0x0, 0x0, 0x37e88, 0x4f1a0},
	{"PRC Envelope #10", 0x1, 0x4f1a0, 0x6fd10, 0x0, 0x0, 0x4f1a0, 0x6fd10},
	{"PRC 16K Rotated", 0x1, 0x3f7a0, 0x2de60, 0x0, 0x0, 0x3f7a0, 0x2de60},
	{"PRC 32K Rotated", 0x1, 0x2cec0, 0x1fbd0, 0x0, 0x0, 0x2cec0, 0x1fbd0},
	{"PRC 32K(Big) Rotated", 0x1, 0x318f8, 0x222e0, 0x0, 0x0, 0x318f8, 0x222e0},
	{"PRC Envelope #1 Rotated", 0x1, 0x28488, 0x18e70, 0x0, 0x0, 0x28488, 0x18e70},
	{"PRC Envelope #2 Rotated", 0x1, 0x2af80, 0x18e70, 0x0, 0x0, 0x2af80, 0x18e70},
	{"PRC Envelope #3 Rotated", 0x1, 0x2af80, 0x1e848, 0x0, 0x0, 0x2af80, 0x1e848},
	{"PRC Envelope #4 Rotated", 0x1, 0x32c80, 0x1adb0, 0x0, 0x0, 0x32c80, 0x1adb0},
	{"PRC Envelope #5 Rotated", 0x1, 0x35b60, 0x1adb0, 0x0, 0x0, 0x35b60, 0x1adb0},
	{"PRC Envelope #6 Rotated", 0x1, 0x38270, 0x1d4c0, 0x0, 0x0, 0x38270, 0x1d4c0},
	{"PRC Envelope #7 Rotated", 0x1, 0x38270, 0x27100, 0x0, 0x0, 0x38270, 0x27100},
	{"PRC Envelope #8 Rotated", 0x1, 0x4b708, 0x1d4c0, 0x0, 0x0, 0x4b708, 0x1d4c0},
	{"PRC Envelope #9 Rotated", 0x1, 0x4f1a0, 0x37e88, 0x0, 0x0, 0x4f1a0, 0x37e88},
	{"PRC Envelope #10 Rotated", 0x1, 0x6fd10, 0x4f1a0, 0x0, 0x0, 0x6fd10, 0x4f1a0},
};


/****************************************************************************
open the NT printing tdb
****************************************************************************/
BOOL nt_printing_init(void)
{
	static pid_t local_pid;
	char *vstring = "INFO/version";

	if (tdb && local_pid == sys_getpid()) return True;
	tdb = tdb_open(lock_path("ntdrivers.tdb"), 0, 0, O_RDWR|O_CREAT, 0600);
	if (!tdb) {
		DEBUG(0,("Failed to open nt drivers database %s (%s)\n",
			lock_path("ntdrivers.tdb"), strerror(errno) ));
		return False;
	}

	local_pid = sys_getpid();

	/* handle a Samba upgrade */
	tdb_lock_bystring(tdb, vstring);
	if (tdb_fetch_int(tdb, vstring) != NTDRIVERS_DATABASE_VERSION) {
		tdb_traverse(tdb, (tdb_traverse_func)tdb_delete, NULL);
		tdb_store_int(tdb, vstring, NTDRIVERS_DATABASE_VERSION);
	}
	tdb_unlock_bystring(tdb, vstring);

	update_c_setprinter(True);

    return True;
}

/*******************************************************************
 tdb traversal function for counting printers.
********************************************************************/  

static int traverse_counting_printers(TDB_CONTEXT *t, TDB_DATA key,
									  TDB_DATA data, void *context)
{
	int32 *printer_count = (int*)context;

	if (memcmp(PRINTERS_PREFIX, key.dptr, sizeof(PRINTERS_PREFIX)-1) == 0) {	
		(*printer_count)++;
		DEBUG(10,("traverse_counting_printers: printer = [%s]  printer_count = %d\n", key.dptr, *printer_count));
	}

	return 0;
}

/*******************************************************************
 Update the spooler global c_setprinter. This variable is initialized
 when the parent smbd starts whith the number of existing printers. It
 is monotonically increased by the current number of printers *after*
 each add or delete printer RPC. Only Microsoft knows why... JRR020119
********************************************************************/  

uint32 update_c_setprinter(BOOL initialize)
{
	int32 c_setprinter;
	int32 printer_count = 0;

	tdb_lock_bystring(tdb, GLOBAL_C_SETPRINTER);

	/* Traverse the tdb, counting the printers */
	tdb_traverse(tdb, traverse_counting_printers, (void *)&printer_count);

	/* If initializing, set c_setprinter to current printers count
	 * otherwise, bump it buty the current printer count
	 */
	if (!initialize)
		c_setprinter = tdb_fetch_int32(tdb, GLOBAL_C_SETPRINTER) + printer_count;
	else
		c_setprinter = printer_count;

	DEBUG(10,("update_c_setprinter: c_setprinter = %d\n", c_setprinter));
	tdb_store_int32(tdb, GLOBAL_C_SETPRINTER, c_setprinter);

	tdb_unlock_bystring(tdb, GLOBAL_C_SETPRINTER);

	return (uint32)c_setprinter;
}

/*******************************************************************
 Get the spooler global c_setprinter, accounting for initialization.
********************************************************************/  

uint32 get_c_setprinter(void)
{
	int32 c_setprinter = tdb_fetch_int32(tdb, GLOBAL_C_SETPRINTER);

	if (c_setprinter == (int32)-1)
		c_setprinter = update_c_setprinter(True);

	DEBUG(10,("get_c_setprinter: c_setprinter = %d\n", c_setprinter));
	
	return (uint32)c_setprinter;
}

/****************************************************************************
 Get builtin form struct list.
****************************************************************************/

int get_builtin_ntforms(nt_forms_struct **list)
{
	*list = (nt_forms_struct *)memdup(&default_forms[0], sizeof(default_forms));
	return sizeof(default_forms) / sizeof(default_forms[0]);
}

/****************************************************************************
 Get a builtin form struct.
****************************************************************************/

BOOL get_a_builtin_ntform(UNISTR2 *uni_formname,nt_forms_struct *form)
{
	int i,count;
	fstring form_name;
	unistr2_to_ascii(form_name, uni_formname, sizeof(form_name)-1);
	DEBUGADD(6,("Looking for builtin form %s \n", form_name));
	count = sizeof(default_forms) / sizeof(default_forms[0]);
	for (i=0;i<count;i++) {
		if (strequal(form_name,default_forms[i].name)) {
			DEBUGADD(6,("Found builtin form %s \n", form_name));
			memcpy(form,&default_forms[i],sizeof(*form));
			break;
		}
	}

	return (i !=count);
}

/****************************************************************************
get a form struct list
****************************************************************************/
int get_ntforms(nt_forms_struct **list)
{
	TDB_DATA kbuf, newkey, dbuf;
	nt_forms_struct form;
	int ret;
	int i;
	int n = 0;

	for (kbuf = tdb_firstkey(tdb);
	     kbuf.dptr;
	     newkey = tdb_nextkey(tdb, kbuf), safe_free(kbuf.dptr), kbuf=newkey) {
		if (strncmp(kbuf.dptr, FORMS_PREFIX, strlen(FORMS_PREFIX)) != 0) continue;
		
		dbuf = tdb_fetch(tdb, kbuf);
		if (!dbuf.dptr) continue;

		fstrcpy(form.name, kbuf.dptr+strlen(FORMS_PREFIX));
		ret = tdb_unpack(dbuf.dptr, dbuf.dsize, "dddddddd",
				 &i, &form.flag, &form.width, &form.length, &form.left,
				 &form.top, &form.right, &form.bottom);
		safe_free(dbuf.dptr);
		if (ret != dbuf.dsize) continue;

		*list = Realloc(*list, sizeof(nt_forms_struct)*(n+1));
		if (!*list) {
			DEBUG(0,("get_ntforms: Realloc fail.\n"));
			return 0;
		}
		(*list)[n] = form;
		n++;
	}
	

	return n;
}

/****************************************************************************
write a form struct list
****************************************************************************/
int write_ntforms(nt_forms_struct **list, int number)
{
	pstring buf, key;
	int len;
	TDB_DATA kbuf,dbuf;
	int i;

	for (i=0;i<number;i++) {
		/* save index, so list is rebuilt in correct order */
		len = tdb_pack(buf, sizeof(buf), "dddddddd",
			       i, (*list)[i].flag, (*list)[i].width, (*list)[i].length,
			       (*list)[i].left, (*list)[i].top, (*list)[i].right,
			       (*list)[i].bottom);
		if (len > sizeof(buf)) break;
		slprintf(key, sizeof(key)-1, "%s%s", FORMS_PREFIX, (*list)[i].name);
        dos_to_unix(key, True);            /* Convert key to unix-codepage */
		kbuf.dsize = strlen(key)+1;
		kbuf.dptr = key;
		dbuf.dsize = len;
		dbuf.dptr = buf;
		if (tdb_store(tdb, kbuf, dbuf, TDB_REPLACE) != 0) break;
       }

       return i;
}

/****************************************************************************
add a form struct at the end of the list
****************************************************************************/
BOOL add_a_form(nt_forms_struct **list, const FORM *form, int *count)
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
	
	unistr2_to_ascii(form_name, &form->name, sizeof(form_name)-1);
	for (n=0; n<*count; n++) {
		if (!strncmp((*list)[n].name, form_name, strlen(form_name))) {
			DEBUG(103, ("NT workaround, [%s] already exists\n", form_name));
			update=True;
			break;
		}
	}

	if (update==False) {
		if((*list=Realloc(*list, (n+1)*sizeof(nt_forms_struct))) == NULL)
			return False;
		unistr2_to_ascii((*list)[n].name, &form->name, sizeof((*list)[n].name)-1);
		(*count)++;
	}
	
	(*list)[n].flag=form->flags;
	(*list)[n].width=form->size_x;
	(*list)[n].length=form->size_y;
	(*list)[n].left=form->left;
	(*list)[n].top=form->top;
	(*list)[n].right=form->right;
	(*list)[n].bottom=form->bottom;

	return True;
}

/****************************************************************************
 delete a named form struct
****************************************************************************/
BOOL delete_a_form(nt_forms_struct **list, UNISTR2 *del_name, int *count, uint32 *ret)
{
	pstring key;
	TDB_DATA kbuf;
	int n=0;
	fstring form_name;

	*ret = 0;

	unistr2_to_ascii(form_name, del_name, sizeof(form_name)-1);

	for (n=0; n<*count; n++) {
		if (!strncmp((*list)[n].name, form_name, strlen(form_name))) {
			DEBUG(103, ("delete_a_form, [%s] in list\n", form_name));
			break;
		}
	}

	if (n == *count) {
		DEBUG(10,("delete_a_form, [%s] not found\n", form_name));
		*ret = ERROR_INVALID_PARAMETER;
		return False;
	}

	slprintf(key, sizeof(key)-1, "%s%s", FORMS_PREFIX, (*list)[n].name);
	dos_to_unix(key, True);                /* Convert key to unix-codepage */
	kbuf.dsize = strlen(key)+1;
	kbuf.dptr = key;
	if (tdb_delete(tdb, kbuf) != 0) {
		*ret = ERROR_NOT_ENOUGH_MEMORY;
		return False;
	}

	return True;
}

/****************************************************************************
update a form struct
****************************************************************************/
void update_a_form(nt_forms_struct **list, const FORM *form, int count)
{
	int n=0;
	fstring form_name;
	unistr2_to_ascii(form_name, &(form->name), sizeof(form_name)-1);

	DEBUG(106, ("[%s]\n", form_name));
	for (n=0; n<count; n++)
	{
		DEBUGADD(106, ("n [%d]:[%s]\n", n, (*list)[n].name));
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

traverse the database and look-up the matching names
****************************************************************************/
int get_ntdrivers(fstring **list, char *architecture, uint32 version)
{
	int total=0;
	fstring short_archi;
	pstring key;
	TDB_DATA kbuf, newkey;

	get_short_archi(short_archi, architecture);
	slprintf(key, sizeof(key)-1, "%s%s/%d/", DRIVERS_PREFIX, short_archi, version);

	for (kbuf = tdb_firstkey(tdb);
	     kbuf.dptr;
	     newkey = tdb_nextkey(tdb, kbuf), safe_free(kbuf.dptr), kbuf=newkey) {
		if (strncmp(kbuf.dptr, key, strlen(key)) != 0) continue;
		
		if((*list = Realloc(*list, sizeof(fstring)*(total+1))) == NULL)
			return -1;

		fstrcpy((*list)[total], kbuf.dptr+strlen(key));
		total++;
	}

	return(total);
}

/****************************************************************************
function to do the mapping between the long architecture name and
the short one.
****************************************************************************/
BOOL get_short_archi(char *short_archi, char *long_archi)
{
	struct table {
		char *long_archi;
		char *short_archi;
	};
	
	struct table archi_table[]=
	{
		{"Windows 4.0",          "WIN40"    },
		{"Windows NT x86",       "W32X86"   },
		{"Windows NT R4000",     "W32MIPS"  },
		{"Windows NT Alpha_AXP", "W32ALPHA" },
		{"Windows NT PowerPC",   "W32PPC"   },
		{NULL,                   ""         }
	};
	
	int i=-1;

	DEBUG(107,("Getting architecture dependant directory\n"));
	do {
		i++;
	} while ( (archi_table[i].long_archi!=NULL ) &&
	          StrCaseCmp(long_archi, archi_table[i].long_archi) );

	if (archi_table[i].long_archi==NULL) {
		DEBUGADD(107,("Unknown architecture [%s] !\n", long_archi));
		return FALSE;
	}

	StrnCpy (short_archi, archi_table[i].short_archi, strlen(archi_table[i].short_archi));

	DEBUGADD(108,("index: [%d]\n", i));
	DEBUGADD(108,("long architecture: [%s]\n", long_archi));
	DEBUGADD(108,("short architecture: [%s]\n", short_archi));
	
	return TRUE;
}

/****************************************************************************
Version information in Microsoft files is held in a VS_VERSION_INFO structure.
There are two case to be covered here: PE (Portable Executable) and NE (New
Executable) files. Both files support the same INFO structure, but PE files
store the signature in unicode, and NE files store it as !unicode.
returns -1 on error, 1 on version info found, and 0 on no version info found.
****************************************************************************/
static int get_file_version(files_struct *fsp, char *fname,uint32 *major,
							 uint32 *minor)
{
	int     i;
	char    *buf;
	ssize_t byte_count;

	if ((buf=malloc(PE_HEADER_SIZE)) == NULL) {
		DEBUG(0,("get_file_version: PE file [%s] PE Header malloc failed bytes = %d\n",
				fname, PE_HEADER_SIZE));
		goto error_exit;
	}

	/* Note: DOS_HEADER_SIZE < malloc'ed PE_HEADER_SIZE */
	if ((byte_count = vfs_read_data(fsp, buf, DOS_HEADER_SIZE)) < DOS_HEADER_SIZE) {
		DEBUG(3,("get_file_version: File [%s] DOS header too short, bytes read = %d\n",
				fname, byte_count));
		goto no_version_info;
	}

	/* Is this really a DOS header? */
	if (SVAL(buf,DOS_HEADER_MAGIC_OFFSET) != DOS_HEADER_MAGIC) {
		DEBUG(6,("get_file_version: File [%s] bad DOS magic = 0x%x\n",
				fname, SVAL(buf,DOS_HEADER_MAGIC_OFFSET)));
		goto no_version_info;
	}

	/* Skip OEM header (if any) and the DOS stub to start of Windows header */
	if (fsp->conn->vfs_ops.lseek(fsp, fsp->fd, SVAL(buf,DOS_HEADER_LFANEW_OFFSET), SEEK_SET) == (SMB_OFF_T)-1) {
		DEBUG(3,("get_file_version: File [%s] too short, errno = %d\n",
				fname, errno));
		/* Assume this isn't an error... the file just looks sort of like a PE/NE file */
		goto no_version_info;
	}

	if ((byte_count = vfs_read_data(fsp, buf, PE_HEADER_SIZE)) < PE_HEADER_SIZE) {
		DEBUG(3,("get_file_version: File [%s] Windows header too short, bytes read = %d\n",
				fname, byte_count));
		/* Assume this isn't an error... the file just looks sort of like a PE/NE file */
		goto no_version_info;
	}

	/* The header may be a PE (Portable Executable) or an NE (New Executable) */
	if (IVAL(buf,PE_HEADER_SIGNATURE_OFFSET) == PE_HEADER_SIGNATURE) {
		int num_sections;
		int section_table_bytes;
		
		if (SVAL(buf,PE_HEADER_MACHINE_OFFSET) != PE_HEADER_MACHINE_I386) {
			DEBUG(3,("get_file_version: PE file [%s] wrong machine = 0x%x\n",
					fname, SVAL(buf,PE_HEADER_MACHINE_OFFSET)));
			/* At this point, we assume the file is in error. It still could be somthing
			 * else besides a PE file, but it unlikely at this point.
			 */
			goto error_exit;
		}

		/* get the section table */
		num_sections        = SVAL(buf,PE_HEADER_NUMBER_OF_SECTIONS);
		section_table_bytes = num_sections * PE_HEADER_SECT_HEADER_SIZE;
		free(buf);
		if ((buf=malloc(section_table_bytes)) == NULL) {
			DEBUG(0,("get_file_version: PE file [%s] section table malloc failed bytes = %d\n",
					fname, section_table_bytes));
			goto error_exit;
		}

		if ((byte_count = vfs_read_data(fsp, buf, section_table_bytes)) < section_table_bytes) {
			DEBUG(3,("get_file_version: PE file [%s] Section header too short, bytes read = %d\n",
					fname, byte_count));
			goto error_exit;
		}

		/* Iterate the section table looking for the resource section ".rsrc" */
		for (i = 0; i < num_sections; i++) {
			int sec_offset = i * PE_HEADER_SECT_HEADER_SIZE;

			if (strcmp(".rsrc", &buf[sec_offset+PE_HEADER_SECT_NAME_OFFSET]) == 0) {
				int section_pos   = IVAL(buf,sec_offset+PE_HEADER_SECT_PTR_DATA_OFFSET);
				int section_bytes = IVAL(buf,sec_offset+PE_HEADER_SECT_SIZE_DATA_OFFSET);

				free(buf);
				if ((buf=malloc(section_bytes)) == NULL) {
					DEBUG(0,("get_file_version: PE file [%s] version malloc failed bytes = %d\n",
							fname, section_bytes));
					goto error_exit;
				}

				/* Seek to the start of the .rsrc section info */
				if (fsp->conn->vfs_ops.lseek(fsp, fsp->fd, section_pos, SEEK_SET) == (SMB_OFF_T)-1) {
					DEBUG(3,("get_file_version: PE file [%s] too short for section info, errno = %d\n",
							fname, errno));
					goto error_exit;
				}

				if ((byte_count = vfs_read_data(fsp, buf, section_bytes)) < section_bytes) {
					DEBUG(3,("get_file_version: PE file [%s] .rsrc section too short, bytes read = %d\n",
							fname, byte_count));
					goto error_exit;
				}

				for (i=0; i<section_bytes-VS_VERSION_INFO_UNICODE_SIZE; i++) {
					/* Scan for 1st 3 unicoded bytes followed by word aligned magic value */
					if (buf[i] == 'V' && buf[i+1] == '\0' && buf[i+2] == 'S') {
						/* Align to next long address */
						int pos = (i + sizeof(VS_SIGNATURE)*2 + 3) & 0xfffffffc;

						if (IVAL(buf,pos) == VS_MAGIC_VALUE) {
							*major = IVAL(buf,pos+VS_MAJOR_OFFSET);
							*minor = IVAL(buf,pos+VS_MINOR_OFFSET);
							
							DEBUG(6,("get_file_version: PE file [%s] Version = %08x:%08x (%d.%d.%d.%d)\n",
									  fname, *major, *minor,
									  (*major>>16)&0xffff, *major&0xffff,
									  (*minor>>16)&0xffff, *minor&0xffff));
							free(buf);
							return 1;
						}
					}
				}
			}
		}

		/* Version info not found, fall back to origin date/time */
		DEBUG(10,("get_file_version: PE file [%s] has no version info\n", fname));
		free(buf);
		return 0;

	} else if (SVAL(buf,NE_HEADER_SIGNATURE_OFFSET) == NE_HEADER_SIGNATURE) {
		if (CVAL(buf,NE_HEADER_TARGET_OS_OFFSET) != NE_HEADER_TARGOS_WIN ) {
			DEBUG(3,("get_file_version: NE file [%s] wrong target OS = 0x%x\n",
					fname, CVAL(buf,NE_HEADER_TARGET_OS_OFFSET)));
			/* At this point, we assume the file is in error. It still could be somthing
			 * else besides a NE file, but it unlikely at this point. */
			goto error_exit;
		}

		/* Allocate a bit more space to speed up things */
		free(buf);
		if ((buf=malloc(VS_NE_BUF_SIZE)) == NULL) {
			DEBUG(0,("get_file_version: NE file [%s] malloc failed bytes  = %d\n",
					fname, PE_HEADER_SIZE));
			goto error_exit;
		}

		/* This is a HACK! I got tired of trying to sort through the messy
		 * 'NE' file format. If anyone wants to clean this up please have at
		 * it, but this works. 'NE' files will eventually fade away. JRR */
		while((byte_count = vfs_read_data(fsp, buf, VS_NE_BUF_SIZE)) > 0) {
			/* Cover case that should not occur in a well formed 'NE' .dll file */
			if (byte_count-VS_VERSION_INFO_SIZE <= 0) break;

			for(i=0; i<byte_count; i++) {
				/* Fast skip past data that can't possibly match */
				if (buf[i] != 'V') continue;

				/* Potential match data crosses buf boundry, move it to beginning
				 * of buf, and fill the buf with as much as it will hold. */
				if (i>byte_count-VS_VERSION_INFO_SIZE) {
					int bc;

					memcpy(buf, &buf[i], byte_count-i);
					if ((bc = vfs_read_data(fsp, &buf[byte_count-i], VS_NE_BUF_SIZE-
								   (byte_count-i))) < 0) {

						DEBUG(0,("get_file_version: NE file [%s] Read error, errno=%d\n",
								 fname, errno));
						goto error_exit;
					}

					byte_count = bc + (byte_count - i);
					if (byte_count<VS_VERSION_INFO_SIZE) break;

					i = 0;
				}

				/* Check that the full signature string and the magic number that
				 * follows exist (not a perfect solution, but the chances that this
				 * occurs in code is, well, remote. Yes I know I'm comparing the 'V'
				 * twice, as it is simpler to read the code. */
				if (strcmp(&buf[i], VS_SIGNATURE) == 0) {
					/* Compute skip alignment to next long address */
					int skip = -(fsp->conn->vfs_ops.lseek(fsp, fsp->fd, 0, SEEK_CUR) - (byte_count - i) +
								 sizeof(VS_SIGNATURE)) & 3;
					if (IVAL(buf,i+sizeof(VS_SIGNATURE)+skip) != 0xfeef04bd) continue;

					*major = IVAL(buf,i+sizeof(VS_SIGNATURE)+skip+VS_MAJOR_OFFSET);
					*minor = IVAL(buf,i+sizeof(VS_SIGNATURE)+skip+VS_MINOR_OFFSET);
					DEBUG(6,("get_file_version: NE file [%s] Version = %08x:%08x (%d.%d.%d.%d)\n",
							  fname, *major, *minor,
							  (*major>>16)&0xffff, *major&0xffff,
							  (*minor>>16)&0xffff, *minor&0xffff));
					free(buf);
					return 1;
				}
			}
		}

		/* Version info not found, fall back to origin date/time */
		DEBUG(0,("get_file_version: NE file [%s] Version info not found\n", fname));
		free(buf);
		return 0;

	} else
		/* Assume this isn't an error... the file just looks sort of like a PE/NE file */
		DEBUG(3,("get_file_version: File [%s] unknown file format, signature = 0x%x\n",
				fname, IVAL(buf,PE_HEADER_SIGNATURE_OFFSET)));

	no_version_info:
		free(buf);
		return 0;

	error_exit:
		free(buf);
		return -1;
}

/****************************************************************************
Drivers for Microsoft systems contain multiple files. Often, multiple drivers
share one or more files. During the MS installation process files are checked
to insure that only a newer version of a shared file is installed over an
older version. There are several possibilities for this comparison. If there
is no previous version, the new one is newer (obviously). If either file is
missing the version info structure, compare the creation date (on Unix use
the modification date). Otherwise chose the numerically larger version number.
****************************************************************************/
static int file_version_is_newer(connection_struct *conn, fstring new_file,
								fstring old_file)
{
	BOOL   use_version = True;
	pstring filepath;

	uint32 new_major;
	uint32 new_minor;
	time_t new_create_time;

	uint32 old_major;
	uint32 old_minor;
	time_t old_create_time;

	int access_mode;
	int action;
	files_struct    *fsp = NULL;
	SMB_STRUCT_STAT st;
	SMB_STRUCT_STAT stat_buf;
	BOOL bad_path;

	ZERO_STRUCT(st);
	ZERO_STRUCT(stat_buf);
	new_create_time = (time_t)0;
	old_create_time = (time_t)0;

	/* Get file version info (if available) for previous file (if it exists) */
	pstrcpy(filepath, old_file);

	unix_convert(filepath,conn,NULL,&bad_path,&stat_buf);

	fsp = open_file_shared(conn, filepath, &stat_buf,
						   SET_OPEN_MODE(DOS_OPEN_RDONLY),
						   (FILE_FAIL_IF_NOT_EXIST|FILE_EXISTS_OPEN),
						   0, 0, &access_mode, &action);
	if (!fsp) {
		/* Old file not found, so by definition new file is in fact newer */
		DEBUG(10,("file_version_is_newer: Can't open old file [%s], errno = %d\n",
				filepath, errno));
		return True;

	} else {
		int ret = get_file_version(fsp, old_file, &old_major, &old_minor);
		if (ret == -1) goto error_exit;

		if (!ret) {
			DEBUG(6,("file_version_is_newer: Version info not found [%s], use mod time\n",
					 old_file));
			use_version = False;
			if (fsp->conn->vfs_ops.fstat(fsp, fsp->fd, &st) == -1) goto error_exit;
			old_create_time = st.st_mtime;
			DEBUGADD(6,("file_version_is_newer: mod time = %ld sec\n", old_create_time));
		}
	}
	close_file(fsp, True);

	/* Get file version info (if available) for new file */
	pstrcpy(filepath, new_file);
	unix_convert(filepath,conn,NULL,&bad_path,&stat_buf);

	fsp = open_file_shared(conn, filepath, &stat_buf,
						   SET_OPEN_MODE(DOS_OPEN_RDONLY),
						   (FILE_FAIL_IF_NOT_EXIST|FILE_EXISTS_OPEN),
						   0, 0, &access_mode, &action);
	if (!fsp) {
		/* New file not found, this shouldn't occur if the caller did its job */
		DEBUG(3,("file_version_is_newer: Can't open new file [%s], errno = %d\n",
				filepath, errno));
		goto error_exit;

	} else {
		int ret = get_file_version(fsp, new_file, &new_major, &new_minor);
		if (ret == -1) goto error_exit;

		if (!ret) {
			DEBUG(6,("file_version_is_newer: Version info not found [%s], use mod time\n",
					 new_file));
			use_version = False;
			if (fsp->conn->vfs_ops.fstat(fsp, fsp->fd, &st) == -1) goto error_exit;
			new_create_time = st.st_mtime;
			DEBUGADD(6,("file_version_is_newer: mod time = %ld sec\n", new_create_time));
		}
	}
	close_file(fsp, True);

	if (use_version) {
		/* Compare versions and choose the larger version number */
		if (new_major > old_major ||
			(new_major == old_major && new_minor > old_minor)) {
			
			DEBUG(6,("file_version_is_newer: Replacing [%s] with [%s]\n", old_file, new_file));
			return True;
		}
		else {
			DEBUG(6,("file_version_is_newer: Leaving [%s] unchanged\n", old_file));
			return False;
		}

	} else {
		/* Compare modification time/dates and choose the newest time/date */
		if (new_create_time > old_create_time) {
			DEBUG(6,("file_version_is_newer: Replacing [%s] with [%s]\n", old_file, new_file));
			return True;
		}
		else {
			DEBUG(6,("file_version_is_newer: Leaving [%s] unchanged\n", old_file));
			return False;
		}
	}

	error_exit:
		if(fsp)
			close_file(fsp, True);
		return -1;
}

/****************************************************************************
Determine the correct cVersion associated with an architecture and driver
****************************************************************************/
static uint32 get_correct_cversion(fstring architecture, fstring driverpath_in,
								   struct current_user *user, uint32 *perr)
{
	int               cversion;
	int               access_mode;
	int               action;
	int               ecode;
	pstring           driverpath;
	fstring           user_name;
	fstring           null_pw;
	files_struct      *fsp = NULL;
	BOOL              bad_path;
	SMB_STRUCT_STAT   st;
	struct passwd *pass;
	connection_struct *conn;

	ZERO_STRUCT(st);

	*perr = ERROR_INVALID_PARAMETER;

	/* If architecture is Windows 95/98, the version is always 0. */
	if (strcmp(architecture, "WIN40") == 0) {
		DEBUG(10,("get_correct_cversion: Driver is Win9x, cversion = 0\n"));
		*perr = 0;
		return 0;
	}

	become_root();
	pass = getpwuid(user->uid);
	if(pass == NULL) {
		DEBUG(0,("get_correct_cversion: Unable to get passwd entry for uid %u\n",
				(unsigned int)user->uid ));
		unbecome_root();
		*perr = ERROR_ACCESS_DENIED;
		return -1;
	}
	unbecome_root();

	/* connect to the print$ share under the same account as the user connected
	 * to the rpc pipe */	
	fstrcpy(user_name, pass->pw_name );
	DEBUG(10,("get_correct_cversion: uid %d -> user %s\n", (int)user->uid, user_name));

	/* Null password is ok - we are already an authenticated user... */
	*null_pw = '\0';
	conn = make_connection("print$", user_name, null_pw, 0, "A:", user->vuid, &ecode);

	if (conn == NULL) {
		DEBUG(0,("get_correct_cversion: Unable to connect\n"));
		*perr = (uint32)ecode;
		return -1;
	}

	/* Save who we are - we are temporarily becoming the connection user. */
	push_sec_ctx();

	if (!become_user(conn, conn->vuid)) {
		DEBUG(0,("get_correct_cversion: Can't become user %s\n", user_name ));
		*perr = ERROR_ACCESS_DENIED;
		pop_sec_ctx();
		return -1;
	}

	/* Open the driver file (Portable Executable format) and determine the
	 * deriver the cversion. */
	slprintf(driverpath, sizeof(driverpath)-1, "%s/%s", architecture, driverpath_in);

	unix_convert(driverpath,conn,NULL,&bad_path,&st);

	fsp = open_file_shared(conn, driverpath, &st,
						   SET_OPEN_MODE(DOS_OPEN_RDONLY),
						   (FILE_FAIL_IF_NOT_EXIST|FILE_EXISTS_OPEN),
						   0, 0, &access_mode, &action);
	if (!fsp) {
		DEBUG(3,("get_correct_cversion: Can't open file [%s], errno = %d\n",
				driverpath, errno));
		*perr = ERROR_ACCESS_DENIED;
		goto error_exit;
	}
	else {
		uint32 major;
		uint32 minor;
		int    ret = get_file_version(fsp, driverpath, &major, &minor);
		if (ret == -1) goto error_exit;

		if (!ret) {
			DEBUG(6,("get_correct_cversion: Version info not found [%s]\n", driverpath));
			goto error_exit;
		}

		/*
		 * This is a Microsoft'ism. See references in MSDN to VER_FILEVERSION
		 * for more details. Version in this case is not just the version of the 
		 * file, but the version in the sense of kernal mode (2) vs. user mode
		 * (3) drivers. Other bits of the version fields are the version info. 
		 * JRR 010716
		*/
		cversion = major & 0x0000ffff;
		switch (cversion) {
			case 2: /* WinNT drivers */
			case 3: /* Win2K drivers */
				break;
			
			default:
				DEBUG(6,("get_correct_cversion: cversion invalid [%s]  cversion = %d\n", 
					driverpath, cversion));
				goto error_exit;
		}

		DEBUG(10,("get_correct_cversion: Version info found [%s]  major = 0x%x  minor = 0x%x\n",
				  driverpath, major, minor));
	}

	DEBUG(10,("get_correct_cversion: Driver file [%s] cversion = %d\n",
			driverpath, cversion));

	close_file(fsp, True);
	close_cnum(conn, user->vuid);
	pop_sec_ctx();
	*perr = 0;
	return cversion;

  error_exit:
	if(fsp)
		close_file(fsp, True);
	close_cnum(conn, user->vuid);
	pop_sec_ctx();
	return -1;
}

/****************************************************************************
****************************************************************************/
static uint32 clean_up_driver_struct_level_3(NT_PRINTER_DRIVER_INFO_LEVEL_3 *driver,
											 struct current_user *user)
{
	fstring architecture;
	fstring new_name;
	char *p;
	int i;
	uint32 err;

	/* clean up the driver name.
	 * we can get .\driver.dll
	 * or worse c:\windows\system\driver.dll !
	 */
	/* using an intermediate string to not have overlaping memcpy()'s */
	if ((p = strrchr(driver->driverpath,'\\')) != NULL) {
		fstrcpy(new_name, p+1);
		fstrcpy(driver->driverpath, new_name);
	}

	if ((p = strrchr(driver->datafile,'\\')) != NULL) {
		fstrcpy(new_name, p+1);
		fstrcpy(driver->datafile, new_name);
	}

	if ((p = strrchr(driver->configfile,'\\')) != NULL) {
		fstrcpy(new_name, p+1);
		fstrcpy(driver->configfile, new_name);
	}

	if ((p = strrchr(driver->helpfile,'\\')) != NULL) {
		fstrcpy(new_name, p+1);
		fstrcpy(driver->helpfile, new_name);
	}

	if (driver->dependentfiles) {
		for (i=0; *driver->dependentfiles[i]; i++) {
			if ((p = strrchr(driver->dependentfiles[i],'\\')) != NULL) {
				fstrcpy(new_name, p+1);
				fstrcpy(driver->dependentfiles[i], new_name);
			}
		}
	}

	get_short_archi(architecture, driver->environment);
	
	/* jfm:7/16/2000 the client always sends the cversion=0.
	 * The server should check which version the driver is by reading
	 * the PE header of driver->driverpath.
	 *
	 * For Windows 95/98 the version is 0 (so the value sent is correct)
	 * For Windows NT (the architecture doesn't matter)
	 *	NT 3.1: cversion=0
	 *	NT 3.5/3.51: cversion=1
	 *	NT 4: cversion=2
	 *	NT2K: cversion=3
	 */
	if ((driver->cversion = get_correct_cversion( architecture,
									driver->driverpath, user, &err)) == -1)
		return err;

	return NT_STATUS_NO_PROBLEMO;
}
	
/****************************************************************************
****************************************************************************/
static uint32 clean_up_driver_struct_level_6(NT_PRINTER_DRIVER_INFO_LEVEL_6 *driver,
											 struct current_user *user)
{
	fstring architecture;
	fstring new_name;
	char *p;
	int i;
	uint32 err;

	/* clean up the driver name.
	 * we can get .\driver.dll
	 * or worse c:\windows\system\driver.dll !
	 */
	/* using an intermediate string to not have overlaping memcpy()'s */
	if ((p = strrchr(driver->driverpath,'\\')) != NULL) {
		fstrcpy(new_name, p+1);
		fstrcpy(driver->driverpath, new_name);
	}

	if ((p = strrchr(driver->datafile,'\\')) != NULL) {
		fstrcpy(new_name, p+1);
		fstrcpy(driver->datafile, new_name);
	}

	if ((p = strrchr(driver->configfile,'\\')) != NULL) {
		fstrcpy(new_name, p+1);
		fstrcpy(driver->configfile, new_name);
	}

	if ((p = strrchr(driver->helpfile,'\\')) != NULL) {
		fstrcpy(new_name, p+1);
		fstrcpy(driver->helpfile, new_name);
	}

	if (driver->dependentfiles) {
		for (i=0; *driver->dependentfiles[i]; i++) {
			if ((p = strrchr(driver->dependentfiles[i],'\\')) != NULL) {
				fstrcpy(new_name, p+1);
				fstrcpy(driver->dependentfiles[i], new_name);
			}
		}
	}

	get_short_archi(architecture, driver->environment);

	/* jfm:7/16/2000 the client always sends the cversion=0.
	 * The server should check which version the driver is by reading
	 * the PE header of driver->driverpath.
	 *
	 * For Windows 95/98 the version is 0 (so the value sent is correct)
	 * For Windows NT (the architecture doesn't matter)
	 *	NT 3.1: cversion=0
	 *	NT 3.5/3.51: cversion=1
	 *	NT 4: cversion=2
	 *	NT2K: cversion=3
	 */
	if ((driver->version = get_correct_cversion(architecture,
									driver->driverpath, user, &err)) == -1)
		return err;

	return NT_STATUS_NO_PROBLEMO;
}

/****************************************************************************
****************************************************************************/
uint32 clean_up_driver_struct(NT_PRINTER_DRIVER_INFO_LEVEL driver_abstract,
							  uint32 level, struct current_user *user)
{
	switch (level) {
		case 3:
		{
			NT_PRINTER_DRIVER_INFO_LEVEL_3 *driver;
			driver=driver_abstract.info_3;
			return clean_up_driver_struct_level_3(driver, user);
		}
		case 6:
		{
			NT_PRINTER_DRIVER_INFO_LEVEL_6 *driver;
			driver=driver_abstract.info_6;
			return clean_up_driver_struct_level_6(driver, user);
		}
		default:
			return ERROR_INVALID_PARAMETER;
	}
}

/****************************************************************************
****************************************************************************/
static uint32 validate_driver_hook(char *command) 
{
	int     ret;
	char   *path;
	pstring tmp_file;
	pid_t   local_pid = sys_getpid();

	/* build a result file... which we don't care about */
	if (*lp_pathname(lp_servicenumber(PRINTERS_NAME)))
		path = lp_pathname(lp_servicenumber(PRINTERS_NAME));
	else
		path = tmpdir();

	slprintf(tmp_file, sizeof(tmp_file), "%s/smbcmd.%d", path, local_pid);
	unlink(tmp_file);

    /* Convert script args to unix-codepage */
    dos_to_unix(command, True);
	DEBUG(10,("validate_driver_hook: Running [%s > %s]\n", command, tmp_file));
	ret = smbrun(command, tmp_file, False);
	DEBUGADD(10,("validate_driver_hook: Returned [%d]\n", ret));

	unlink(tmp_file);

	return ret==0 ? NT_STATUS_NO_PROBLEMO : NT_STATUS_FILE_INVALID;
}

/* NB: pstrings are *not* big enough. E.g. "EPSOM Stylus Photo 2000P" copies
 * 85 files... you do the math. BTW, many of these files are not really driver
 * files, but other junk that is transfered during Point and Print. No wonder
 * printer drivers get such a bad rap from sys admins. JRR */
#define VALIDIDATE_DRIVER_COMMAND_SZ 2048

/* Local convenience macros */
#define VALIDATE_STRCAT(d,s) \
{ \
	safe_strcat(d, " ", VALIDIDATE_DRIVER_COMMAND_SZ-1); \
	safe_strcat(d, s,   VALIDIDATE_DRIVER_COMMAND_SZ-1); \
}
#define VALIDATE_STRCAT_QUOTED(d,s) \
{ \
	safe_strcat(d, " \"", VALIDIDATE_DRIVER_COMMAND_SZ-1); \
	safe_strcat(d, s,     VALIDIDATE_DRIVER_COMMAND_SZ-1); \
	safe_strcat(d, "\"",  VALIDIDATE_DRIVER_COMMAND_SZ-1); \
}

/****************************************************************************
****************************************************************************/
static uint32 validate_driver_3(char *cmd, char *path,
								NT_PRINTER_DRIVER_INFO_LEVEL_3 *driver)
{
	int     i;
	char    command[VALIDIDATE_DRIVER_COMMAND_SZ];
	char    cversion[16];
	fstring architecture;

	/* build the command string */
	safe_strcpy(command, cmd, sizeof(command)-1);
	
	VALIDATE_STRCAT_QUOTED(command, driver->name);

	slprintf(cversion, sizeof(cversion)-1, "%d", driver->cversion);
	VALIDATE_STRCAT(command, cversion);
	
	get_short_archi(architecture, driver->environment);
	VALIDATE_STRCAT(command, architecture);
	
	VALIDATE_STRCAT_QUOTED(command, path);
	
	VALIDATE_STRCAT(command, driver->driverpath);
	VALIDATE_STRCAT(command, driver->configfile);
	VALIDATE_STRCAT(command, driver->datafile);
	VALIDATE_STRCAT(command, driver->helpfile);
	for (i=0; driver->dependentfiles[i][0]; i++)
		VALIDATE_STRCAT(command, driver->dependentfiles[i]);

	DEBUG(10, ("validate_driver_3: command = [%s]\n", command));
	return validate_driver_hook(command);
}

/****************************************************************************
****************************************************************************/
static uint32 validate_driver_6(char *cmd, char *path,
								NT_PRINTER_DRIVER_INFO_LEVEL_6 *driver)
{
	int     i;
	char    command[VALIDIDATE_DRIVER_COMMAND_SZ];
	char    cversion[16];
	fstring architecture;

	/* build the command string */
	safe_strcpy(command, cmd, sizeof(command)-1);
	
	VALIDATE_STRCAT_QUOTED(command, driver->name);

	slprintf(cversion, sizeof(cversion)-1, "%d", driver->version);
	VALIDATE_STRCAT(command, cversion);
	
	get_short_archi(architecture, driver->environment);
	VALIDATE_STRCAT(command, architecture);
	
	VALIDATE_STRCAT_QUOTED(command, path);
	
	VALIDATE_STRCAT(command, driver->driverpath);
	VALIDATE_STRCAT(command, driver->configfile);
	VALIDATE_STRCAT(command, driver->datafile);
	VALIDATE_STRCAT(command, driver->helpfile);
	for (i=0; driver->dependentfiles[i][0]; i++)
		VALIDATE_STRCAT(command, driver->dependentfiles[i]);

	DEBUG(10, ("validate_driver_6: command = [%s]\n", command));
	return validate_driver_hook(command);
}

/****************************************************************************
****************************************************************************/
uint32 validate_driver(NT_PRINTER_DRIVER_INFO_LEVEL *driver_abstract, 
							uint32 level)
{
	int     ret;
	char   *path = lp_pathname(lp_servicenumber("print$"));
	char   *cmd  = lp_validatedriver_cmd();

	/* if there is no path for drivers, what are we doing here? */
	if (!path) {
		DEBUG(10, ("validate_driver: Error - print$ not found\n"));
		return NT_STATUS_ACCESS_DENIED;
	}

	switch (level) {
		case 3:
		{
			NT_PRINTER_DRIVER_INFO_LEVEL_3 *driver = driver_abstract->info_3;
			ret = validate_driver_3(cmd, path, driver);
			break;
		}
		case 6:
		{
			NT_PRINTER_DRIVER_INFO_LEVEL_6 *driver = driver_abstract->info_6;
			ret = validate_driver_6(cmd, path, driver);
			break;
		}
		default:
		{
			DEBUG(10, ("validate_driver: Error - invalid driver level = %d\n", level));
			ret = NT_STATUS_INVALID_LEVEL;
			break;
		}
	}

	return ret;
}

/****************************************************************************
 This function sucks and should be replaced. JRA.
****************************************************************************/

static void convert_level_6_to_level3(NT_PRINTER_DRIVER_INFO_LEVEL_3 *dst, NT_PRINTER_DRIVER_INFO_LEVEL_6 *src)
{
    dst->cversion  = src->version;

    fstrcpy( dst->name, src->name);
    fstrcpy( dst->environment, src->environment);
    fstrcpy( dst->driverpath, src->driverpath);
    fstrcpy( dst->datafile, src->datafile);
    fstrcpy( dst->configfile, src->configfile);
    fstrcpy( dst->helpfile, src->helpfile);
    fstrcpy( dst->monitorname, src->monitorname);
    fstrcpy( dst->defaultdatatype, src->defaultdatatype);
    dst->dependentfiles = src->dependentfiles;
}

#if 0 /* Debugging function */

static char* ffmt(unsigned char *c){
	int i;
	static char ffmt_str[17];

	for (i=0; i<16; i++) {
		if ((c[i] < ' ') || (c[i] > '~'))
			ffmt_str[i]='.';
		else
			ffmt_str[i]=c[i];
	}
    ffmt_str[16]='\0';
	return ffmt_str;
}

#endif

/****************************************************************************
****************************************************************************/
BOOL move_driver_to_download_area(NT_PRINTER_DRIVER_INFO_LEVEL driver_abstract, uint32 level, struct current_user *user, uint32 *perr)
{
	NT_PRINTER_DRIVER_INFO_LEVEL_3 *driver;
	NT_PRINTER_DRIVER_INFO_LEVEL_3 converted_driver;
	fstring architecture;
	pstring new_dir;
	pstring old_name;
	pstring new_name;
	fstring user_name;
	fstring null_pw;
	connection_struct *conn;
	pstring inbuf;
	pstring outbuf;
	struct passwd *pass;
	int ecode;
	int ver = 0;
	int i;

	*perr = 0;
	memset(inbuf, '\0', sizeof(inbuf));
	memset(outbuf, '\0', sizeof(outbuf));

	if (level==3)
		driver=driver_abstract.info_3;
	else if (level==6) {
		convert_level_6_to_level3(&converted_driver, driver_abstract.info_6);
		driver = &converted_driver;
	} else {
		DEBUG(0,("move_driver_to_download_area: Unknown info level (%u)\n", (unsigned int)level ));
		return False;
	}

	get_short_archi(architecture, driver->environment);

	become_root();
	pass = getpwuid(user->uid);
	if(pass == NULL) {
		DEBUG(0,("move_driver_to_download_area: Unable to get passwd entry for uid %u\n",
				(unsigned int)user->uid ));
		unbecome_root();
		return False;
	}
	unbecome_root();

	/* connect to the print$ share under the same account as the user connected to the rpc pipe */	
	fstrcpy(user_name, pass->pw_name );
	DEBUG(10,("move_driver_to_download_area: uid %d -> user %s\n", (int)user->uid, user_name));

	/* Null password is ok - we are already an authenticated user... */
	*null_pw = '\0';
	conn = make_connection("print$", user_name, null_pw, 0, "A:", user->vuid, &ecode);

	if (conn == NULL) {
		DEBUG(0,("move_driver_to_download_area: Unable to connect\n"));
		*perr = (uint32)ecode;
		return False;
	}

	/*
	 * Save who we are - we are temporarily becoming the connection user.
	 */

	push_sec_ctx();

	if (!become_user(conn, conn->vuid)) {
		DEBUG(0,("move_driver_to_download_area: Can't become user %s\n", user_name ));
		pop_sec_ctx();
		return False;
	}

	/*
	 * make the directories version and version\driver_name
	 * under the architecture directory.
	 */
	DEBUG(5,("Creating first directory\n"));
	slprintf(new_dir, sizeof(new_dir)-1, "%s/%d", architecture, driver->cversion);
	mkdir_internal(conn, inbuf, outbuf, new_dir);

	/* For each driver file, archi\filexxx.yyy, if there is a duplicate file
	 * listed for this driver which has already been moved, skip it (note:
	 * drivers may list the same file name several times. Then check if the
	 * file already exists in archi\cversion\, if so, check that the version
	 * info (or time stamps if version info is unavailable) is newer (or the
	 * date is later). If it is, move it to archi\cversion\filexxx.yyy.
	 * Otherwise, delete the file.
	 *
	 * If a file is not moved to archi\cversion\ because of an error, all the
	 * rest of the 'unmoved' driver files are removed from archi\. If one or
	 * more of the driver's files was already moved to archi\cversion\, it
	 * potentially leaves the driver in a partially updated state. Version
	 * trauma will most likely occur if an client attempts to use any printer
	 * bound to the driver. Perhaps a rewrite to make sure the moves can be
	 * done is appropriate... later JRR
	 */

	DEBUG(5,("Moving files now !\n"));

	if (driver->driverpath && strlen(driver->driverpath)) {
		slprintf(new_name, sizeof(new_name)-1, "%s/%s", architecture, driver->driverpath);	
		slprintf(old_name, sizeof(old_name)-1, "%s/%s", new_dir, driver->driverpath);	
		if (ver != -1 && (ver=file_version_is_newer(conn, new_name, old_name)) > 0) {
			if (rename_internals(conn, inbuf, outbuf, new_name, old_name, True) != 0) {
				DEBUG(0,("move_driver_to_download_area: Unable to rename [%s] to [%s]\n",
						new_name, old_name));
				*perr = (uint32)SVAL(outbuf,smb_err);
				unlink_internals(conn, inbuf, outbuf, 0, new_name);
				ver = -1;
			}
		}
		else
			unlink_internals(conn, inbuf, outbuf, 0, new_name);
	}

	if (driver->datafile && strlen(driver->datafile)) {
		if (!strequal(driver->datafile, driver->driverpath)) {
			slprintf(new_name, sizeof(new_name)-1, "%s/%s", architecture, driver->datafile);	
			slprintf(old_name, sizeof(old_name)-1, "%s/%s", new_dir, driver->datafile);	
			if (ver != -1 && (ver=file_version_is_newer(conn, new_name, old_name)) > 0) {
				if (rename_internals(conn, inbuf, outbuf, new_name, old_name, True) != 0) {
					DEBUG(0,("move_driver_to_download_area: Unable to rename [%s] to [%s]\n",
							new_name, old_name));
					*perr = (uint32)SVAL(outbuf,smb_err);
					unlink_internals(conn, inbuf, outbuf, 0, new_name);
					ver = -1;
				}
			}
			else
				unlink_internals(conn, inbuf, outbuf, 0, new_name);
		}
	}

	if (driver->configfile && strlen(driver->configfile)) {
		if (!strequal(driver->configfile, driver->driverpath) &&
			!strequal(driver->configfile, driver->datafile)) {
			slprintf(new_name, sizeof(new_name)-1, "%s/%s", architecture, driver->configfile);	
			slprintf(old_name, sizeof(old_name)-1, "%s/%s", new_dir, driver->configfile);	
			if (ver != -1 && (ver=file_version_is_newer(conn, new_name, old_name)) > 0) {
				if (rename_internals(conn, inbuf, outbuf, new_name, old_name, True) != 0) {
					DEBUG(0,("move_driver_to_download_area: Unable to rename [%s] to [%s]\n",
							new_name, old_name));
					*perr = (uint32)SVAL(outbuf,smb_err);
					unlink_internals(conn, inbuf, outbuf, 0, new_name);
					ver = -1;
				}
			}
			else
				unlink_internals(conn, inbuf, outbuf, 0, new_name);
		}
	}

	if (driver->helpfile && strlen(driver->helpfile)) {
		if (!strequal(driver->helpfile, driver->driverpath) &&
			!strequal(driver->helpfile, driver->datafile) &&
			!strequal(driver->helpfile, driver->configfile)) {
			slprintf(new_name, sizeof(new_name)-1, "%s/%s", architecture, driver->helpfile);	
			slprintf(old_name, sizeof(old_name)-1, "%s/%s", new_dir, driver->helpfile);	
			if (ver != -1 && (ver=file_version_is_newer(conn, new_name, old_name)) > 0) {
				if (rename_internals(conn, inbuf, outbuf, new_name, old_name, True) != 0) {
					DEBUG(0,("move_driver_to_download_area: Unable to rename [%s] to [%s]\n",
							new_name, old_name));
					*perr = (uint32)SVAL(outbuf,smb_err);
					unlink_internals(conn, inbuf, outbuf, 0, new_name);
					ver = -1;
				}
			}
			else
				unlink_internals(conn, inbuf, outbuf, 0, new_name);
		}
	}

	if (driver->dependentfiles) {
		for (i=0; *driver->dependentfiles[i]; i++) {
			if (!strequal(driver->dependentfiles[i], driver->driverpath) &&
				!strequal(driver->dependentfiles[i], driver->datafile) &&
				!strequal(driver->dependentfiles[i], driver->configfile) &&
				!strequal(driver->dependentfiles[i], driver->helpfile)) {
				int j;
				for (j=0; j < i; j++) {
					if (strequal(driver->dependentfiles[i], driver->dependentfiles[j])) {
						goto NextDriver;
					}
				}

				slprintf(new_name, sizeof(new_name)-1, "%s/%s", architecture, driver->dependentfiles[i]);	
				slprintf(old_name, sizeof(old_name)-1, "%s/%s", new_dir, driver->dependentfiles[i]);	
				if (ver != -1 && (ver=file_version_is_newer(conn, new_name, old_name)) > 0) {
					if (rename_internals(conn, inbuf, outbuf, new_name, old_name, True) != 0) {
						DEBUG(0,("move_driver_to_download_area: Unable to rename [%s] to [%s]\n",
								new_name, old_name));
						*perr = (uint32)SVAL(outbuf,smb_err);
						unlink_internals(conn, inbuf, outbuf, 0, new_name);
						ver = -1;
					}
				}
				else
					unlink_internals(conn, inbuf, outbuf, 0, new_name);
			}
		NextDriver: ;
		}
	}

	close_cnum(conn, user->vuid);
	pop_sec_ctx();

	return ver == -1 ? False : True;
}

/****************************************************************************
****************************************************************************/
static uint32 add_a_printer_driver_3(NT_PRINTER_DRIVER_INFO_LEVEL_3 *driver)
{
	int len, buflen;
	fstring architecture;
	pstring directory;
	pstring temp_name;
	pstring key;
	char *buf;
	int i, ret;
	TDB_DATA kbuf, dbuf;

	get_short_archi(architecture, driver->environment);

	/* The names are relative. We store them in the form: \print$\arch\version\driver.xxx
	 * \\server is added in the rpc server layer.
	 * It does make sense to NOT store the server's name in the printer TDB.
	 */

	slprintf(directory, sizeof(directory)-1, "\\print$\\%s\\%d\\", architecture, driver->cversion);

    /* .inf files do not always list a file for each of the four standard files. 
     * Don't prepend a path to a null filename, or client claims:
     *   "The server on which the printer resides does not have a suitable 
     *   <printer driver name> printer driver installed. Click OK if you 
     *   wish to install the driver on your local machine."
     */
	if (strlen(driver->driverpath)) {
    	fstrcpy(temp_name, driver->driverpath);
    	slprintf(driver->driverpath, sizeof(driver->driverpath)-1, "%s%s", directory, temp_name);
    }

	if (strlen(driver->datafile)) {
    	fstrcpy(temp_name, driver->datafile);
    	slprintf(driver->datafile, sizeof(driver->datafile)-1, "%s%s", directory, temp_name);
    }

	if (strlen(driver->configfile)) {
    	fstrcpy(temp_name, driver->configfile);
    	slprintf(driver->configfile, sizeof(driver->configfile)-1, "%s%s", directory, temp_name);
    }

	if (strlen(driver->helpfile)) {
    	fstrcpy(temp_name, driver->helpfile);
    	slprintf(driver->helpfile, sizeof(driver->helpfile)-1, "%s%s", directory, temp_name);
    }

	if (driver->dependentfiles) {
		for (i=0; *driver->dependentfiles[i]; i++) {
            fstrcpy(temp_name, driver->dependentfiles[i]);
            slprintf(driver->dependentfiles[i], sizeof(driver->dependentfiles[i])-1, "%s%s", directory, temp_name);
		}
	}

	slprintf(key, sizeof(key)-1, "%s%s/%d/%s", DRIVERS_PREFIX, architecture, driver->cversion, driver->name);
	dos_to_unix(key, True);                /* Convert key to unix-codepage */

	DEBUG(5,("add_a_printer_driver_3: Adding driver with key %s\n", key ));

	buf = NULL;
	len = buflen = 0;

 again:
	len = 0;
	len += tdb_pack(buf+len, buflen-len, "dffffffff",
			driver->cversion,
			driver->name,
			driver->environment,
			driver->driverpath,
			driver->datafile,
			driver->configfile,
			driver->helpfile,
			driver->monitorname,
			driver->defaultdatatype);

	if (driver->dependentfiles) {
		for (i=0; *driver->dependentfiles[i]; i++) {
			len += tdb_pack(buf+len, buflen-len, "f",
					driver->dependentfiles[i]);
		}
	}

	if (len != buflen) {
		buf = (char *)Realloc(buf, len);
		buflen = len;
		goto again;
	}


	kbuf.dptr = key;
	kbuf.dsize = strlen(key)+1;
	dbuf.dptr = buf;
	dbuf.dsize = len;
	
	ret = tdb_store(tdb, kbuf, dbuf, TDB_REPLACE);

	if (ret)
		DEBUG(0,("add_a_printer_driver_3: Adding driver with key %s failed.\n", key ));

	safe_free(buf);
	return ret;
}

/****************************************************************************
****************************************************************************/
static uint32 add_a_printer_driver_6(NT_PRINTER_DRIVER_INFO_LEVEL_6 *driver)
{
	NT_PRINTER_DRIVER_INFO_LEVEL_3 info3;

	ZERO_STRUCT(info3);
	info3.cversion = driver->version;
	fstrcpy(info3.name,driver->name);
	fstrcpy(info3.environment,driver->environment);
	fstrcpy(info3.driverpath,driver->driverpath);
	fstrcpy(info3.datafile,driver->datafile);
	fstrcpy(info3.configfile,driver->configfile);
	fstrcpy(info3.helpfile,driver->helpfile);
	fstrcpy(info3.monitorname,driver->monitorname);
	fstrcpy(info3.defaultdatatype,driver->defaultdatatype);
	info3.dependentfiles = driver->dependentfiles;

	return add_a_printer_driver_3(&info3);
}


/****************************************************************************
****************************************************************************/
static uint32 get_a_printer_driver_3_default(NT_PRINTER_DRIVER_INFO_LEVEL_3 **info_ptr, fstring in_prt, fstring in_arch)
{
	NT_PRINTER_DRIVER_INFO_LEVEL_3 info;

	ZERO_STRUCT(info);

	fstrcpy(info.name, in_prt);
	fstrcpy(info.defaultdatatype, "RAW");
	
	fstrcpy(info.driverpath, "");
	fstrcpy(info.datafile, "");
	fstrcpy(info.configfile, "");
	fstrcpy(info.helpfile, "");

	if ((info.dependentfiles=(fstring *)malloc(2*sizeof(fstring))) == NULL)
		return ERROR_NOT_ENOUGH_MEMORY;

	memset(info.dependentfiles, '\0', 2*sizeof(fstring));
	fstrcpy(info.dependentfiles[0], "");

	*info_ptr = memdup(&info, sizeof(info));
	
	return 0;	
}

/****************************************************************************
****************************************************************************/
static uint32 get_a_printer_driver_3(NT_PRINTER_DRIVER_INFO_LEVEL_3 **info_ptr, fstring in_prt, fstring in_arch, uint32 version)
{
	NT_PRINTER_DRIVER_INFO_LEVEL_3 driver;
	TDB_DATA kbuf, dbuf;
	fstring architecture;
	int len = 0;
	int i;
	pstring key;

	ZERO_STRUCT(driver);

	get_short_archi(architecture, in_arch);

	DEBUG(8,("get_a_printer_driver_3: [%s%s/%d/%s]\n", DRIVERS_PREFIX, architecture, version, in_prt));

	slprintf(key, sizeof(key)-1, "%s%s/%d/%s", DRIVERS_PREFIX, architecture, version, in_prt);

	kbuf.dptr = key;
	kbuf.dsize = strlen(key)+1;
	
	dbuf = tdb_fetch(tdb, kbuf);
#if 0
	if (!dbuf.dptr) return get_a_printer_driver_3_default(info_ptr, in_prt, in_arch);
#else
	if (!dbuf.dptr) return 5;
#endif
	len += tdb_unpack(dbuf.dptr, dbuf.dsize, "dffffffff",
			  &driver.cversion,
			  driver.name,
			  driver.environment,
			  driver.driverpath,
			  driver.datafile,
			  driver.configfile,
			  driver.helpfile,
			  driver.monitorname,
			  driver.defaultdatatype);

	i=0;
	while (len < dbuf.dsize) {
		driver.dependentfiles = (fstring *)Realloc(driver.dependentfiles,
							 sizeof(fstring)*(i+2));
		if (driver.dependentfiles == NULL)
			break;

		len += tdb_unpack(dbuf.dptr+len, dbuf.dsize-len, "f",
				  &driver.dependentfiles[i]);
		i++;
	}
	if (driver.dependentfiles != NULL)
		fstrcpy(driver.dependentfiles[i], "");

	safe_free(dbuf.dptr);

	if (len != dbuf.dsize) {
		if (driver.dependentfiles != NULL)
			safe_free(driver.dependentfiles);

		return get_a_printer_driver_3_default(info_ptr, in_prt, in_arch);
	}

	*info_ptr = (NT_PRINTER_DRIVER_INFO_LEVEL_3 *)memdup(&driver, sizeof(driver));

	return 0;
}

/****************************************************************************
****************************************************************************/
uint32 get_a_printer_driver_9x_compatible(pstring line, fstring model)
{
	NT_PRINTER_DRIVER_INFO_LEVEL_3 *info3;
	TDB_DATA kbuf;
	pstring key;
	int i;
	line[0] = '\0';

	slprintf(key, sizeof(key)-1, "%s%s/%d/%s", DRIVERS_PREFIX, "WIN40", 0, model);
	DEBUG(10,("driver key: [%s]\n", key));
	
	kbuf.dptr = key;
	kbuf.dsize = strlen(key)+1;
	if (!tdb_exists(tdb, kbuf)) return False;

	ZERO_STRUCT(info3);
	get_a_printer_driver_3(&info3, model, "Windows 4.0", 0);
	
    DEBUGADD(10,("info3->name            [%s]\n", info3->name));
    DEBUGADD(10,("info3->datafile        [%s]\n", info3->datafile));
    DEBUGADD(10,("info3->helpfile        [%s]\n", info3->helpfile));
    DEBUGADD(10,("info3->monitorname     [%s]\n", info3->monitorname));
    DEBUGADD(10,("info3->defaultdatatype [%s]\n", info3->defaultdatatype));
	for (i=0; info3->dependentfiles && *info3->dependentfiles[i]; i++) {
    DEBUGADD(10,("info3->dependentfiles  [%s]\n", info3->dependentfiles[i]));
    }
    DEBUGADD(10,("info3->environment     [%s]\n", info3->environment));
    DEBUGADD(10,("info3->driverpath      [%s]\n", info3->driverpath));
    DEBUGADD(10,("info3->configfile      [%s]\n", info3->configfile));

	/*pstrcat(line, info3->name);             pstrcat(line, ":");*/
	trim_string(info3->configfile, "\\print$\\WIN40\\0\\", 0);
	pstrcat(line, info3->configfile);
    pstrcat(line, ":");
	trim_string(info3->datafile, "\\print$\\WIN40\\0\\", 0);
	pstrcat(line, info3->datafile);
    pstrcat(line, ":");
	trim_string(info3->helpfile, "\\print$\\WIN40\\0\\", 0);
	pstrcat(line, info3->helpfile);
    pstrcat(line, ":");
	trim_string(info3->monitorname, "\\print$\\WIN40\\0\\", 0);
	pstrcat(line, info3->monitorname);
    pstrcat(line, ":");
	pstrcat(line, "RAW");                /*info3->defaultdatatype);*/
    pstrcat(line, ":");

	for (i=0; info3->dependentfiles &&
		 *info3->dependentfiles[i]; i++) {
		if (i) pstrcat(line, ",");               /* don't end in a "," */
		trim_string(info3->dependentfiles[i], "\\print$\\WIN40\\0\\", 0);
		pstrcat(line, info3->dependentfiles[i]);
	}
	
	free(info3);

	return True;	
}

/****************************************************************************
debugging function, dump at level 6 the struct in the logs
****************************************************************************/
static uint32 dump_a_printer_driver(NT_PRINTER_DRIVER_INFO_LEVEL driver, uint32 level)
{
	uint32 result;
	NT_PRINTER_DRIVER_INFO_LEVEL_3 *info3;
	int i;
	
	DEBUG(106,("Dumping printer driver at level [%d]\n", level));
	
	switch (level)
	{
		case 3:
		{
			if (driver.info_3 == NULL)
				result=5;
			else {
				info3=driver.info_3;
			
				DEBUGADD(106,("version:[%d]\n",         info3->cversion));
				DEBUGADD(106,("name:[%s]\n",            info3->name));
				DEBUGADD(106,("environment:[%s]\n",     info3->environment));
				DEBUGADD(106,("driverpath:[%s]\n",      info3->driverpath));
				DEBUGADD(106,("datafile:[%s]\n",        info3->datafile));
				DEBUGADD(106,("configfile:[%s]\n",      info3->configfile));
				DEBUGADD(106,("helpfile:[%s]\n",        info3->helpfile));
				DEBUGADD(106,("monitorname:[%s]\n",     info3->monitorname));
				DEBUGADD(106,("defaultdatatype:[%s]\n", info3->defaultdatatype));
				
				for (i=0; info3->dependentfiles &&
					  *info3->dependentfiles[i]; i++) {
					DEBUGADD(106,("dependentfile:[%s]\n",
						      info3->dependentfiles[i]));
				}
				result=0;
			}
			break;
		}
		default:
			DEBUGADD(1,("Level not implemented\n"));
			result=1;
			break;
	}
	
	return result;
}

/****************************************************************************
****************************************************************************/
static int pack_devicemode(NT_DEVICEMODE *nt_devmode, char *buf, int buflen)
{
	int len = 0;

	len += tdb_pack(buf+len, buflen-len, "p", nt_devmode);

	if (!nt_devmode) return len;

	len += tdb_pack(buf+len, buflen-len, "ffwwwwwwwwwwwwwwwwwwddddddddddddddp",
			nt_devmode->devicename,
			nt_devmode->formname,

			nt_devmode->specversion,
			nt_devmode->driverversion,
			nt_devmode->size,
			nt_devmode->driverextra,
			nt_devmode->orientation,
			nt_devmode->papersize,
			nt_devmode->paperlength,
			nt_devmode->paperwidth,
			nt_devmode->scale,
			nt_devmode->copies,
			nt_devmode->defaultsource,
			nt_devmode->printquality,
			nt_devmode->color,
			nt_devmode->duplex,
			nt_devmode->yresolution,
			nt_devmode->ttoption,
			nt_devmode->collate,
			nt_devmode->logpixels,
			
			nt_devmode->fields,
			nt_devmode->bitsperpel,
			nt_devmode->pelswidth,
			nt_devmode->pelsheight,
			nt_devmode->displayflags,
			nt_devmode->displayfrequency,
			nt_devmode->icmmethod,
			nt_devmode->icmintent,
			nt_devmode->mediatype,
			nt_devmode->dithertype,
			nt_devmode->reserved1,
			nt_devmode->reserved2,
			nt_devmode->panningwidth,
			nt_devmode->panningheight,
			nt_devmode->private);

	
	if (nt_devmode->private) {
		len += tdb_pack(buf+len, buflen-len, "B",
				nt_devmode->driverextra,
				nt_devmode->private);
	}

	DEBUG(8,("Packed devicemode [%s]\n", nt_devmode->formname));

	return len;
}

/****************************************************************************
****************************************************************************/
static int pack_specifics(NT_PRINTER_PARAM *param, char *buf, int buflen)
{
	int len = 0;

	while (param != NULL) {
		len += tdb_pack(buf+len, buflen-len, "pfdB",
				param,
				param->value,
				param->type,
				param->data_len,
				param->data);
		param=param->next;	
	}

	len += tdb_pack(buf+len, buflen-len, "p", param);

	return len;
}


/****************************************************************************
delete a printer - this just deletes the printer info file, any open
handles are not affected
****************************************************************************/
uint32 del_a_printer(char *sharename)
{
	pstring key;
	TDB_DATA kbuf;

	slprintf(key, sizeof(key)-1, "%s%s", PRINTERS_PREFIX, sharename);
	dos_to_unix(key, True);                /* Convert key to unix-codepage */

	kbuf.dptr=key;
	kbuf.dsize=strlen(key)+1;

	tdb_delete(tdb, kbuf);
	return 0;
}

/* FIXME!!!  Reorder so this forward declaration is not necessary --jerry */
static uint32 get_a_printer_2(NT_PRINTER_INFO_LEVEL_2 **, fstring);
static void free_nt_printer_info_level_2(NT_PRINTER_INFO_LEVEL_2 **);
/****************************************************************************
****************************************************************************/
static uint32 update_a_printer_2(NT_PRINTER_INFO_LEVEL_2 *info)
{
	pstring key;
	char *buf;
	int buflen, len, ret;
	TDB_DATA kbuf, dbuf;
	
	/*
	 * in addprinter: no servername and the printer is the name
	 * in setprinter: servername is \\server
	 *                and printer is \\server\\printer
	 *
	 * Samba manages only local printers.
	 * we currently don't support things like path=\\other_server\printer
	 */

	if (info->servername[0]!='\0') {
		trim_string(info->printername, info->servername, NULL);
		trim_string(info->printername, "\\", NULL);
		info->servername[0]='\0';
	}

	/*
	 * JFM: one day I'll forget.
	 * below that's info->portname because that's the SAMBA sharename
	 * and I made NT 'thinks' it's the portname
	 * the info->sharename is the thing you can name when you add a printer
	 * that's the short-name when you create shared printer for 95/98
	 * So I've made a limitation in SAMBA: you can only have 1 printer model
	 * behind a SAMBA share.
	 */

	buf = NULL;
	buflen = 0;

 again:	
	len = 0;
	len += tdb_pack(buf+len, buflen-len, "dddddddddddfffffPfffff",
			info->attributes,
			info->priority,
			info->default_priority,
			info->starttime,
			info->untiltime,
			info->status,
			info->cjobs,
			info->averageppm,
			info->changeid,
			info->c_setprinter,
			info->setuptime,
			info->servername,
			info->printername,
			info->sharename,
			info->portname,
			info->drivername,
			info->comment,
			info->location,
			info->sepfile,
			info->printprocessor,
			info->datatype,
			info->parameters);

	len += pack_devicemode(info->devmode, buf+len, buflen-len);
	
	len += pack_specifics(info->specific, buf+len, buflen-len);

	if (buflen != len) {
		buf = (char *)Realloc(buf, len);
		buflen = len;
		goto again;
	}
	

	slprintf(key, sizeof(key)-1, "%s%s", PRINTERS_PREFIX, info->sharename);
	dos_to_unix(key, True);                /* Convert key to unix-codepage */

	kbuf.dptr = key;
	kbuf.dsize = strlen(key)+1;
	dbuf.dptr = buf;
	dbuf.dsize = len;

	ret = tdb_store(tdb, kbuf, dbuf, TDB_REPLACE);

	if (ret == -1)
		DEBUG(8, ("error updating printer to tdb on disk\n"));

	safe_free(buf);

	DEBUG(8,("packed printer [%s] with driver [%s] portname=[%s] len=%d\n",
		 info->sharename, info->drivername, info->portname, len));

	return ret;
}

/****************************************************************************
****************************************************************************/
void add_a_specific_param(NT_PRINTER_INFO_LEVEL_2 *info_2, NT_PRINTER_PARAM **param)
{
	NT_PRINTER_PARAM *current;
	
	DEBUG(108,("add_a_specific_param\n"));	

	(*param)->next=NULL;
	
	if (info_2->specific == NULL)
	{
		info_2->specific=*param;
	}
	else
	{
		current=info_2->specific;		
		while (current->next != NULL) {
			current=current->next;
		}		
		current->next=*param;
	}

	*param = NULL;
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
	    (strlen(current->value)==strlen(param->value)) ) {
		DEBUG(109,("deleting first value\n"));
		info_2->specific=current->next;
		safe_free(current->data);
		safe_free(current);
		DEBUG(109,("deleted first value\n"));
		return (True);
	}

	current=previous->next;
		
	while ( current!=NULL ) {
		if (!strcmp(current->value, param->value) &&
		    strlen(current->value)==strlen(param->value) ) {
			DEBUG(109,("deleting current value\n"));
			previous->next=current->next;
			safe_free(current->data);
			safe_free(current);
			DEBUG(109,("deleted current value\n"));
			return(True);
		}
		
		previous=previous->next;
		current=current->next;
	}
	return (False);
}

/****************************************************************************
 Clean up and deallocate a (maybe partially) allocated NT_PRINTER_PARAM.
****************************************************************************/
void free_nt_printer_param(NT_PRINTER_PARAM **param_ptr)
{
	NT_PRINTER_PARAM *param = *param_ptr;

	if(param == NULL)
		return;

	DEBUG(106,("free_nt_printer_param: deleting param [%s]\n", param->value));

	if(param->data)
		safe_free(param->data);

	safe_free(param);
	*param_ptr = NULL;
}

/****************************************************************************
 Malloc and return an NT devicemode.
****************************************************************************/

NT_DEVICEMODE *construct_nt_devicemode(const fstring default_devicename)
{
/*
 * should I init this ones ???
	nt_devmode->devicename
*/

	char adevice[32];
	NT_DEVICEMODE *nt_devmode = (NT_DEVICEMODE *)malloc(sizeof(NT_DEVICEMODE));

	if (nt_devmode == NULL) {
		DEBUG(0,("construct_nt_devicemode: malloc fail.\n"));
		return NULL;
	}

	ZERO_STRUCTP(nt_devmode);

	safe_strcpy(adevice, default_devicename, sizeof(adevice));
	fstrcpy(nt_devmode->devicename, adevice);	
	
	fstrcpy(nt_devmode->formname, "Letter");

	nt_devmode->specversion      = 0x0401;
	nt_devmode->driverversion    = 0x0400;
	nt_devmode->size             = 0x00DC;
	nt_devmode->driverextra      = 0x0000;
	nt_devmode->fields           = FORMNAME | TTOPTION | PRINTQUALITY |
				       DEFAULTSOURCE | COPIES | SCALE |
				       PAPERSIZE | ORIENTATION;
	nt_devmode->orientation      = 1;
	nt_devmode->papersize        = PAPER_LETTER;
	nt_devmode->paperlength      = 0;
	nt_devmode->paperwidth       = 0;
	nt_devmode->scale            = 0x64;
	nt_devmode->copies           = 1;
	nt_devmode->defaultsource    = BIN_FORMSOURCE;
	nt_devmode->printquality     = RES_HIGH;           /* 0x0258 */
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
	
	nt_devmode->private = NULL;
	return nt_devmode;
}

/****************************************************************************
 Deepcopy an NT devicemode.
****************************************************************************/

NT_DEVICEMODE *dup_nt_devicemode(NT_DEVICEMODE *nt_devicemode)
{
	NT_DEVICEMODE *new_nt_devicemode = NULL;

	if ((new_nt_devicemode = (NT_DEVICEMODE *)memdup(nt_devicemode, sizeof(NT_DEVICEMODE))) == NULL) {
		DEBUG(0,("dup_nt_devicemode: malloc fail.\n"));
		return NULL;
	}

	new_nt_devicemode->private = NULL;
	if (nt_devicemode->private != NULL) {
		if ((new_nt_devicemode->private = memdup(nt_devicemode->private, nt_devicemode->driverextra)) == NULL) {
			safe_free(new_nt_devicemode);
			DEBUG(0,("dup_nt_devicemode: malloc fail.\n"));
			return NULL;
        }
	}

	return new_nt_devicemode;
}

/****************************************************************************
 Clean up and deallocate a (maybe partially) allocated NT_DEVICEMODE.
****************************************************************************/

void free_nt_devicemode(NT_DEVICEMODE **devmode_ptr)
{
	NT_DEVICEMODE *nt_devmode = *devmode_ptr;

	if(nt_devmode == NULL)
		return;

	DEBUG(106,("free_nt_devicemode: deleting DEVMODE\n"));

	if(nt_devmode->private)
		safe_free(nt_devmode->private);

	safe_free(nt_devmode);
	*devmode_ptr = NULL;
}

/****************************************************************************
 Clean up and deallocate a (maybe partially) allocated NT_PRINTER_INFO_LEVEL_2.
****************************************************************************/
static void free_nt_printer_info_level_2(NT_PRINTER_INFO_LEVEL_2 **info_ptr)
{
	NT_PRINTER_INFO_LEVEL_2 *info = *info_ptr;
	NT_PRINTER_PARAM *param_ptr;

	if(info == NULL)
		return;

	DEBUG(106,("free_nt_printer_info_level_2: deleting info\n"));

	free_nt_devicemode(&info->devmode);
	free_sec_desc_buf(&info->secdesc_buf);

	for(param_ptr = info->specific; param_ptr; ) {
		NT_PRINTER_PARAM *tofree = param_ptr;

		param_ptr = param_ptr->next;
		free_nt_printer_param(&tofree);
	}

	safe_free(*info_ptr);
	*info_ptr = NULL;
}


/****************************************************************************
****************************************************************************/
static int unpack_devicemode(NT_DEVICEMODE **nt_devmode, char *buf, int buflen)
{
	int len = 0;
	int extra_len = 0;
	NT_DEVICEMODE devmode;

	ZERO_STRUCT(devmode);

	len += tdb_unpack(buf+len, buflen-len, "p", nt_devmode);

	if (!*nt_devmode) return len;

	len += tdb_unpack(buf+len, buflen-len, "ffwwwwwwwwwwwwwwwwwwddddddddddddddp",
			  devmode.devicename,
			  devmode.formname,

			  &devmode.specversion,
			  &devmode.driverversion,
			  &devmode.size,
			  &devmode.driverextra,
			  &devmode.orientation,
			  &devmode.papersize,
			  &devmode.paperlength,
			  &devmode.paperwidth,
			  &devmode.scale,
			  &devmode.copies,
			  &devmode.defaultsource,
			  &devmode.printquality,
			  &devmode.color,
			  &devmode.duplex,
			  &devmode.yresolution,
			  &devmode.ttoption,
			  &devmode.collate,
			  &devmode.logpixels,
			
			  &devmode.fields,
			  &devmode.bitsperpel,
			  &devmode.pelswidth,
			  &devmode.pelsheight,
			  &devmode.displayflags,
			  &devmode.displayfrequency,
			  &devmode.icmmethod,
			  &devmode.icmintent,
			  &devmode.mediatype,
			  &devmode.dithertype,
			  &devmode.reserved1,
			  &devmode.reserved2,
			  &devmode.panningwidth,
			  &devmode.panningheight,
			  &devmode.private);

	DEBUG(    8,("Unpacked devicemode:\n"));
	DEBUGADD( 8,("devicename = %s\n", devmode.devicename));
	DEBUGADD(11,("formname = %s\n", devmode.formname));
	DEBUGADD(11,("specversion = %d\n", devmode.specversion));
	DEBUGADD(11,("driverversion = %d\n", devmode.driverversion));
	DEBUGADD(11,("size = %d\n", devmode.size));
	DEBUGADD(11,("driverextra = %d\n", devmode.driverextra));
	DEBUGADD(11,("orientation = %d\n", devmode.orientation));
	DEBUGADD(11,("papersize = %d\n", devmode.papersize));
	DEBUGADD(11,("paperlength = %d\n", devmode.paperlength));
	DEBUGADD(11,("paperwidth = %d\n", devmode.paperwidth));
	DEBUGADD(11,("scale = %d\n", devmode.scale));
	DEBUGADD(11,("copies = %d\n", devmode.copies));
	DEBUGADD(11,("defaultsource = %d\n", devmode.defaultsource));
	DEBUGADD(11,("printquality = %d\n", devmode.printquality));
	DEBUGADD(11,("color = %d\n", devmode.color));
	DEBUGADD(11,("duplex = %d\n", devmode.duplex));
	DEBUGADD(11,("yresolution = %d\n", devmode.yresolution));
	DEBUGADD(11,("ttoption = %d\n", devmode.ttoption));
	DEBUGADD(11,("collate = %d\n", devmode.collate));
	DEBUGADD(11,("logpixels = %d\n", devmode.logpixels));
	DEBUGADD(11,("fields = %d\n", devmode.fields));
	DEBUGADD(11,("bitsperpel = %d\n", devmode.bitsperpel));
	DEBUGADD(11,("pelswidth = %d\n", devmode.pelswidth));
	DEBUGADD(11,("pelsheight = %d\n", devmode.pelsheight));
	DEBUGADD(11,("displayflags = %d\n", devmode.displayflags));
	DEBUGADD(11,("displayfrequency = %d\n", devmode.displayfrequency));
	DEBUGADD(11,("icmmethod = %d\n", devmode.icmmethod));
	DEBUGADD(11,("icmintent = %d\n", devmode.icmintent));
	DEBUGADD(11,("mediatype = %d\n", devmode.mediatype));
	DEBUGADD(11,("dithertype = %d\n", devmode.dithertype));
	DEBUGADD(11,("reserved1 = %d\n", devmode.reserved1));
	DEBUGADD(11,("reserved2 = %d\n", devmode.reserved2));
	DEBUGADD(11,("panningwidth = %d\n", devmode.panningwidth));
	DEBUGADD(11,("panningheight = %d\n", devmode.panningheight));
	
	if (devmode.private) {
		/* the len in tdb_unpack is an int value and
		 * devmode.driverextra is only a short
		 */
		len += tdb_unpack(buf+len, buflen-len, "B", &extra_len, &devmode.private);
		devmode.driverextra=(uint16)extra_len;
		
		/* check to catch an invalid TDB entry so we don't segfault */
		if (devmode.driverextra == 0) {
			devmode.private = NULL;
		}
	}

	*nt_devmode = (NT_DEVICEMODE *)memdup(&devmode, sizeof(devmode));

	if (devmode.private) {
		DEBUG(8,("with a private section of %d bytes\n", devmode.driverextra));
		dump_data(11, devmode.private, devmode.driverextra);
	}

	return len;
}

/****************************************************************************
****************************************************************************/
static int unpack_specifics(NT_PRINTER_PARAM **list, char *buf, int buflen)
{
	int len = 0;
	NT_PRINTER_PARAM param, *p;

	*list = NULL;

	while (1) {
		len += tdb_unpack(buf+len, buflen-len, "p", &p);
		if (!p) break;

		len += tdb_unpack(buf+len, buflen-len, "fdB",
				  param.value,
				  &param.type,
				  &param.data_len,
				  &param.data);
		param.next = *list;
		*list = memdup(&param, sizeof(param));

		DEBUG(10,("specific: [%s], type: %d len: %d\n", param.value, param.type, param.data_len));
		dump_data(11, param.data, param.data_len);
	}

	return len;
}


/****************************************************************************
get a default printer info 2 struct
****************************************************************************/
static uint32 get_a_printer_2_default(NT_PRINTER_INFO_LEVEL_2 **info_ptr, fstring sharename)
{
	extern pstring global_myname;
	int snum;
	NT_PRINTER_INFO_LEVEL_2 info;

	ZERO_STRUCT(info);

	snum = lp_servicenumber(sharename);

	slprintf(info.servername, sizeof(info.servername)-1, "\\\\%s", global_myname);
	slprintf(info.printername, sizeof(info.printername)-1, "\\\\%s\\%s", 
		 global_myname, sharename);
	fstrcpy(info.sharename, sharename);
	fstrcpy(info.portname, SAMBA_PRINTER_PORT_NAME);
	fstrcpy(info.drivername, lp_printerdriver(snum));

#if 0	/* JERRY */
	if (!*info.drivername)
		fstrcpy(info.drivername, "NO DRIVER AVAILABLE FOR THIS PRINTER");
#else
	/* by setting the driver name to an empty string, a local NT admin
	   can now run the **local** APW to install a local printer driver
 	   for a Samba shared printer in 2.2.  Without this, drivers **must** be 
	   installed on the Samba server for NT clients --jerry */
	if (!*info.drivername)
		fstrcpy(info.drivername, "");
#endif


	DEBUG(10,("get_a_printer_2_default: driver name set to [%s]\n", info.drivername));

	pstrcpy(info.comment, "");
	fstrcpy(info.printprocessor, "winprint");
	fstrcpy(info.datatype, "RAW");
	
	/* See note in check_printer_ok() for reasons for these attributes. JRR */
	info.attributes = PRINTER_ATTRIBUTE_SHARED   \
					| PRINTER_ATTRIBUTE_NETWORK;            /* attributes */

	info.starttime = 0; /* Minutes since 12:00am GMT */
	info.untiltime = 0; /* Minutes since 12:00am GMT */
	info.priority = 1;
	info.default_priority = 1;
	info.setuptime = (uint32)time(NULL);

#if 1 /* JRA - NO NOT CHANGE ! */
	info.devmode = NULL;
#else
	/*
	 * We should not return a default devicemode, as this causes
	 * Win2K to not send the correct one on PCL drivers. It needs to
	 * see a null devicemode so it can then overwrite the devicemode
	 * on OpenPrinterEx. Yes this *is* insane :-). JRA.
	 */
	if ((info.devmode = construct_nt_devicemode(info.printername)) == NULL)
		goto fail;
#endif

	if (!nt_printing_getsec(sharename, &info.secdesc_buf))
		goto fail;

	*info_ptr = (NT_PRINTER_INFO_LEVEL_2 *)memdup(&info, sizeof(info));
	if (! *info_ptr) {
		DEBUG(0,("get_a_printer_2_default: malloc fail.\n"));
		goto fail;
	}

	return (0);	

  fail:

	if (info.devmode)
		free_nt_devicemode(&info.devmode);
	if (info.secdesc_buf)
		free_sec_desc_buf(&info.secdesc_buf);
	return 2;
}

/****************************************************************************
****************************************************************************/
static uint32 get_a_printer_2(NT_PRINTER_INFO_LEVEL_2 **info_ptr, fstring sharename)
{
	pstring key;
	NT_PRINTER_INFO_LEVEL_2 info;
	int 		len = 0;
	TDB_DATA kbuf, dbuf;
	fstring printername;
		
	ZERO_STRUCT(info);

	slprintf(key, sizeof(key)-1, "%s%s", PRINTERS_PREFIX, sharename);
	dos_to_unix(key, True);                /* Convert key to unix-codepage */

	kbuf.dptr = key;
	kbuf.dsize = strlen(key)+1;

	dbuf = tdb_fetch(tdb, kbuf);
	if (!dbuf.dptr)
		return get_a_printer_2_default(info_ptr, sharename);

	len += tdb_unpack(dbuf.dptr+len, dbuf.dsize-len, "dddddddddddfffffPfffff",
			&info.attributes,
			&info.priority,
			&info.default_priority,
			&info.starttime,
			&info.untiltime,
			&info.status,
			&info.cjobs,
			&info.averageppm,
			&info.changeid,
			&info.c_setprinter,
			&info.setuptime,
			info.servername,
			info.printername,
			info.sharename,
			info.portname,
			info.drivername,
			info.comment,
			info.location,
			info.sepfile,
			info.printprocessor,
			info.datatype,
			info.parameters);

	/* See note in check_printer_ok() for reasons for these attributes. JRR */
	info.attributes |= PRINTER_ATTRIBUTE_SHARED | PRINTER_ATTRIBUTE_NETWORK;

	/* Restore the stripped strings. */
	slprintf(info.servername, sizeof(info.servername)-1, "\\\\%s", global_myname);
	slprintf(printername, sizeof(printername)-1, "\\\\%s\\%s", global_myname,
			info.printername);
	fstrcpy(info.printername, printername);

#if 0
	/*
	 * We don't want to generate a default device mode (which is why this code is commented out).  
	 * Better to have the printer initiailized by the client.	  --jerry
	 */
	if (!(devmode_length=unpack_devicemode(&info.devmode,dbuf.dptr+len, dbuf.dsize-len)))
		info.devmode = construct_nt_devicemode(printername);
	else
		len += devmode_length;
#else
	len += unpack_devicemode(&info.devmode,dbuf.dptr+len, dbuf.dsize-len);
#endif
		
	len += unpack_specifics(&info.specific,dbuf.dptr+len, dbuf.dsize-len);

	nt_printing_getsec(sharename, &info.secdesc_buf);

	safe_free(dbuf.dptr);
	*info_ptr=memdup(&info, sizeof(info));

	DEBUG(9,("Unpacked printer [%s] name [%s] running driver [%s]\n",
		 sharename, info.printername, info.drivername));

	
	return 0;	
}

/****************************************************************************
debugging function, dump at level 6 the struct in the logs
****************************************************************************/
static uint32 dump_a_printer(NT_PRINTER_INFO_LEVEL printer, uint32 level)
{
	uint32 result;
	NT_PRINTER_INFO_LEVEL_2	*info2;
	
	DEBUG(106,("Dumping printer at level [%d]\n", level));
	
	switch (level)
	{
		case 2:
		{
			if (printer.info_2 == NULL)
				result=5;
			else
			{
				info2=printer.info_2;
			
				DEBUGADD(106,("attributes:[%d]\n", info2->attributes));
				DEBUGADD(106,("priority:[%d]\n", info2->priority));
				DEBUGADD(106,("default_priority:[%d]\n", info2->default_priority));
				DEBUGADD(106,("starttime:[%d]\n", info2->starttime));
				DEBUGADD(106,("untiltime:[%d]\n", info2->untiltime));
				DEBUGADD(106,("status:[%d]\n", info2->status));
				DEBUGADD(106,("cjobs:[%d]\n", info2->cjobs));
				DEBUGADD(106,("averageppm:[%d]\n", info2->averageppm));
				DEBUGADD(106,("changeid:[%d]\n", info2->changeid));
				DEBUGADD(106,("c_setprinter:[%d]\n", info2->c_setprinter));
				DEBUGADD(106,("setuptime:[%d]\n", info2->setuptime));

				DEBUGADD(106,("servername:[%s]\n", info2->servername));
				DEBUGADD(106,("printername:[%s]\n", info2->printername));
				DEBUGADD(106,("sharename:[%s]\n", info2->sharename));
				DEBUGADD(106,("portname:[%s]\n", info2->portname));
				DEBUGADD(106,("drivername:[%s]\n", info2->drivername));
				DEBUGADD(106,("comment:[%s]\n", info2->comment));
				DEBUGADD(106,("location:[%s]\n", info2->location));
				DEBUGADD(106,("sepfile:[%s]\n", info2->sepfile));
				DEBUGADD(106,("printprocessor:[%s]\n", info2->printprocessor));
				DEBUGADD(106,("datatype:[%s]\n", info2->datatype));
				DEBUGADD(106,("parameters:[%s]\n", info2->parameters));
				result=0;
			}
			break;
		}
		default:
			DEBUGADD(1,("Level not implemented\n"));
			result=1;
			break;
	}
	
	return result;
}

/****************************************************************************
 Get the parameters we can substitute in an NT print job.
****************************************************************************/

void get_printer_subst_params(int snum, fstring *printername, fstring *sharename, fstring *portname)
{
	NT_PRINTER_INFO_LEVEL *printer = NULL;

	**printername = **sharename = **portname = '\0';

	if (get_a_printer(&printer, 2, lp_servicename(snum))!=0)
		return;

	fstrcpy(*printername, printer->info_2->printername);
	fstrcpy(*sharename, printer->info_2->sharename);
	fstrcpy(*portname, printer->info_2->portname);

	free_a_printer(&printer, 2);
}

/****************************************************************************
 Update the changeid time.
 This is SO NASTY as some drivers need this to change, others need it
 static. This value will change every second, and I must hope that this
 is enough..... DON'T CHANGE THIS CODE WITHOUT A TEST MATRIX THE SIZE OF
 UTAH ! JRA.
****************************************************************************/

static uint32 rev_changeid(void)
{
	struct timeval tv;

	get_process_uptime(&tv);

    /* Return changeid as msec since spooler restart */
	return tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

/*
 * The function below are the high level ones.
 * only those ones must be called from the spoolss code.
 * JFM.
 */

/****************************************************************************
 Modify a printer. This is called from SETPRINTERDATA/DELETEPRINTERDATA.
****************************************************************************/

uint32 mod_a_printer(NT_PRINTER_INFO_LEVEL printer, uint32 level)
{
    uint32 result;
	
	dump_a_printer(printer, level);	
	
	switch (level)
	{
		case 2:
		{
			/*
			 * Update the changestamp.  Emperical tests show that the
			 * ChangeID is always updated,but c_setprinter is only 
			 * incremented on a SetPrinter() call.
			 */

			/* ChangeID **must** be increasing over the lifetime
			   of client's spoolss service in order for the
			   client's cache to show updates */

			printer.info_2->changeid = rev_changeid();

			/*
			 * Because one day someone will ask:
			 * NT->NT	An admin connection to a remote
			 * 		printer show changes imeediately in
			 * 		the properities dialog
			 * 	
			 * 		A non-admin connection will only show the
			 * 		changes after viewing the properites page
			 * 		2 times.  Seems to be related to a
			 * 		race condition in the client between the spooler
			 * 		updating the local cache and the Explorer.exe GUI
			 *		actually displaying the properties.
			 *
			 *		This is fixed in Win2k.  admin/non-admin
			 * 		connections both display changes immediately.
			 *
			 * 14/12/01	--jerry
			 */

			result=update_a_printer_2(printer.info_2);
			break;
		}
		default:
			result=1;
			break;
	}
	
	return result;
}

/****************************************************************************
 Add a printer. This is called from ADDPRINTER(EX) and also SETPRINTER.
 We split this out from mod_a_printer as it updates the id's and timestamps.
****************************************************************************/

uint32 add_a_printer(NT_PRINTER_INFO_LEVEL printer, uint32 level)
{
	uint32 result;
	
	dump_a_printer(printer, level);	
	
	switch (level)
	{
		case 2:
		{
			/*
			 * Update the changestamp.  See comments in mod_a_printer()
			 * --jerry
			 */

			printer.info_2->changeid = rev_changeid();

			result=update_a_printer_2(printer.info_2);
			break;
		}
		default:
			result=1;
			break;
	}
	
	return result;
}

/****************************************************************************
 Initialize printer devmode & data with previously saved driver init values.
****************************************************************************/
static uint32 set_driver_init_2(NT_PRINTER_INFO_LEVEL_2 *info_ptr)
{
	int                     len = 0;
	pstring                 key;
	TDB_DATA                kbuf, dbuf;
	NT_PRINTER_PARAM        *current;
	NT_PRINTER_INFO_LEVEL_2 info;

	/* 
	 * Delete any printer data 'specifics' already set. When called for driver
	 * replace, there will generally be some, but during an add printer, there 
	 * should not be any (if there are delete them).
	 */
	while ( (current=info_ptr->specific) != NULL ) {
		info_ptr->specific=current->next;
		safe_free(current->data);
		safe_free(current);
	}

	ZERO_STRUCT(info);

	slprintf(key, sizeof(key)-1, "%s%s", DRIVER_INIT_PREFIX, info_ptr->drivername);
	dos_to_unix(key, True);                /* Convert key to unix-codepage */

	kbuf.dptr = key;
	kbuf.dsize = strlen(key)+1;

	dbuf = tdb_fetch(tdb, kbuf);
	if (!dbuf.dptr) {
		/*
		 * When changing to a driver that has no init info in the tdb, remove
		 * the previous drivers init info and leave the new on blank.
		 */
		free_nt_devicemode(&info_ptr->devmode);
		return False;
	}

	/*
	 * Get the saved DEVMODE..
	 */
	len += unpack_devicemode(&info.devmode,dbuf.dptr+len, dbuf.dsize-len);

	/*
	 * The saved DEVMODE contains the devicename from the printer used during
	 * the initialization save. Change it to reflect the new printer.
	 */
	ZERO_STRUCT(info.devmode->devicename);
	fstrcpy(info.devmode->devicename, info_ptr->printername);

	/* 
	 * 	Bind the saved DEVMODE to the new the printer.
	 */
	free_nt_devicemode(&info_ptr->devmode);
	info_ptr->devmode = info.devmode;

	DEBUG(10,("set_driver_init_2: Set printer [%s] init DEVMODE for driver [%s]\n",
			info_ptr->printername, info_ptr->drivername));

	/* 
	 * Add the printer data 'specifics' to the new printer
	 */
	len += unpack_specifics(&info_ptr->specific,dbuf.dptr+len, dbuf.dsize-len);

	safe_free(dbuf.dptr);

	return True;	
}

/****************************************************************************
 Initialize printer devmode & data with previously saved driver init values.
 When a printer is created using AddPrinter, the drivername bound to the
 printer is used to lookup previously saved driver initialization info, which
 is bound to the new printer.
****************************************************************************/

uint32 set_driver_init(NT_PRINTER_INFO_LEVEL *printer, uint32 level)
{
	uint32 result;
	
	switch (level)
	{
		case 2:
		{
			result=set_driver_init_2(printer->info_2);
			break;
		}
		default:
			result=1;
			break;
	}
	
	return result;
}

/****************************************************************************
 Pack up the DEVMODE and specifics for a printer into a 'driver init' entry 
 in the tdb. Note: this is different from the driver entry and the printer
 entry. There should be a single driver init entry for each driver regardless
 of whether it was installed from NT or 2K. Technically, they should be
 different, but they work out to the same struct.
****************************************************************************/
static uint32 update_driver_init_2(NT_PRINTER_INFO_LEVEL_2 *info)
{
	pstring key;
	char *buf;
	int buflen, len, ret;
	TDB_DATA kbuf, dbuf;

	buf = NULL;
	buflen = 0;

 again:	
	len = 0;
	len += pack_devicemode(info->devmode, buf+len, buflen-len);

	len += pack_specifics(info->specific, buf+len, buflen-len);

	if (buflen != len) {
		buf = (char *)Realloc(buf, len);
		buflen = len;
		goto again;
	}

	slprintf(key, sizeof(key)-1, "%s%s", DRIVER_INIT_PREFIX, info->drivername);
	dos_to_unix(key, True);                /* Convert key to unix-codepage */

	kbuf.dptr = key;
	kbuf.dsize = strlen(key)+1;
	dbuf.dptr = buf;
	dbuf.dsize = len;

	ret = tdb_store(tdb, kbuf, dbuf, TDB_REPLACE);

	if (ret == -1)
		DEBUG(8, ("update_driver_init_2: error updating printer init to tdb on disk\n"));

	safe_free(buf);

	DEBUG(10,("update_driver_init_2: Saved printer [%s] init DEVMODE & specifics for driver [%s]\n",
		 info->sharename, info->drivername));

	return ret;
}

/****************************************************************************
 Update (i.e. save) the driver init info (DEVMODE and specifics) for a printer
****************************************************************************/

uint32 update_driver_init(NT_PRINTER_INFO_LEVEL printer, uint32 level)
{
	uint32 result;
	
	dump_a_printer(printer, level);	
	
	switch (level)
	{
		case 2:
		{
			result=update_driver_init_2(printer.info_2);
			break;
		}
		default:
			result=1;
			break;
	}
	
	return result;
}

/****************************************************************************
 Convert the printer data value, a REG_BINARY array, into an initialization 
 DEVMODE. Note: the array must be parsed as if it was a DEVMODE in an rpc...
 got to keep the endians happy :).
****************************************************************************/

static BOOL convert_driver_init(NT_PRINTER_PARAM *param, TALLOC_CTX *ctx, NT_DEVICEMODE *nt_devmode)
{
	BOOL       result = False;
	prs_struct ps;
	DEVICEMODE devmode;

	ZERO_STRUCT(devmode);

	prs_init(&ps, 0, 0, ctx, UNMARSHALL);
	ps.data_p      = param->data;
	ps.buffer_size = param->data_len;

	if (spoolss_io_devmode("phantom DEVMODE", &ps, 0, &devmode))
		result = convert_devicemode("", &devmode, &nt_devmode);
	else
		DEBUG(10,("convert_driver_init: error parsing DEVMODE\n"));


	safe_free(devmode.private);
	return result;
}

/****************************************************************************
 Set the DRIVER_INIT info in the tdb. Requires Win32 client code that:

 1. Use the driver's config DLL to this UNC printername and:
    a. Call DrvPrintEvent with PRINTER_EVENT_INITIALIZE
    b. Call DrvConvertDevMode with CDM_DRIVER_DEFAULT to get default DEVMODE
 2. Call SetPrinterData with the 'magic' key and the DEVMODE as data.

 The last step triggers saving the "driver initialization" information for
 this printer into the tdb. Later, new printers that use this driver will
 have this initialization information bound to them. This simulates the
 driver initialization, as if it had run on the Samba server (as it would
 have done on NT).

 The Win32 client side code requirement sucks! But until we can run arbitrary
 Win32 printer driver code on any Unix that Samba runs on, we are stuck with it.
 
 It would have been easier to use SetPrinter because all the UNMARSHALLING of
 the DEVMODE is done there, but 2K/XP clients do not set the DEVMODE... think
 about it and you will realize why.  JRR 010720
****************************************************************************/

static uint32 save_driver_init_2(NT_PRINTER_INFO_LEVEL *printer, NT_PRINTER_PARAM *param)
{
	uint32        status       = ERROR_SUCCESS;
	TALLOC_CTX    *ctx         = NULL;
	NT_DEVICEMODE *nt_devmode  = NULL;
	NT_DEVICEMODE *tmp_devmode = printer->info_2->devmode;
	
	/*
	 * Set devmode on printer info, so entire printer initialization can be 
	 * saved to tdb.
	 */
	if ((ctx = talloc_init()) == NULL)
		return ERROR_NOT_ENOUGH_MEMORY;

	if ((nt_devmode = (NT_DEVICEMODE*)malloc(sizeof(NT_DEVICEMODE))) == NULL) {
		status = ERROR_NOT_ENOUGH_MEMORY;
		goto done;
	}
	
	ZERO_STRUCTP(nt_devmode);

	/*
	 * The DEVMODE is held in the 'data' component of the param in raw binary.
	 * Convert it to to a devmode structure
	 */
	if (!convert_driver_init(param, ctx, nt_devmode)) {
		DEBUG(10,("save_driver_init_2: error converting DEVMODE\n"));
		status = ERROR_INVALID_PARAMETER;
		goto done;
	}

	/*
	 * Pack up and add (or update) the DEVMODE and any current printer data to
	 * a 'driver init' element in the tdb
	 * 
	 */
	printer->info_2->devmode = nt_devmode;
	if (update_driver_init(*printer, 2)!=0) {
		DEBUG(10,("save_driver_init_2: error updating DEVMODE\n"));
		status = ERROR_NOT_ENOUGH_MEMORY;
		goto done;
	}
	
	/*
	 * If driver initialization info was successfully saved, set the current 
	 * printer to match it. This allows initialization of the current printer 
	 * as well as the driver.
	 */
	if (mod_a_printer(*printer, 2)!=0) {
		DEBUG(10,("save_driver_init_2: error setting DEVMODE on printer [%s]\n",
				  printer->info_2->printername));
		status = ERROR_INVALID_PARAMETER;
	}

  done:
	talloc_destroy(ctx);
	if (nt_devmode)
		safe_free(nt_devmode->private);
	safe_free(nt_devmode);
	printer->info_2->devmode = tmp_devmode;

	return status;
}

/****************************************************************************
 Update the driver init info (DEVMODE and specifics) for a printer
****************************************************************************/

uint32 save_driver_init(NT_PRINTER_INFO_LEVEL *printer, uint32 level, NT_PRINTER_PARAM *param)
{
	uint32 status = ERROR_SUCCESS;
	
	switch (level)
	{
		case 2:
		{
			status=save_driver_init_2(printer, param);
			break;
		}
		default:
			status=ERROR_INVALID_LEVEL;
			break;
	}
	
	return status;
}

/****************************************************************************
 Get a NT_PRINTER_INFO_LEVEL struct. It returns malloced memory.
****************************************************************************/

uint32 get_a_printer(NT_PRINTER_INFO_LEVEL **pp_printer, uint32 level, fstring sharename)
{
	uint32 result;
	NT_PRINTER_INFO_LEVEL *printer = NULL;
	
	*pp_printer = NULL;

	DEBUG(10,("get_a_printer: [%s] level %u\n", sharename, (unsigned int)level));

	switch (level)
	{
		case 2:
		{
			if ((printer = (NT_PRINTER_INFO_LEVEL *)malloc(sizeof(NT_PRINTER_INFO_LEVEL))) == NULL) {
				DEBUG(0,("get_a_printer: malloc fail.\n"));
				return 1;
			}
			ZERO_STRUCTP(printer);
			result=get_a_printer_2(&printer->info_2, sharename);
			if (result == 0) {
				dump_a_printer(*printer, level);
				*pp_printer = printer;
			} else {
				safe_free(printer);
			}
			break;
		}
		default:
			result=1;
			break;
	}
	
	DEBUG(10,("get_a_printer: [%s] level %u returning %u\n", sharename, (unsigned int)level, (unsigned int)result));

	return result;
}

/****************************************************************************
 Deletes a NT_PRINTER_INFO_LEVEL struct.
****************************************************************************/

uint32 free_a_printer(NT_PRINTER_INFO_LEVEL **pp_printer, uint32 level)
{
	uint32 result;
	NT_PRINTER_INFO_LEVEL *printer = *pp_printer;

	DEBUG(104,("freeing a printer at level [%d]\n", level));

	if (printer == NULL)
		return 0;
	
	switch (level)
	{
		case 2:
		{
			if (printer->info_2 != NULL)
			{
				free_nt_printer_info_level_2(&printer->info_2);
				result=0;
			}
			else
			{
				result=4;
			}
			break;
		}
		default:
			result=1;
			break;
	}

	safe_free(printer);
	*pp_printer = NULL;
	return result;
}

/****************************************************************************
****************************************************************************/
uint32 add_a_printer_driver(NT_PRINTER_DRIVER_INFO_LEVEL driver, uint32 level)
{
	uint32 result = NT_STATUS_NO_PROBLEMO;
	DEBUG(104,("adding a printer at level [%d]\n", level));
	dump_a_printer_driver(driver, level);
	
	switch (level)
	{
		case 3:
		{
			if(add_a_printer_driver_3(driver.info_3) != 0)
				result = ERROR_ACCESS_DENIED;
			break;
		}

		case 6:
		{
			if (add_a_printer_driver_6(driver.info_6) != 0)
				result = ERROR_ACCESS_DENIED;
			break;
		}

		default:
			result = NT_STATUS_INVALID_INFO_CLASS;
			break;
	}
	
	return result;
}
/****************************************************************************
****************************************************************************/
uint32 get_a_printer_driver(NT_PRINTER_DRIVER_INFO_LEVEL *driver, uint32 level,
                            fstring printername, fstring architecture, uint32 version)
{
	uint32 result;
	
	switch (level)
	{
		case 3:
		{
			result=get_a_printer_driver_3(&driver->info_3, printername, architecture, version);
			break;
		}
		default:
			result=1;
			break;
	}
	
	if (result == 0)
		dump_a_printer_driver(*driver, level);
	return result;
}

/****************************************************************************
****************************************************************************/
uint32 free_a_printer_driver(NT_PRINTER_DRIVER_INFO_LEVEL driver, uint32 level)
{
	uint32 result;
	
	switch (level)
	{
		case 3:
		{
			NT_PRINTER_DRIVER_INFO_LEVEL_3 *info3;
			if (driver.info_3 != NULL)
			{
				info3=driver.info_3;
				safe_free(info3->dependentfiles);
				ZERO_STRUCTP(info3);
				safe_free(info3);
				result=0;
			}
			else
			{
				result=4;
			}
			break;
		}
		case 6:
		{
			NT_PRINTER_DRIVER_INFO_LEVEL_6 *info6;
			if (driver.info_6 != NULL)
			{
				info6=driver.info_6;
				safe_free(info6->dependentfiles);
				safe_free(info6->previousnames);
				ZERO_STRUCTP(info6);
				safe_free(info6);
				result=0;
			}
			else
			{
				result=4;
			}
			break;
		}
		default:
			result=1;
			break;
	}
	return result;
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
	
	while (param != NULL && i < param_index) {
		param=param->next;
		i++;
	}
	
	if (param == NULL)
		return False;

	/* exited because it exist */
	*type=param->type;		
	StrnCpy(value, param->value, sizeof(fstring)-1);
	*data=(uint8 *)malloc(param->data_len*sizeof(uint8));
	if(*data == NULL)
		return False;
	ZERO_STRUCTP(*data);
	memcpy(*data, param->data, param->data_len);
	*len=param->data_len;
	return True;
}

/****************************************************************************
****************************************************************************/
BOOL get_specific_param(NT_PRINTER_INFO_LEVEL printer, uint32 level,
                        fstring value, uint8 **data, uint32 *type, uint32 *len)
{
	/* right now that's enough ! */	
	NT_PRINTER_PARAM *param;
	
	DEBUG(10, ("get_specific_param\n"));
	
	param=printer.info_2->specific;
		
	while (param != NULL)
	{
#if 1 /* JRA - I think this should be case insensitive.... */
		if ( strequal(value, param->value)
#else
		if ( !strcmp(value, param->value)
#endif
		    && strlen(value)==strlen(param->value))
			break;
			
		param=param->next;
	}
	
	if (param != NULL)
	{
        DEBUGADD(10, ("get_specific_param: found one param\n"));
		/* exited because it exist */
		*type=param->type;	
		
		*data=(uint8 *)malloc(param->data_len*sizeof(uint8));
		if(*data == NULL)
			return False;
		memcpy(*data, param->data, param->data_len);
		*len=param->data_len;

		DEBUGADD(10, ("get_specific_param: exit true\n"));
		return (True);
	}
	DEBUGADD(10, ("get_specific_param: exit false\n"));
	return (False);
}

/****************************************************************************
 Store a security desc for a printer.
****************************************************************************/

uint32 nt_printing_setsec(char *printername, SEC_DESC_BUF *secdesc_ctr)
{
	SEC_DESC_BUF *new_secdesc_ctr = NULL;
	SEC_DESC_BUF *old_secdesc_ctr = NULL;
	prs_struct ps;
	TALLOC_CTX *mem_ctx = NULL;
	fstring key;
	uint32 status;

	mem_ctx = talloc_init();
	if (mem_ctx == NULL)
		return False;

        /* The old owner and group sids of the security descriptor are not
	   present when new ACEs are added or removed by changing printer
	   permissions through NT.  If they are NULL in the new security
	   descriptor then copy them over from the old one. */

	if (!secdesc_ctr->sec->owner_sid || !secdesc_ctr->sec->grp_sid) {
		DOM_SID *owner_sid, *group_sid;
		SEC_ACL *dacl, *sacl;
		SEC_DESC *psd = NULL;
		size_t size;

		nt_printing_getsec(printername, &old_secdesc_ctr);

		/* Pick out correct owner and group sids */

		owner_sid = secdesc_ctr->sec->owner_sid ?
			secdesc_ctr->sec->owner_sid :
			old_secdesc_ctr->sec->owner_sid;

		group_sid = secdesc_ctr->sec->grp_sid ?
			secdesc_ctr->sec->grp_sid :
			old_secdesc_ctr->sec->grp_sid;

		dacl = secdesc_ctr->sec->dacl ?
			secdesc_ctr->sec->dacl :
			old_secdesc_ctr->sec->dacl;

		sacl = secdesc_ctr->sec->sacl ?
			secdesc_ctr->sec->sacl :
			old_secdesc_ctr->sec->sacl;

		/* Make a deep copy of the security descriptor */

		psd = make_sec_desc(secdesc_ctr->sec->revision,
				    owner_sid, group_sid,
				    sacl,
				    dacl,
				    &size);

		new_secdesc_ctr = make_sec_desc_buf(size, psd);

		/* Free up memory */

		free_sec_desc(&psd);
		free_sec_desc_buf(&old_secdesc_ctr);
	}

	if (!new_secdesc_ctr) {
		new_secdesc_ctr = secdesc_ctr;
	}

	/* Store the security descriptor in a tdb */

	prs_init(&ps, (uint32)sec_desc_size(new_secdesc_ctr->sec) +
		 sizeof(SEC_DESC_BUF), 4, mem_ctx, MARSHALL);

	if (!sec_io_desc_buf("nt_printing_setsec", &new_secdesc_ctr,
			     &ps, 1)) {
		status = ERROR_INVALID_FUNCTION;
		goto out;
	}

	slprintf(key, sizeof(key)-1, "SECDESC/%s", printername);

	if (tdb_prs_store(tdb, key, &ps)==0) {
		status = 0;
	} else {
		DEBUG(1,("Failed to store secdesc for %s\n", printername));
		status = ERROR_INVALID_FUNCTION;
	}

	/* Free malloc'ed memory */

 out:
	free_sec_desc_buf(&old_secdesc_ctr);

	if (new_secdesc_ctr != secdesc_ctr) {
		free_sec_desc_buf(&new_secdesc_ctr);
	}

	prs_mem_free(&ps);
	if (mem_ctx)
		talloc_destroy(mem_ctx);
	return status;
}

/****************************************************************************
 Construct a default security descriptor buffer for a printer.
****************************************************************************/

static SEC_DESC_BUF *construct_default_printer_sdb(void)
{
	extern DOM_SID global_sam_sid;
	SEC_ACE ace[3];
	SEC_ACCESS sa;
	SEC_ACL *psa = NULL;
	SEC_DESC_BUF *sdb = NULL;
	SEC_DESC *psd = NULL;
	DOM_SID owner_sid;
	size_t sd_size;
	enum SID_NAME_USE name_type;

	/* Create an ACE where Everyone is allowed to print */

	init_sec_access(&sa, PRINTER_ACE_PRINT);
	init_sec_ace(&ace[0], &global_sid_World, SEC_ACE_TYPE_ACCESS_ALLOWED,
		     sa, SEC_ACE_FLAG_CONTAINER_INHERIT);

	/* Make the security descriptor owned by the Administrators group
	   on the PDC of the domain. */

	if (winbind_lookup_name(lp_workgroup(), &owner_sid, &name_type)) {
		sid_append_rid(&owner_sid, DOMAIN_USER_RID_ADMIN);
	} else {
		/* Backup plan - make printer owned by admins or root.
		   This should emulate a lanman printer as security
		   settings can't be changed. */

		if (!lookup_name("root", &owner_sid, &name_type)) {
			sid_copy(&owner_sid, &global_sam_sid);
			sid_append_rid(&owner_sid, DOMAIN_USER_RID_ADMIN);
		}
	}

	init_sec_access(&sa, PRINTER_ACE_FULL_CONTROL);
	init_sec_ace(&ace[1], &owner_sid, SEC_ACE_TYPE_ACCESS_ALLOWED,
		     sa, SEC_ACE_FLAG_OBJECT_INHERIT |
		     SEC_ACE_FLAG_INHERIT_ONLY);

	init_sec_access(&sa, PRINTER_ACE_FULL_CONTROL);
	init_sec_ace(&ace[2], &owner_sid, SEC_ACE_TYPE_ACCESS_ALLOWED,
		     sa, SEC_ACE_FLAG_CONTAINER_INHERIT);

	/* The ACL revision number in rpc_secdesc.h differs from the one
	   created by NT when setting ACE entries in printer
	   descriptors.  NT4 complains about the property being edited by a
	   NT5 machine. */

#define NT4_ACL_REVISION 0x2

	if ((psa = make_sec_acl(NT4_ACL_REVISION, 3, ace)) != NULL) {
		psd = make_sec_desc(SEC_DESC_REVISION,
				    &owner_sid, NULL,
				    NULL, psa, &sd_size);
		free_sec_acl(&psa);
	}

	if (!psd) {
		DEBUG(0,("construct_default_printer_sd: Failed to make SEC_DESC.\n"));
		return NULL;
	}

	sdb = make_sec_desc_buf(sd_size, psd);

	DEBUG(4,("construct_default_printer_sdb: size = %u.\n",
		 (unsigned int)sd_size));

	free_sec_desc(&psd);
	return sdb;
}

/****************************************************************************
 Get a security desc for a printer.
****************************************************************************/

BOOL nt_printing_getsec(char *printername, SEC_DESC_BUF **secdesc_ctr)
{
	prs_struct ps;
	TALLOC_CTX *mem_ctx = NULL;
	fstring key;
	char *temp;

	mem_ctx = talloc_init();

	if (mem_ctx == NULL)
		return False;

	if ((temp = strchr(printername + 2, '\\'))) {
		printername = temp + 1;
	}

	/* Fetch security descriptor from tdb */

	slprintf(key, sizeof(key)-1, "SECDESC/%s", printername);

	if (tdb_prs_fetch(tdb, key, &ps, mem_ctx)!=0 ||
	    !sec_io_desc_buf("nt_printing_getsec", secdesc_ctr, &ps, 1)) {

		DEBUG(4,("creating default secdesc for %s\n", printername));

		if (!(*secdesc_ctr = construct_default_printer_sdb())) {
			talloc_destroy(mem_ctx);
			return False;
		}

                /* Save default security descriptor for later */

                prs_init(&ps, (uint32)sec_desc_size((*secdesc_ctr)->sec) +
                         sizeof(SEC_DESC_BUF), 4, mem_ctx, MARSHALL);

                if (sec_io_desc_buf("nt_printing_setsec", secdesc_ctr, &ps, 1))
                        tdb_prs_store(tdb, key, &ps);

		talloc_destroy(mem_ctx);
                prs_mem_free(&ps);

		return True;
	}

	/* If security descriptor is owned by S-1-1-0 and winbindd is up,
	   this security descriptor has been created when winbindd was
	   down.  Take ownership of security descriptor. */

	if (sid_equal((*secdesc_ctr)->sec->owner_sid, &global_sid_World)) {
		DOM_SID owner_sid;
		enum SID_NAME_USE name_type;

		/* Change sd owner to workgroup administrator */

		if (winbind_lookup_name(lp_workgroup(), &owner_sid,
					&name_type)) {
			SEC_DESC_BUF *new_secdesc_ctr = NULL;
			SEC_DESC *psd = NULL;
			size_t size;

			/* Create new sd */

			sid_append_rid(&owner_sid, DOMAIN_USER_RID_ADMIN);

			psd = make_sec_desc((*secdesc_ctr)->sec->revision,
					    &owner_sid,
					    (*secdesc_ctr)->sec->grp_sid,
					    (*secdesc_ctr)->sec->sacl,
					    (*secdesc_ctr)->sec->dacl,
					    &size);

			new_secdesc_ctr = make_sec_desc_buf(size, psd);

			free_sec_desc(&psd);

			/* Swap with other one */

			free_sec_desc_buf(secdesc_ctr);
			*secdesc_ctr = new_secdesc_ctr;

			/* Set it */

			nt_printing_setsec(printername, *secdesc_ctr);
		}
	}

	if (DEBUGLEVEL >= 10) {
		SEC_ACL *acl = (*secdesc_ctr)->sec->dacl;
		int i;

		DEBUG(10, ("secdesc_ctr for %s has %d aces:\n", 
			   printername, acl->num_aces));

		for (i = 0; i < acl->num_aces; i++) {
			fstring sid_str;

			sid_to_string(sid_str, &acl->ace[i].sid);

			DEBUG(10, ("%s %d %d 0x%08x\n", sid_str,
				   acl->ace[i].type, acl->ace[i].flags, 
				   acl->ace[i].info.mask)); 
		}
	}

	prs_mem_free(&ps);
	talloc_destroy(mem_ctx);
	return True;
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

/* Convert generic access rights to printer object specific access rights.
   It turns out that NT4 security descriptors use generic access rights and
   NT5 the object specific ones. */

void map_printer_permissions(SEC_DESC *sd)
{
	int i;

	for (i = 0; sd->dacl && i < sd->dacl->num_aces; i++) {
		se_map_generic(&sd->dacl->ace[i].info.mask,
			       &printer_generic_mapping);
	}
}

/****************************************************************************
 Check a user has permissions to perform the given operation.  We use the
 permission constants defined in include/rpc_spoolss.h to check the various
 actions we perform when checking printer access.

   PRINTER_ACCESS_ADMINISTER:
       print_queue_pause, print_queue_resume, update_printer_sec,
       update_printer, spoolss_addprinterex_level_2,
       _spoolss_setprinterdata

   PRINTER_ACCESS_USE:
       print_job_start

   JOB_ACCESS_ADMINISTER:
       print_job_delete, print_job_pause, print_job_resume,
       print_queue_purge

 ****************************************************************************/
BOOL print_access_check(struct current_user *user, int snum, int access_type)
{
	SEC_DESC_BUF *secdesc = NULL;
	uint32 access_granted, status;
	BOOL result;
	char *pname;
	extern struct current_user current_user;
        user_struct *us;
	
	/* If user is NULL then use the current_user structure */

	if (!user) user = &current_user;

	/* Always printer admins to do anything */

        if ((us = get_valid_user_struct(user->vuid)) && us->printer_admin)
                return True;

	/* Get printer name */

	pname = PRINTERNAME(snum);

	if (!pname || !*pname) {
		errno = EACCES;
		return False;
	}

	/* Get printer security descriptor */

	nt_printing_getsec(pname, &secdesc);

	if (access_type == JOB_ACCESS_ADMINISTER) {
		SEC_DESC_BUF *parent_secdesc = secdesc;

		/* Create a child security descriptor to check permissions
		   against.  This is because print jobs are child objects
		   objects of a printer. */

		secdesc = se_create_child_secdesc(parent_secdesc->sec, False);

		free_sec_desc_buf(&parent_secdesc);

		/* Now this is the bit that really confuses me.  The access
		   type needs to be changed from JOB_ACCESS_ADMINISTER to
		   PRINTER_ACCESS_ADMINISTER for this to work.  Something
		   to do with the child (job) object becoming like a
		   printer??  -tpot */

		access_type = PRINTER_ACCESS_ADMINISTER;
	}
	
	/* Check access */
	
	map_printer_permissions(secdesc->sec);

	result = se_access_check(secdesc->sec, user, access_type,
				 &access_granted, &status);

	/* BEGIN_ADMIN_LOG */
	if (access_granted == 0) {
		switch(access_type) {
			case 0x8:	sys_adminlog( LOG_ERR, (char *)
					gettext( "Permission denied-- user not allowed to connect to printer. User name: %s. Printer name: %s." ),
					uidtoname(user->uid), PRINTERNAME(snum) );
					break;
		}
	}
	/* END_ADMIN_LOG */

	DEBUG(4, ("access check was %s\n", result ? "SUCCESS" : "FAILURE"));
	
	/* Free mallocated memory */

	free_sec_desc_buf(&secdesc);

	if (!result)
		errno = EACCES;

	return result;
}

/****************************************************************************
 Check the time parameters allow a print operation.
*****************************************************************************/

BOOL print_time_access_check(int snum)
{
	NT_PRINTER_INFO_LEVEL *printer = NULL;
	BOOL ok = False;
	time_t now = time(NULL);
	struct tm *t;
	uint32 mins;

	if (get_a_printer(&printer, 2, lp_servicename(snum))!=0)
		return False;

	if (printer->info_2->starttime == 0 && printer->info_2->untiltime == 0)
		ok = True;

	t = gmtime(&now);
	mins = (uint32)t->tm_hour*60 + (uint32)t->tm_min;

	if (mins >= printer->info_2->starttime && mins <= printer->info_2->untiltime)
		ok = True;

	free_a_printer(&printer, 2);

	if (!ok)
		errno = EACCES;

	return ok;
}

/****************************************************************************
 Attempt to write a default device.
*****************************************************************************/

uint32 printer_write_default_dev(int snum, const PRINTER_DEFAULT *printer_default)
{
	NT_PRINTER_INFO_LEVEL *printer = NULL;

	uint32 result = 0;

	/*
	 * Don't bother if no default devicemode was sent.
	 */

	if (printer_default->devmode_cont.devmode == NULL)
		return 0;

	if (get_a_printer(&printer, 2, lp_servicename(snum))!=0)
		return ERROR_ACCESS_DENIED;

	/*
	 * Just ignore it if we already have a devmode.
	 */
#if 0
	if (printer->info_2->devmode != NULL)
		goto done;
#endif
	/*
	 * We don't have a devicemode and we're trying to write
	 * one. Check we have the access needed.
	 */
	DEBUG(5,("printer_write_default_dev: access: %x\n", printer_default->access_required));

	if ( (printer_default->access_required & PRINTER_ACCESS_ADMINISTER) != 
	      PRINTER_ACCESS_ADMINISTER) {
		DEBUG(5,("printer_write_default_dev: invalid request access to update: %x\n", printer_default->access_required));
		result = ERROR_ACCESS_DENIED;
		goto done;
	}

	if (!print_access_check(NULL, snum, PRINTER_ACCESS_ADMINISTER)) {
		DEBUG(5,("printer_write_default_dev: Access denied for printer %s\n",
			lp_servicename(snum) ));
		result = ERROR_ACCESS_DENIED;
		/*result = NT_STATUS_NO_PROBLEMO;*/
		goto done;
	}

	DEBUG(5,("printer_write_default_dev: updating, check OK.\n"));

	/*
	 * Convert the on the wire devicemode format to the internal one.
	 */

	if (!convert_devicemode(printer->info_2->printername,
				printer_default->devmode_cont.devmode,
				&printer->info_2->devmode)) {
		result = ERROR_NOT_ENOUGH_MEMORY;
		goto done;
	}

	/*
	 * Finally write back to the tdb.
	 */

	if (add_a_printer(*printer, 2)!=0) {
		result = ERROR_ACCESS_DENIED;
		goto done;
	}

  done:

	free_a_printer(&printer, 2);
	return result;
}

#undef OLD_NTDOMAIN
