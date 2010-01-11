/*
   Unix SMB/CIFS implementation.
   test suite for spoolss rpc operations

   Copyright (C) Guenther Deschner 2009-2010

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/****************************************************************************
****************************************************************************/

#include "spoolss.h"
#include "string.h"
#include "torture.h"

/****************************************************************************
****************************************************************************/

static BOOL test_OpenPrinter(struct torture_context *tctx,
			     LPSTR printername,
			     HANDLE handle)
{
	torture_comment(tctx, "Testing OpenPrinter(%s)", printername);

	if (!OpenPrinter(printername, handle, NULL)) {
		char tmp[1024];
		sprintf(tmp, "failed to open printer %s, error was: 0x%08x\n",
			printername, GetLastError());
		torture_fail(tctx, tmp);
	}

	return TRUE;
}

/****************************************************************************
****************************************************************************/

static BOOL test_ClosePrinter(struct torture_context *tctx,
			      HANDLE handle)
{
	torture_comment(tctx, "Testing ClosePrinter");

	if (!ClosePrinter(handle)) {
		char tmp[1024];
		sprintf(tmp, "failed to close printer, error was: %s\n",
			errstr(GetLastError()));
		torture_fail(tctx, tmp);
	}

	return TRUE;
}


/****************************************************************************
****************************************************************************/

static BOOL test_EnumPrinters(struct torture_context *tctx,
			      LPSTR servername)
{
	DWORD levels[]  = { 1, 2, 5 };
	DWORD success[] = { 1, 1, 1 };
	DWORD i;
	DWORD flags = PRINTER_ENUM_NAME;
	LPBYTE buffer = NULL;

	for (i=0; i < ARRAY_SIZE(levels); i++) {

		DWORD needed = 0;
		DWORD returned = 0;
		DWORD err = 0;
		char tmp[1024];

		torture_comment(tctx, "Testing EnumPrinters level %d", levels[i]);

		EnumPrinters(flags, servername, levels[i], NULL, 0, &needed, &returned);
		err = GetLastError();
		if (err == ERROR_INSUFFICIENT_BUFFER) {
			err = 0;
			buffer = malloc(needed);
			torture_assert(tctx, buffer, "malloc failed");
			if (!EnumPrinters(flags, servername, levels[i], buffer, needed, &needed, &returned)) {
				err = GetLastError();
			}
		}
		if (err) {
			sprintf(tmp, "EnumPrinters failed level %d on [%s] (buffer size = %d), error: %s\n",
				levels[i], servername, needed, errstr(err));
			if (success[i]) {
				torture_fail(tctx, tmp);
			} else {
				torture_warning(tctx, tmp);
			}
		}

		if (tctx->print) {
			print_printer_info_bylevel(levels[i], buffer, returned);
		}

		free(buffer);
		buffer = NULL;
	}

	return TRUE;
}

/****************************************************************************
****************************************************************************/

static BOOL test_EnumDrivers(struct torture_context *tctx,
			     LPSTR servername,
			     LPSTR architecture)
{
	DWORD levels[]  = { 1, 2, 3, 4, 5, 6, 8 };
	DWORD success[] = { 1, 1, 1, 1, 1, 1, 1 };
	DWORD i;
	LPBYTE buffer = NULL;

	for (i=0; i < ARRAY_SIZE(levels); i++) {

		DWORD needed = 0;
		DWORD returned = 0;
		DWORD err = 0;
		char tmp[1024];

		torture_comment(tctx, "Testing EnumPrinterDrivers level %d", levels[i]);

		EnumPrinterDrivers(servername, architecture, levels[i], NULL, 0, &needed, &returned);
		err = GetLastError();
		if (err == ERROR_INSUFFICIENT_BUFFER) {
			err = 0;
			buffer = malloc(needed);
			torture_assert(tctx, buffer, "malloc failed");
			if (!EnumPrinterDrivers(servername, architecture, levels[i], buffer, needed, &needed, &returned)) {
				err = GetLastError();
			}
		}
		if (err) {
			sprintf(tmp, "EnumPrinterDrivers failed level %d on [%s] (buffer size = %d), error: %s\n",
				levels[i], servername, needed, errstr(err));
			if (success[i]) {
				torture_fail(tctx, tmp);
			} else {
				torture_warning(tctx, tmp);
			}
		}

		free(buffer);
		buffer = NULL;
	}

	return TRUE;
}

/****************************************************************************
****************************************************************************/

static BOOL test_EnumForms(struct torture_context *tctx,
			   LPSTR servername,
			   HANDLE handle)
{
	DWORD levels[]  = { 1, 2 };
	DWORD success[] = { 1, 0 };
	DWORD i;
	LPBYTE buffer = NULL;

	for (i=0; i < ARRAY_SIZE(levels); i++) {

		DWORD needed = 0;
		DWORD returned = 0;
		DWORD err = 0;
		char tmp[1024];

		torture_comment(tctx, "Testing EnumForms level %d", levels[i]);

		EnumForms(handle, levels[i], NULL, 0, &needed, &returned);
		err = GetLastError();
		if (err == ERROR_INSUFFICIENT_BUFFER) {
			err = 0;
			buffer = malloc(needed);
			torture_assert(tctx, buffer, "malloc failed");
			if (!EnumForms(handle, levels[i], buffer, needed, &needed, &returned)) {
				err = GetLastError();
			}
		}
		if (err) {
			sprintf(tmp, "EnumForms failed level %d on [%s] (buffer size = %d), error: %s\n",
				levels[i], servername, needed, errstr(err));
			if (success[i]) {
				torture_fail(tctx, tmp);
			} else {
				torture_warning(tctx, tmp);
			}
		}

		free(buffer);
		buffer = NULL;
	}

	return TRUE;
}

/****************************************************************************
****************************************************************************/

static BOOL test_EnumPorts(struct torture_context *tctx,
			   LPSTR servername)
{
	DWORD levels[]  = { 1, 2 };
	DWORD success[] = { 1, 1 };
	DWORD i;
	LPBYTE buffer = NULL;

	for (i=0; i < ARRAY_SIZE(levels); i++) {

		DWORD needed = 0;
		DWORD returned = 0;
		DWORD err = 0;
		char tmp[1024];

		torture_comment(tctx, "Testing EnumPorts level %d", levels[i]);

		EnumPorts(servername, levels[i], NULL, 0, &needed, &returned);
		err = GetLastError();
		if (err == ERROR_INSUFFICIENT_BUFFER) {
			err = 0;
			buffer = malloc(needed);
			torture_assert(tctx, buffer, "malloc failed");
			if (!EnumPorts(servername, levels[i], buffer, needed, &needed, &returned)) {
				err = GetLastError();
			}
		}
		if (err) {
			sprintf(tmp, "EnumPorts failed level %d on [%s] (buffer size = %d), error: %s\n",
				levels[i], servername, needed, errstr(err));
			if (success[i]) {
				torture_fail(tctx, tmp);
			} else {
				torture_warning(tctx, tmp);
			}
		}

		free(buffer);
		buffer = NULL;
	}

	return TRUE;
}

/****************************************************************************
****************************************************************************/

static BOOL test_EnumMonitors(struct torture_context *tctx,
			      LPSTR servername)
{
	DWORD levels[]  = { 1, 2 };
	DWORD success[] = { 1, 1 };
	DWORD i;
	LPBYTE buffer = NULL;

	for (i=0; i < ARRAY_SIZE(levels); i++) {

		DWORD needed = 0;
		DWORD returned = 0;
		DWORD err = 0;
		char tmp[1024];

		torture_comment(tctx, "Testing EnumMonitors level %d", levels[i]);

		EnumMonitors(servername, levels[i], NULL, 0, &needed, &returned);
		err = GetLastError();
		if (err == ERROR_INSUFFICIENT_BUFFER) {
			err = 0;
			buffer = malloc(needed);
			torture_assert(tctx, buffer, "malloc failed");
			if (!EnumMonitors(servername, levels[i], buffer, needed, &needed, &returned)) {
				err = GetLastError();
			}
		}
		if (err) {
			sprintf(tmp, "EnumMonitors failed level %d on [%s] (buffer size = %d), error: %s\n",
				levels[i], servername, needed, errstr(err));
			if (success[i]) {
				torture_fail(tctx, tmp);
			} else {
				torture_warning(tctx, tmp);
			}
		}

		free(buffer);
		buffer = NULL;
	}

	return TRUE;
}

/****************************************************************************
****************************************************************************/

static BOOL test_EnumPrintProcessors(struct torture_context *tctx,
				     LPSTR servername,
				     LPSTR architecture)
{
	DWORD levels[]  = { 1 };
	DWORD success[] = { 1 };
	DWORD i;
	LPBYTE buffer = NULL;

	for (i=0; i < ARRAY_SIZE(levels); i++) {

		DWORD needed = 0;
		DWORD returned = 0;
		DWORD err = 0;
		char tmp[1024];

		torture_comment(tctx, "Testing EnumPrintProcessors level %d", levels[i]);

		EnumPrintProcessors(servername, architecture, levels[i], NULL, 0, &needed, &returned);
		err = GetLastError();
		if (err == ERROR_INSUFFICIENT_BUFFER) {
			err = 0;
			buffer = malloc(needed);
			torture_assert(tctx, buffer, "malloc failed");
			if (!EnumPrintProcessors(servername, architecture, levels[i], buffer, needed, &needed, &returned)) {
				err = GetLastError();
			}
		}
		if (err) {
			sprintf(tmp, "EnumPrintProcessors failed level %d on [%s] (buffer size = %d), error: %s\n",
				levels[i], servername, needed, errstr(err));
			if (success[i]) {
				torture_fail(tctx, tmp);
			} else {
				torture_warning(tctx, tmp);
			}
		}

		free(buffer);
		buffer = NULL;
	}

	return TRUE;
}

/****************************************************************************
****************************************************************************/

static BOOL test_EnumPrintProcessorDatatypes(struct torture_context *tctx,
					     LPSTR servername)
{
	DWORD levels[]  = { 1 };
	DWORD success[] = { 1 };
	DWORD i;
	LPBYTE buffer = NULL;

	for (i=0; i < ARRAY_SIZE(levels); i++) {

		DWORD needed = 0;
		DWORD returned = 0;
		DWORD err = 0;
		char tmp[1024];

		torture_comment(tctx, "Testing EnumPrintProcessorDatatypes level %d", levels[i]);

		EnumPrintProcessorDatatypes(servername, "winprint", levels[i], NULL, 0, &needed, &returned);
		err = GetLastError();
		if (err == ERROR_INSUFFICIENT_BUFFER) {
			err = 0;
			buffer = malloc(needed);
			torture_assert(tctx, buffer, "malloc failed");
			if (!EnumPrintProcessorDatatypes(servername, "winprint", levels[i], buffer, needed, &needed, &returned)) {
				err = GetLastError();
			}
		}
		if (err) {
			sprintf(tmp, "EnumPrintProcessorDatatypes failed level %d on [%s] (buffer size = %d), error: %s\n",
				levels[i], servername, needed, errstr(err));
			if (success[i]) {
				torture_fail(tctx, tmp);
			} else {
				torture_warning(tctx, tmp);
			}
		}

		free(buffer);
		buffer = NULL;
	}

	return TRUE;
}

/****************************************************************************
****************************************************************************/

static BOOL test_GetPrinter(struct torture_context *tctx,
			    LPSTR printername,
			    HANDLE handle)
{
	DWORD levels[]  = { 1, 2, 3, 4, 5, 6, 7, 8 };
	DWORD success[] = { 1, 1, 1, 1, 1, 1, 1, 1 };
	DWORD i;
	LPBYTE buffer = NULL;

	for (i=0; i < ARRAY_SIZE(levels); i++) {

		DWORD needed = 0;
		DWORD err = 0;
		char tmp[1024];

		torture_comment(tctx, "Testing GetPrinter level %d", levels[i]);

		GetPrinter(handle, levels[i], NULL, 0, &needed);
		err = GetLastError();
		if (err == ERROR_INSUFFICIENT_BUFFER) {
			err = 0;
			buffer = malloc(needed);
			torture_assert(tctx, buffer, "malloc failed");
			if (!GetPrinter(handle, levels[i], buffer, needed, &needed)) {
				err = GetLastError();
			}
		}
		if (err) {
			sprintf(tmp, "GetPrinter failed level %d on [%s] (buffer size = %d), error: %s\n",
				levels[i], printername, needed, errstr(err));
			if (success[i]) {
				torture_fail(tctx, tmp);
			} else {
				torture_warning(tctx, tmp);
			}
		}

		free(buffer);
		buffer = NULL;
	}

	return TRUE;
}

/****************************************************************************
****************************************************************************/

static BOOL test_GetPrinterDriver(struct torture_context *tctx,
				  LPSTR printername,
				  LPSTR architecture,
				  HANDLE handle)
{
	DWORD levels[]  = { 1, 2, 3, 4, 5, 6, 8, 101};
	DWORD success[] = { 1, 1, 1, 1, 1, 1, 1, 1 };
	DWORD i;
	LPBYTE buffer = NULL;

	for (i=0; i < ARRAY_SIZE(levels); i++) {

		DWORD needed = 0;
		DWORD err = 0;
		char tmp[1024];

		torture_comment(tctx, "Testing GetPrinterDriver level %d", levels[i]);

		GetPrinterDriver(handle, architecture, levels[i], NULL, 0, &needed);
		err = GetLastError();
		if (err == ERROR_INSUFFICIENT_BUFFER) {
			err = 0;
			buffer = malloc(needed);
			torture_assert(tctx, buffer, "malloc failed");
			if (!GetPrinterDriver(handle, architecture, levels[i], buffer, needed, &needed)) {
				err = GetLastError();
			}
		}
		if (err) {
			sprintf(tmp, "GetPrinterDriver failed level %d on [%s] (buffer size = %d), error: %s\n",
				levels[i], printername, needed, errstr(err));
			if (success[i]) {
				torture_fail(tctx, tmp);
			} else {
				torture_warning(tctx, tmp);
			}
		}

		free(buffer);
		buffer = NULL;
	}

	return TRUE;
}


/****************************************************************************
****************************************************************************/

static BOOL test_EnumJobs(struct torture_context *tctx,
			  LPSTR printername,
			  HANDLE handle)
{
	DWORD levels[]  = { 1, 2, 3, 4 };
	DWORD success[] = { 1, 1, 1, 1 };
	DWORD i;
	LPBYTE buffer = NULL;

	for (i=0; i < ARRAY_SIZE(levels); i++) {

		DWORD needed = 0;
		DWORD returned = 0;
		DWORD err = 0;
		char tmp[1024];

		torture_comment(tctx, "Testing EnumJobs level %d", levels[i]);

		EnumJobs(handle, 0, 100, levels[i], NULL, 0, &needed, &returned);
		err = GetLastError();
		if (err == ERROR_INSUFFICIENT_BUFFER) {
			err = 0;
			buffer = malloc(needed);
			torture_assert(tctx, buffer, "malloc failed");
			if (!EnumJobs(handle, 0, 100, levels[i], buffer, needed, &needed, &returned)) {
				err = GetLastError();
			}
		}
		if (err) {
			sprintf(tmp, "EnumJobs failed level %d on [%s] (buffer size = %d), error: %s\n",
				levels[i], printername, needed, errstr(err));
			if (success[i]) {
				torture_fail(tctx, tmp);
			} else {
				torture_warning(tctx, tmp);
			}
		}

		free(buffer);
		buffer = NULL;
	}

	return TRUE;
}

/****************************************************************************
****************************************************************************/

static BOOL test_OnePrinter(struct torture_context *tctx,
			    LPSTR printername,
			    LPSTR architecture)
{
	HANDLE handle;
	BOOL ret = TRUE;

	torture_comment(tctx, "Testing Printer %s", printername);

	ret &= test_OpenPrinter(tctx, printername, &handle);
	ret &= test_GetPrinter(tctx, printername, handle);
	ret &= test_GetPrinterDriver(tctx, printername, architecture, handle);
	ret &= test_EnumForms(tctx, printername, handle);
	ret &= test_EnumJobs(tctx, printername, handle);
	ret &= test_ClosePrinter(tctx, handle);

	return ret;
}

/****************************************************************************
****************************************************************************/

static BOOL test_OneDriver(struct torture_context *tctx,
			   LPSTR printername,
			   LPSTR drivername)
{
	return TRUE;
}

/****************************************************************************
****************************************************************************/

static BOOL test_EachDriver(struct torture_context *tctx,
			    LPSTR servername)
{
	return TRUE;
}

/****************************************************************************
****************************************************************************/

static BOOL test_EachPrinter(struct torture_context *tctx,
			     LPSTR servername,
			     LPSTR architecture)
{
	DWORD needed = 0;
	DWORD returned = 0;
	DWORD err = 0;
	char tmp[1024];
	DWORD i;
	DWORD flags = PRINTER_ENUM_NAME;
	PPRINTER_INFO_1 buffer = NULL;

	torture_comment(tctx, "Testing EnumPrinters level %d", 1);

	EnumPrinters(flags, servername, 1, NULL, 0, &needed, &returned);
	err = GetLastError();
	if (err == ERROR_INSUFFICIENT_BUFFER) {
		err = 0;
		buffer = (PPRINTER_INFO_1)malloc(needed);
		torture_assert(tctx, buffer, "malloc failed");
		if (!EnumPrinters(flags, servername, 1, (LPBYTE)buffer, needed, &needed, &returned)) {
			err = GetLastError();
		}
	}
	if (err) {
		sprintf(tmp, "EnumPrinters failed level %d on [%s] (buffer size = %d), error: %s\n",
			1, servername, needed, errstr(err));
		torture_fail(tctx, tmp);
	}

	for (i=0; i < returned; i++) {
		torture_assert(tctx, test_OnePrinter(tctx, buffer[i].pName, architecture),
			"failed to test one printer");
	}

	free(buffer);

	return TRUE;
}

/****************************************************************************
****************************************************************************/

static BOOL test_GetPrintProcessorDirectory(struct torture_context *tctx,
					    LPSTR servername,
					    LPSTR architecture)
{
	DWORD levels[]  = { 1 };
	DWORD success[] = { 1 };
	DWORD i;
	LPBYTE buffer = NULL;

	for (i=0; i < ARRAY_SIZE(levels); i++) {

		DWORD needed = 0;
		DWORD err = 0;
		char tmp[1024];

		torture_comment(tctx, "Testing GetPrintProcessorDirectory level %d", levels[i]);

		GetPrintProcessorDirectory(servername, architecture, levels[i], NULL, 0, &needed);
		err = GetLastError();
		if (err == ERROR_INSUFFICIENT_BUFFER) {
			err = 0;
			buffer = malloc(needed);
			torture_assert(tctx, buffer, "malloc failed");
			if (!GetPrintProcessorDirectory(servername, architecture, levels[i], buffer, needed, &needed)) {
				err = GetLastError();
			}
		}
		if (err) {
			sprintf(tmp, "GetPrintProcessorDirectory failed level %d on [%s] (buffer size = %d), error: %s\n",
				levels[i], servername, needed, errstr(err));
			if (success[i]) {
				torture_fail(tctx, tmp);
			} else {
				torture_warning(tctx, tmp);
			}
		}

		free(buffer);
		buffer = NULL;
	}

	return TRUE;
}

/****************************************************************************
****************************************************************************/

static BOOL test_GetPrinterDriverDirectory(struct torture_context *tctx,
					   LPSTR servername,
					   LPSTR architecture)
{
	DWORD levels[]  = { 1 };
	DWORD success[] = { 1 };
	DWORD i;
	LPBYTE buffer = NULL;

	for (i=0; i < ARRAY_SIZE(levels); i++) {

		DWORD needed = 0;
		DWORD err = 0;
		char tmp[1024];

		torture_comment(tctx, "Testing GetPrinterDriverDirectory level %d", levels[i]);

		GetPrinterDriverDirectory(servername, architecture, levels[i], NULL, 0, &needed);
		err = GetLastError();
		if (err == ERROR_INSUFFICIENT_BUFFER) {
			err = 0;
			buffer = malloc(needed);
			torture_assert(tctx, buffer, "malloc failed");
			if (!GetPrinterDriverDirectory(servername, architecture, levels[i], buffer, needed, &needed)) {
				err = GetLastError();
			}
		}
		if (err) {
			sprintf(tmp, "GetPrinterDriverDirectory failed level %d on [%s] (buffer size = %d), error: %s\n",
				levels[i], servername, needed, errstr(err));
			if (success[i]) {
				torture_fail(tctx, tmp);
			} else {
				torture_warning(tctx, tmp);
			}
		}

		free(buffer);
		buffer = NULL;
	}

	return TRUE;
}


/****************************************************************************
****************************************************************************/

int main(int argc, char *argv[])
{
	BOOL ret = FALSE;
	LPSTR servername;
	LPSTR architecture = "Windows NT x86";
	HANDLE handle;
	struct torture_context *tctx;

	if (argc < 2) {
		fprintf(stderr, "usage: %s <servername> [print]\n", argv[0]);
		exit(-1);
	}

	tctx = malloc(sizeof(struct torture_context));
	if (!tctx) {
		fprintf(stderr, "out of memory\n");
		exit(-1);
	}
	memset(tctx, '\0', sizeof(*tctx));

	servername = argv[1];

	if (argc >= 3) {
		if (strcmp(argv[2], "print") == 0) {
			tctx->print = TRUE;
		}
	}

	ret &= test_EnumPrinters(tctx, servername);
	ret &= test_EnumDrivers(tctx, servername, architecture);
	ret &= test_OpenPrinter(tctx, servername, &handle);
	ret &= test_EnumForms(tctx, servername, handle);
	ret &= test_ClosePrinter(tctx, handle);
	ret &= test_EnumPorts(tctx, servername);
	ret &= test_EnumMonitors(tctx, servername);
	ret &= test_EnumPrintProcessors(tctx, servername, architecture);
	ret &= test_EnumPrintProcessorDatatypes(tctx, servername);
	ret &= test_GetPrintProcessorDirectory(tctx, servername, architecture);
	ret &= test_GetPrinterDriverDirectory(tctx, servername, architecture);
	ret &= test_EachPrinter(tctx, servername, architecture);
	ret &= test_EachDriver(tctx, servername);

	if (!ret) {
		if (tctx->last_reason) {
			fprintf(stderr, "failed: %s\n", tctx->last_reason);
		}
		free(tctx);
		return -1;
	}

	printf("%s run successfully\n", argv[0]);

	free(tctx);
	return 0;
}
