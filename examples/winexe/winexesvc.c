/*
 * Copyright (C) Andrzej Hajda 2009-2013
 * Contact: andrzej.hajda@wp.pl
 *
 * Source of this file: https://git.code.sf.net/p/winexe/winexe-waf
 * commit b787d2a2c4b1abc3653bad10aec943b8efcd7aab.
 *
 * ** NOTE! The following "GPLv3 only" license applies to the winexe
 * ** service files.  This does NOT imply that all of Samba is released
 * ** under the "GPLv3 only" license.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 3 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <windows.h>
#include <aclapi.h>
#include <userenv.h>

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>

#include "winexesvc.h"

#define BUFSIZE 256

#if 0
#define dbg(arg...) \
({\
	FILE *f = fopen("C:\\" SERVICE_NAME ".log", "at");\
	if (f) {\
		fprintf(f, arg);\
		fclose(f);\
	}\
})
#else
#define dbg(arg...)
#endif

static SECURITY_ATTRIBUTES sa;

/* Creates SECURITY_ATTRIBUTES sa with full access for BUILTIN\Administrators */
static int CreatePipesSA()
{
	DWORD dwRes;
	PSID pAdminSID = NULL;
	PACL pACL = NULL;
	PSECURITY_DESCRIPTOR pSD = NULL;
	EXPLICIT_ACCESS ea;
	SID_IDENTIFIER_AUTHORITY SIDAuthNT = {SECURITY_NT_AUTHORITY};

	/* Create a SID for the BUILTIN\Administrators group. */
	if (
		!AllocateAndInitializeSid(
			&SIDAuthNT, 2,
			SECURITY_BUILTIN_DOMAIN_RID,
			DOMAIN_ALIAS_RID_ADMINS,
			0, 0, 0, 0, 0, 0, &pAdminSID
		)
	) {
		dbg("AllocateAndInitializeSid Error %lu\n", GetLastError());
		return 0;
	}
	/* Initialize an EXPLICIT_ACCESS structure for an ACE.
	   The ACE will allow the Administrators group full access to the key.
	*/
	ea.grfAccessPermissions = FILE_ALL_ACCESS;
	ea.grfAccessMode = SET_ACCESS;
	ea.grfInheritance = NO_INHERITANCE;
	ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
	ea.Trustee.TrusteeType = TRUSTEE_IS_GROUP;
	ea.Trustee.ptstrName = (LPTSTR) pAdminSID;

	/* Create a new ACL that contains the new ACEs */
	dwRes = SetEntriesInAcl(1, &ea, NULL, &pACL);
	if (ERROR_SUCCESS != dwRes) {
		dbg("SetEntriesInAcl Error %lu\n", GetLastError());
		return 0;
	}
	/* Initialize a security descriptor */
	pSD = (PSECURITY_DESCRIPTOR) LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);
	if (NULL == pSD) {
		dbg("LocalAlloc Error %lu\n", GetLastError());
		return 0;
	}

	if (!InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION))
	{
		dbg("InitializeSecurityDescriptor Error %lu\n", GetLastError());
		return 0;
	}
	/* Add the ACL to the security descriptor */
	if (
		!SetSecurityDescriptorDacl(
			pSD, TRUE,  /* bDaclPresent flag */
			pACL, FALSE  /* not a default DACL */
		)
	) {
		dbg("SetSecurityDescriptorDacl Error %lu\n", GetLastError());
		return 0;
	}
	/* Initialize a security attributes structure */
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.lpSecurityDescriptor = pSD;
	sa.bInheritHandle = FALSE;
	return 1;
}

typedef struct {
	HANDLE h;
	OVERLAPPED o;
} OV_HANDLE;

static int hgets(char *str, int n, OV_HANDLE *pipe)
{
	DWORD res;
	DWORD count = 0;
	--n;
	while (--n >= 0) {
		if (!ReadFile(pipe->h, str, 1, NULL, &pipe->o) && GetLastError() != ERROR_IO_PENDING)
			goto finish;
		if (!GetOverlappedResult(pipe->h, &pipe->o, &res, TRUE) || !res)
			goto finish;
		if (*str == '\n')
			goto finish;
		++count;
		++str;
	}
finish:
	*str = 0;
	return count;
}

static int hprintf(OV_HANDLE *pipe, const char *fmt, ...)
{
	int res;
	char buf[1024];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	if (!WriteFile(pipe->h, buf, strlen(buf), NULL, &pipe->o) && GetLastError() == ERROR_IO_PENDING)
		GetOverlappedResult(pipe->h, &pipe->o, (LPDWORD)&res, TRUE);
	FlushFileBuffers(pipe->h);
	return res;
}

typedef struct {
	OV_HANDLE *pipe;
	const char *cmd;
	HANDLE pin;
	HANDLE pout;
	HANDLE perr;
	HANDLE token;
	int implevel;
	int system;
	int profile;
	char *runas;
	int conn_number;
} connection_context;

typedef int CMD_FUNC(connection_context *);

typedef struct {
	const char *name;
	CMD_FUNC *func;
} CMD_ITEM;

static int cmd_set(connection_context *c)
{
	static const char* var_system = "system";
	static const char* var_implevel = "implevel";
	static const char* var_runas = "runas";
	static const char* var_profile = "profile";
	char *cmdline;
	int res = 0;

	cmdline = strchr(c->cmd, ' ');
	if (!cmdline) {
		goto finish;
	}
	++cmdline;
	int l;
	if ((strstr(cmdline, var_system) == cmdline) && (cmdline[l = strlen(var_system)] == ' ')) {
		c->system = atoi(cmdline + l + 1);
	} else if ((strstr(cmdline, var_implevel) == cmdline) && (cmdline[l = strlen(var_implevel)] == ' ')) {
		c->implevel = atoi(cmdline + l + 1);
	} else if ((strstr(cmdline, var_profile) == cmdline) && (cmdline[l = strlen(var_profile)] == ' ')) {
		c->profile = atoi(cmdline + l + 1);
	} else if ((strstr(cmdline, var_runas) == cmdline) && (cmdline[l = strlen(var_runas)] == ' ')) {
		c->runas = strdup(cmdline + l + 1);
	} else {
		hprintf(c->pipe, "error Unknown commad (%s)\n", c->cmd);
		goto finish;
	}
	res = 1;
finish:
	return res;
}

static int cmd_get(connection_context *c)
{
	static const char* var_version = "version";
	static const char* var_codepage = "codepage";
	char *cmdline;
	int res = 0;

	cmdline = strchr(c->cmd, ' ');
	if (!cmdline) {
		goto finish;
	}
	++cmdline;
	int l;
	if ((strstr(cmdline, var_version) == cmdline)
	    && (cmdline[l = strlen(var_version)] == 0)) {
		hprintf(c->pipe, "version 0x%04X\n", VERSION);
	} else if ((strstr(cmdline, var_codepage) == cmdline)
	           && (cmdline[l = strlen(var_codepage)] == 0)) {
		hprintf(c->pipe, "codepage %d\n", GetOEMCP());
	} else {
		hprintf(c->pipe, "error Unknown argument (%s)\n", c->cmd);
		goto finish;
	}
	res = 1;
finish:
	return res;
}

typedef struct {
	char *user;
	char *domain;
	char *password;
} credentials;

static int prepare_credentials(char *str, credentials *crd)
{
	char *p;
	p = strchr(str, '/');
	if (!p) p = strchr(str, '\\');
	if (p) {
		*p++ = 0;
		crd->domain = str;
	} else {
		p = str;
		crd->domain = ".";
	}
	crd->user = p;
	p = strchr(p, '%');
	if (p)
		*p++ = 0;
	crd->password = p;
	return 1;
}

static int get_token(connection_context *c)
{
	int res = 0;
	int wres;
	HANDLE token;

	if (c->runas) {
		credentials crd;
		if (!prepare_credentials(c->runas, &crd)) {
			hprintf(c->pipe, "error Incorrect runas credentials\n");
			goto finish;
		}
		wres = LogonUser(crd.user, crd.domain, crd.password, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &c->token);
		if (!wres) {
			hprintf(c->pipe, "error Cannot LogonUser(%s,%s,%s) %d\n",
			        crd.user, crd.domain, crd.password, GetLastError());
			goto finish;
		}
		res = 1;
		goto finish;
	} else if (c->system) {
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &token)) {
			hprintf(c->pipe, "error Cannot OpenProcessToken %d\n", GetLastError());
			goto finish;
		}
	} else {
		if (!ImpersonateNamedPipeClient(c->pipe->h)) {
			hprintf(c->pipe, "error Cannot ImpersonateNamedPipeClient %d\n", GetLastError());
			goto finish;
		}
		if (!OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, FALSE, &token)) {
			hprintf(c->pipe, "error Cannot OpenThreadToken %d\n", GetLastError());
			goto finishRevertToSelf;
		}
	}
	if (!DuplicateTokenEx(token, MAXIMUM_ALLOWED, 0, c->implevel, TokenPrimary, &c->token)) {
		hprintf(c->pipe, "error Cannot Duplicate Token %d\n", GetLastError());
		goto finishCloseToken;
	}
	res = 1;
finishCloseToken:
	CloseHandle(token);
finishRevertToSelf:
	if (!c->system) {
		if (!RevertToSelf()) {
			hprintf(c->pipe, "error Cannot RevertToSelf %d\n", GetLastError());
			res = 0;
		}
	}
finish:
	return res;
}

static int load_user_profile(connection_context *c)
{
	PROFILEINFO pi = { .dwSize = sizeof(PROFILEINFO) };
	DWORD ulen = 256;
	TCHAR username[ulen];

	GetUserName(username, &ulen);
	pi.lpUserName = username;

	return LoadUserProfile(c->token, &pi);
}

static int cmd_run(connection_context *c)
{
	char buf[256];
	int res = 0;
	char *cmdline;
	DWORD pipe_nr;

	cmdline = strchr(c->cmd, ' ');
	if (!cmdline) {
		goto finish;
	}
	++cmdline;

	if (!get_token(c))
		return 0;

	pipe_nr = (GetCurrentProcessId() << 16) + (DWORD) c->conn_number;

	sprintf(buf, "\\\\.\\pipe\\" PIPE_NAME_IN, (unsigned int) pipe_nr);
	c->pin = CreateNamedPipe(buf,
	                         PIPE_ACCESS_DUPLEX,
	                         PIPE_WAIT,
	                         1,
	                         BUFSIZE,
	                         BUFSIZE,
	                         NMPWAIT_USE_DEFAULT_WAIT,
	                         &sa);
	if (c->pin == INVALID_HANDLE_VALUE) {
		hprintf(c->pipe, "error Cannot create in pipe(%s), error 0x%08X\n", buf, GetLastError());
		goto finishCloseToken;
	}

	sprintf(buf, "\\\\.\\pipe\\" PIPE_NAME_OUT, (unsigned int) pipe_nr);
	c->pout = CreateNamedPipe(buf,
	                          PIPE_ACCESS_DUPLEX,
	                          PIPE_WAIT,
	                          1,
	                          BUFSIZE,
	                          BUFSIZE,
	                          NMPWAIT_USE_DEFAULT_WAIT,
	                          &sa);
	if (c->pout == INVALID_HANDLE_VALUE) {
		hprintf(c->pipe, "error Cannot create out pipe(%s), error 0x%08X\n", buf, GetLastError());
		goto finishClosePin;
	}

	sprintf(buf, "\\\\.\\pipe\\" PIPE_NAME_ERR, (unsigned int) pipe_nr);
	c->perr = CreateNamedPipe(buf,
	                          PIPE_ACCESS_DUPLEX,
	                          PIPE_WAIT,
	                          1,
	                          BUFSIZE,
	                          BUFSIZE,
	                          NMPWAIT_USE_DEFAULT_WAIT,
	                          &sa);
	if (c->perr == INVALID_HANDLE_VALUE) {
		hprintf(c->pipe, "error Cannot create err pipe(%s), error 0x%08x\n", buf, GetLastError());
		goto finishClosePout;
	}

	/* Send handle to client (it will use it to connect pipes) */
	hprintf(c->pipe, CMD_STD_IO_ERR " %08X\n", pipe_nr);

	HANDLE ph[] = { c->pin, c->pout, c->perr };
	int i;

	for (i = 0; i < 3; ++i) {
		if (ConnectNamedPipe(ph[i], NULL))
			continue;
		int err = GetLastError();
		if (err != ERROR_PIPE_CONNECTED) {
			hprintf(c->pipe, "error ConnectNamedPipe(pin) %d\n", err);
			while (--i >= 0)
				DisconnectNamedPipe(ph[i]);
			goto finishClosePerr;
		}
	}

	SetHandleInformation(c->pin, HANDLE_FLAG_INHERIT, 1);
	SetHandleInformation(c->pout, HANDLE_FLAG_INHERIT, 1);
	SetHandleInformation(c->perr, HANDLE_FLAG_INHERIT, 1);

	if (c->profile)
		load_user_profile(c);

	PROCESS_INFORMATION pi;
	ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));

	STARTUPINFO si;
	ZeroMemory(&si, sizeof(STARTUPINFO));
	si.cb = sizeof(STARTUPINFO);
	si.hStdInput = c->pin;
	si.hStdOutput = c->pout;
	si.hStdError = c->perr;
	si.dwFlags |= STARTF_USESTDHANDLES;

	if (CreateProcessAsUser(
		c->token,
		NULL,
		cmdline,	/* command line */
		NULL,	/* process security attributes */
		NULL,	/* primary thread security attributes */
		TRUE,	/* handles are inherited */
		0,	/* creation flags */
		NULL,	/* use parent's environment */
		NULL,	/* use parent's current directory */
		&si,	/* STARTUPINFO pointer */
		&pi) 	/* receives PROCESS_INFORMATION */
	) {
		HANDLE hlist[2] = {c->pipe->o.hEvent, pi.hProcess};
		DWORD ec;
		char str[1];

		if (!ResetEvent(c->pipe->o.hEvent))
			dbg("ResetEvent error - %lu\n", GetLastError());
		if (!ReadFile(c->pipe->h, str, 1, NULL, &c->pipe->o) && GetLastError() != ERROR_IO_PENDING)
			dbg("ReadFile(control_pipe) error - %lu\n", GetLastError());
		ec = WaitForMultipleObjects(2, hlist, FALSE, INFINITE);
		dbg("WaitForMultipleObjects=%lu\n", ec - WAIT_OBJECT_0);
		if (ec != WAIT_OBJECT_0)
			GetExitCodeProcess(pi.hProcess, &ec);
		else
			TerminateProcess(pi.hProcess, ec = 0x1234);
		FlushFileBuffers(c->pout);
		FlushFileBuffers(c->perr);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		hprintf(c->pipe, CMD_RETURN_CODE " %08X\n", ec);
	} else {
		hprintf(c->pipe, "error Creating process(%s) %d\n", cmdline, GetLastError());
	}

	DisconnectNamedPipe(c->perr);
	DisconnectNamedPipe(c->pout);
	DisconnectNamedPipe(c->pin);
finishClosePerr:
	CloseHandle(c->perr);
finishClosePout:
	CloseHandle(c->pout);
finishClosePin:
	CloseHandle(c->pin);
finishCloseToken:
	CloseHandle(c->token);
finish:
	return res;
}

static CMD_ITEM cmd_table[] = {
	{"run", cmd_run},
	{"set", cmd_set},
	{"get", cmd_get},
	{NULL, NULL}
};

typedef struct {
	OV_HANDLE *pipe;
	int conn_number;
} connection_data;

#define MAX_COMMAND_LENGTH (32768)

static VOID handle_connection(connection_data *data)
{
	char *cmd = 0;
	int res;
	connection_context _c, *c = &_c;
	cmd = malloc(MAX_COMMAND_LENGTH);
	if (!cmd) {
		hprintf(data->pipe,
		        "error: unable to allocate buffer for command\n");
		return;
	}
	ZeroMemory(cmd, MAX_COMMAND_LENGTH);
	ZeroMemory(c, sizeof(connection_context));
	c->pipe = data->pipe;
	c->cmd = cmd;
	c->conn_number = data->conn_number;
	free(data);
	/* FIXME make wait for end of process or ctrl_pipe input */
	while (1) {
		res = hgets(cmd, MAX_COMMAND_LENGTH, c->pipe);
		if (res <= 0) {
			dbg("Error reading from pipe(%p)\n", c->pipe->h);
			goto finish;
		}
		dbg("Retrieved line: \"%s\"\n", cmd);
		CMD_ITEM *ci;
		for (ci = cmd_table; ci->name; ++ci) {
			if (strstr(cmd, ci->name) != cmd)
				continue;
			char c = cmd[strlen(ci->name)];
			if (!c || (c == ' '))
				break;
		}
		if (ci->name) {
			if (!ci->func(c))
				goto finish;
		} else {
			hprintf(c->pipe, "error Ignoring unknown command (%s)\n", cmd);
		}
	}
finish:
	FlushFileBuffers(c->pipe->h);
	DisconnectNamedPipe(c->pipe->h);
	CloseHandle(c->pipe->h);
	CloseHandle(c->pipe->o.hEvent);
	free(c->pipe);
	free(cmd);
}

static int conn_number = 0;

DWORD WINAPI winexesvc_loop(LPVOID lpParameter)
{
	BOOL res;

	dbg("server_loop: alive\n");
	if (!CreatePipesSA()) {
		dbg("CreatePipesSA failed (%08lX)\n", GetLastError());
		return -1;
	}
	dbg("server_loop: CreatePipesSA done\n");
	for (;;) {
		dbg("server_loop: Create Pipe\n");
		OV_HANDLE *pipe;
		pipe = (OV_HANDLE *)malloc(sizeof(OV_HANDLE));
		ZeroMemory(&pipe->o, sizeof(OVERLAPPED));
		pipe->o.hEvent = CreateEvent(NULL, TRUE, TRUE, NULL);
		pipe->h = CreateNamedPipe("\\\\.\\pipe\\" PIPE_NAME,
		                          PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
		                          PIPE_WAIT,
		                          PIPE_UNLIMITED_INSTANCES,
		                          BUFSIZE,
		                          BUFSIZE,
		                          NMPWAIT_USE_DEFAULT_WAIT,
		                          &sa);
		if (pipe->h == INVALID_HANDLE_VALUE) {
			dbg("CreatePipe failed(%08lX)\n",
			            GetLastError());
			CloseHandle(pipe->o.hEvent);
			free(pipe);
			return 0;
		}

		dbg("server_loop: Connect Pipe\n");
		if (ConnectNamedPipe(pipe->h, &pipe->o)) {
			dbg("server_loop: Connect Pipe err %08lX\n", GetLastError());
			res = FALSE;
		} else {
			switch (GetLastError()) {
			  case ERROR_IO_PENDING:
				dbg("server_loop: Connect Pipe(0) pending\n");
				DWORD t;
				res = GetOverlappedResult(pipe->h, &pipe->o, &t, TRUE);
				break;
			  case ERROR_PIPE_CONNECTED:
				dbg("server_loop: Connect Pipe(0) connected\n");
				res = TRUE;
				break;
			  default:
				dbg("server_loop: Connect Pipe(0) err %08lX\n", GetLastError());
				res = FALSE;
			}
		}

		if (res) {
			connection_data *cd = malloc(sizeof(connection_data));
			cd->pipe = pipe;
			cd->conn_number = ++conn_number;
			dbg("server_loop: CreateThread\n");
			HANDLE th = CreateThread(NULL,	/* no security attribute */
			                         0,	/* default stack size */
			                         (LPTHREAD_START_ROUTINE)
			                         handle_connection,
			                         (LPVOID) cd,	/* thread parameter */
			                         0,	/* not suspended */
			                         NULL);	/* returns thread ID */
			if (!th) {
				dbg("Cannot create thread\n");
				CloseHandle(pipe->h);
				CloseHandle(pipe->o.hEvent);
				free(pipe);
			} else {
				CloseHandle(th);
				dbg("server_loop: Thread created\n");
			}
		} else {
			dbg("server_loop: Pipe not connected\n");
			CloseHandle(pipe->h);
			CloseHandle(pipe->o.hEvent);
			free(pipe);
		}
	}
	dbg("server_loop: STH wrong\n");
	return 0;
}

static SERVICE_STATUS winexesvcStatus;
static SERVICE_STATUS_HANDLE winexesvcStatusHandle;

static VOID WINAPI winexesvcCtrlHandler(DWORD Opcode)
{
	switch (Opcode) {
	  case SERVICE_CONTROL_PAUSE:
		dbg(SERVICE_NAME ": winexesvcCtrlHandler: pause\n", 0);
		winexesvcStatus.dwCurrentState = SERVICE_PAUSED;
		break;

	  case SERVICE_CONTROL_CONTINUE:
		dbg(SERVICE_NAME ": winexesvcCtrlHandler: continue\n", 0);
		winexesvcStatus.dwCurrentState = SERVICE_RUNNING;
		break;

	  case SERVICE_CONTROL_STOP:
		dbg(SERVICE_NAME ": winexesvcCtrlHandler: stop\n", 0);
		winexesvcStatus.dwWin32ExitCode = 0;
		winexesvcStatus.dwCurrentState = SERVICE_STOPPED;
		winexesvcStatus.dwCheckPoint = 0;
		winexesvcStatus.dwWaitHint = 0;

		if (!SetServiceStatus (winexesvcStatusHandle, &winexesvcStatus))
			dbg(SERVICE_NAME ": SetServiceStatus error %ld\n", GetLastError());

		dbg(SERVICE_NAME ": Leaving winexesvc\n", 0);
		return;

	  case SERVICE_CONTROL_INTERROGATE:
		dbg(SERVICE_NAME ": winexesvcCtrlHandler: interrogate\n", 0);
		break;

	  default:
		dbg(SERVICE_NAME ": Unrecognized opcode %ld\n", Opcode);
	}

	if (!SetServiceStatus(winexesvcStatusHandle, &winexesvcStatus))
		dbg(SERVICE_NAME ": SetServiceStatus error 0x%08X\n", GetLastError());

	return;
}

static DWORD winexesvcInitialization(DWORD argc, LPTSTR * argv, DWORD * specificError)
{
	HANDLE th = CreateThread(NULL, 0, winexesvc_loop, NULL, 0, NULL);
	if (th) {
		CloseHandle(th);
		return NO_ERROR;
	}
	return !NO_ERROR;
}

static void WINAPI winexesvcStart(DWORD argc, LPTSTR * argv)
{
	DWORD status;
	DWORD specificError;

	winexesvcStatus.dwServiceType = SERVICE_WIN32;
	winexesvcStatus.dwCurrentState = SERVICE_START_PENDING;
	winexesvcStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PAUSE_CONTINUE;
	winexesvcStatus.dwWin32ExitCode = 0;
	winexesvcStatus.dwServiceSpecificExitCode = 0;
	winexesvcStatus.dwCheckPoint = 0;
	winexesvcStatus.dwWaitHint = 0;

	dbg(SERVICE_NAME ": RegisterServiceCtrlHandler\n", 0);

	winexesvcStatusHandle = RegisterServiceCtrlHandler(SERVICE_NAME, winexesvcCtrlHandler);

	if (winexesvcStatusHandle == (SERVICE_STATUS_HANDLE) 0) {
		dbg(SERVICE_NAME
		            ": RegisterServiceCtrlHandler failed %d\n",
		            GetLastError());
		return;
	}
	status = winexesvcInitialization(argc, argv, &specificError);

	if (status != NO_ERROR) {
		winexesvcStatus.dwCurrentState = SERVICE_STOPPED;
		winexesvcStatus.dwCheckPoint = 0;
		winexesvcStatus.dwWaitHint = 0;
		winexesvcStatus.dwWin32ExitCode = status;
		winexesvcStatus.dwServiceSpecificExitCode = specificError;

		SetServiceStatus(winexesvcStatusHandle, &winexesvcStatus);
		return;
	}

	winexesvcStatus.dwCurrentState = SERVICE_RUNNING;
	winexesvcStatus.dwCheckPoint = 0;
	winexesvcStatus.dwWaitHint = 0;

	if (!SetServiceStatus(winexesvcStatusHandle, &winexesvcStatus)) {
		status = GetLastError();
		dbg(SERVICE_NAME ": SetServiceStatus error %ld\n", status);
	}

	dbg(SERVICE_NAME ": Returning the Main Thread \n", 0);

	return;
}

int main(int argc, char *argv[])
{
	SERVICE_TABLE_ENTRY DispatchTable[] = {
		{SERVICE_NAME, winexesvcStart},
		{NULL, NULL}
	};

	dbg(SERVICE_NAME ": StartServiceCtrlDispatcher %d\n", GetLastError());
	if (!StartServiceCtrlDispatcher(DispatchTable)) {
		dbg(SERVICE_NAME
		": StartServiceCtrlDispatcher (%d)\n",
		GetLastError());
	}
	return 0;
}
