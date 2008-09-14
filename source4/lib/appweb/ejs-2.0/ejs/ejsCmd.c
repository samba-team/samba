/*
 *	@file 	ejsCmd.c
 *	@brief 	Embedded JavaScript (EJS) command line program.
 *	@overview 
 */
/********************************* Copyright **********************************/
/*
 *	@copy	default
 *	
 *	Copyright (c) Mbedthis Software LLC, 2003-2006. All Rights Reserved.
 *	Copyright (c) Michael O'Brien, 1994-1995. All Rights Reserved.
 *	
 *	This software is distributed under commercial and open source licenses.
 *	You may use the GPL open source license described below or you may acquire 
 *	a commercial license from Mbedthis Software. You agree to be fully bound 
 *	by the terms of either license. Consult the LICENSE.TXT distributed with 
 *	this software for full details.
 *	
 *	This software is open source; you can redistribute it and/or modify it 
 *	under the terms of the GNU General Public License as published by the 
 *	Free Software Foundation; either version 2 of the License, or (at your 
 *	option) any later version. See the GNU General Public License for more 
 *	details at: http://www.mbedthis.com/downloads/gplLicense.html
 *	
 *	This program is distributed WITHOUT ANY WARRANTY; without even the 
 *	implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
 *	
 *	This GPL license does NOT permit incorporating this software into 
 *	proprietary programs. If you are unable to comply with the GPL, you must
 *	acquire a commercial license to use this software. Commercial licenses 
 *	for this software and support services are available from Mbedthis 
 *	Software at http://www.mbedthis.com 
 *	
 *	@end
 */
/********************************** Includes **********************************/

#include	"ejs.h"

#if BLD_FEATURE_EJS && !BREW

/************************************ Defines *********************************/

#define EJS_MAX_CMD_LINE	(16 * 1024)
#define EJS_MAX_SCRIPT		(4 * 1024 * 1024)
#define EJS_MAX_RESULT_SIZE	(4 * 1024 * 1024)
#define EJS_PROMPT			"ejs> "

/****************************** Forward Declarations **************************/

static int 	parseFile(EjsService *ejsService, Ejs *ejs, const char *fileName, 
	const char *testName, MprFile *testLogFile);
static int	ifConsole();

static int	interactiveUse(MprApp *app, Ejs *ejs, FILE *input, 
				char *fileName);
static char *readCmd(MprApp *app, FILE *input);

static int 	memoryFailure(MprApp *app, uint size, uint total, bool granted);

static int	isConsole = 0;
static int	traceCmds = 0;
static int	stats = 0;
static int	verbose = 0;

/************************************ Main ************************************/

int main(int argc, char *argv[]) 
{
	MprApp			*app;
	const char		*programName;
	MprFile			*testLogFile;
	EjsService		*ejsService;
	Ejs				*ejs;
	char 			*commandLine;
	const char		*testName;
	char			*argp, *cmd, *testLog;
	int				i, rc, nextArg, err, len, firstArg, iterations, debugLevel;

	app = mprInit(memoryFailure);

	isConsole = ifConsole();
	programName = mprGetBaseName(argv[0]);
	debugLevel = 0;

	ejsService = ejsOpenService(app);
	if (ejsService == 0) {
		mprError(app, MPR_LOC, "Can't initialize the EJS service.");
		return -1;
	}

	err = 0;
	iterations = 1;
	stats = 0;
	testLog = getenv("TEST_LOG");
	testLogFile = 0;
	testName = 0;

	for (nextArg = 1; nextArg < argc; nextArg++) {
		argp = argv[nextArg];
		if (*argp != '-') {
			break;
		}
		if (strcmp(argp, "--debug") == 0) {
			if (nextArg >= argc) {
				err++;
			} else {
				debugLevel = atoi(argv[++nextArg]);
			}

		} else if (strcmp(argp, "--stats") == 0) {
			stats++;

		} else if (strcmp(argp, "--trace") == 0) {
			traceCmds++;

		} else if (strcmp(argp, "--iterations") == 0) {
			if (nextArg >= argc) {
				err++;
			} else {
				iterations = atoi(argv[++nextArg]);
			}

		} else if (strcmp(argp, "--log") == 0) {
			/* Get file to log test results to when using ejs as a test shell */
			if (nextArg >= argc) {
				err++;
			} else {
				testLog = argv[++nextArg];
			}

		} else if (strcmp(argp, "--testName") == 0) {
			if (nextArg >= argc) {
				err++;
			} else {
				testName = argv[++nextArg];
			}

		} else if (strcmp(argp, "-v") == 0) {
			verbose++;

		} else if (strcmp(argp, "-vv") == 0) {
			verbose += 2;

		} else if (strcmp(argp, "--verbose") == 0) {
			verbose += 2;

		} else {
			err++;
			break;
		}
		if (err) {
			mprErrorPrintf(app, 
				"Usage: %s [options] files...   or\n"
				"       %s < file               or\n"
				"       %s                      or\n"
				"  Switches:\n"
				"    --iterations num     # Number of iterations to eval file\n"
				"    --stats              # Output stats on exit\n"
				"    --testName name      # Set the test name",
				programName, programName, programName);
			return -1;
		}
	}

	if (testName) {
		i = 0;
		commandLine = 0;
		len = mprAllocStrcat(MPR_LOC_ARGS(app), &commandLine, 0, " ", 
			mprGetBaseName(argv[i++]), NULL);
		for (; i < argc; i++) {
			len = mprReallocStrcat(MPR_LOC_ARGS(app), &commandLine, 0, len, 
				" ", argv[i], NULL);
		}
		mprPrintf(app, "  %s\n", commandLine);
	}
	if (testLog) {
		testLogFile = mprOpen(app, testLog, 
			O_CREAT | O_APPEND | O_WRONLY | O_TEXT, 0664);
		if (testLogFile == 0) {
			mprError(app, MPR_LOC, "Can't open %s", testLog);
			return MPR_ERR_CANT_OPEN;
		}
		mprFprintf(testLogFile, "\n  %s\n", commandLine);
	}

	ejs = ejsCreateInterp(ejsService, 0, 0, 0, 0);
	if (ejs == 0) {
		mprError(app, MPR_LOC, "Can't create EJS interpreter");
		ejsCloseService(ejsService, stats);
		if (testLogFile) {
			mprClose(testLogFile);
		}
		mprTerm(app, stats);
		exit(-1);
	}

	if (debugLevel > 0) {
		ejsSetGCDebugLevel(ejs, debugLevel);
	}

	rc = 0;

	if (nextArg < argc) {
		/*
 		 *	Process files supplied on the command line
		 */
		firstArg = nextArg;
		for (i = 0; i < iterations; i++) {
			for (nextArg = firstArg; nextArg < argc; nextArg++) {
				rc = parseFile(ejsService, ejs, argv[nextArg], testName, 
					testLogFile);
				if (rc < 0) {
					return rc;
				}
			}
		}
		if (testName) {
			if (verbose == 1) {
				mprPrintf(app, "\n");
			} 
			if (verbose <= 1) {
				mprPrintf(app, "  # PASSED all tests for \"%s\"\n", testName);
			}
		}

	} else if (! isConsole) {
		/*
		 *	Read a script from stdin
		 */
		cmd = readCmd(app, stdin);

		ejsSetFileName(ejs, "stdin");

		rc = ejsEvalScript(ejs, cmd, 0);
		if (rc < 0) {
			mprPrintf(app, "ejs: Error: %s\n", ejsGetErrorMsg(ejs));
		}
		mprFree(cmd);

	} else {
		/*
		 *	Interactive use. Read commands from the command line.
		 */
		rc = interactiveUse(app, ejs, stdin, "stdin");
	}

	/*
	 *	Cleanup. Do stats if required.
 	 */
	if (ejs) {
		ejsCleanInterp(ejs, 0);
		ejsCleanInterp(ejs->service->master, 0);
		ejsDestroyInterp(ejs, 0);
	}

	ejsCloseService(ejsService, stats);

	if (testLogFile) {
		mprClose(testLogFile);
	}

	mprTerm(app, stats);
	return rc;
}

/******************************************************************************/

static int parseFile(EjsService *ejsService, Ejs *ejs, const char *fileName, 
	const char *testName, MprFile *testLogFile)
{
	int		rc;

	if (testName && verbose == 1) {
		mprPrintf(ejs, ".");
	}
	if (verbose > 1) {
		mprPrintf(ejs, "File: %s\n", fileName);
	}

	rc = ejsEvalFile(ejs, fileName, 0);

	if (testName) {
		char 	fileBuf[MPR_MAX_FNAME], *cp;
		mprStrcpy(fileBuf, sizeof(fileBuf), fileName);
		if ((cp = strstr(fileBuf, ".ejs")) != 0) {
			*cp = '\0';
		}
		if (rc == 0) {
			if (verbose > 1) {
				mprPrintf(ejs, "  # PASSED test \"%s.%s\"\n", testName, 
					fileBuf);
			}
			if (testLogFile) {
				mprFprintf(testLogFile, "  # PASSED test \"%s.%s\"\n", 
					testName, fileBuf);
			}

		} else {

			mprPrintf(ejs, "FAILED test \"%s.%s\"\nDetails: %s\n", 
				testName, fileBuf, ejsGetErrorMsg(ejs));

			if (testLogFile) {
				mprFprintf(testLogFile, 
					"FAILED test \"%s.%s\"\nDetails: %s\n", 
					testName, fileBuf, ejsGetErrorMsg(ejs));
			}
		}
	} else if (rc < 0) {
		mprPrintf(ejs, "ejs: %sIn file \"%s\"\n", 
			ejsGetErrorMsg(ejs), fileName);
	}
	return rc;
}

/******************************************************************************/

static char *readCmd(MprApp *app, FILE *input)
{
	char	line[EJS_MAX_CMD_LINE];
	char	*cmd;
	int		len, cmdLen;

	cmd = 0;
	cmdLen = 0;

	line[sizeof(line) - 1] = '\0';

	while (1) {

		if (fgets(line, sizeof(line) - 1, input) == NULL) {
			break;
		}

		len = strlen(line);

		if (line[len - 1] == '\\') {
			line[len - 1] = '\0';
		}
		cmdLen = mprReallocStrcat(MPR_LOC_ARGS(app), &cmd, EJS_MAX_SCRIPT, 
			cmdLen, 0, line, NULL);
	}
	return cmd;
}

/******************************************************************************/

static int interactiveUse(MprApp *app, Ejs *ejs, FILE *input, char *fileName)
{
	EjsVar	result;
	char	line[EJS_MAX_CMD_LINE];
	char	*cmd, *buf;
	int		len, cmdLen, rc;

	cmd = 0;
	cmdLen = 0;

	line[sizeof(line) - 1] = '\0';

	ejsSetFileName(ejs, "console");

	while (! ejsIsExiting(ejs)) {

		if (isConsole) {
			write(1, EJS_PROMPT, strlen(EJS_PROMPT));
		}

		if (fgets(line, sizeof(line) - 1, input) == NULL) {
			break;
		}

		len = strlen(line);
		while (len > 0 && 
				(line[len - 1] == '\n' || line[len - 1] == '\r')) {
			len--;
			line[len] = '\0';
		}

		if (line[len - 1] == '\\') {
			line[len - 1] = '\0';
			cmdLen = mprReallocStrcat(MPR_LOC_ARGS(app), &cmd, EJS_MAX_SCRIPT, 
				cmdLen, 0, line, NULL);

		} else {

			cmdLen = mprReallocStrcat(MPR_LOC_ARGS(app), &cmd, EJS_MAX_SCRIPT, 
				cmdLen, 0, line, NULL);
			

			if (traceCmds) {
				mprPrintf(ejs, "# %s\n", cmd);
			}

			if (cmd[0] == 0x4 || cmd[0] == 0x26 || strcmp(cmd, "quit") == 0) {
				ejsExit(ejs, 0);

			} else if ((rc = ejsEvalScript(ejs, cmd, &result)) < 0) {

				mprPrintf(app, "ejs: Error: %s\n", ejsGetErrorMsg(ejs));

				if (! isConsole) {
					return rc;
				}

			} else {
				if (isConsole || traceCmds) {
					buf = ejsVarToString(ejs, &result);
					mprPrintf(ejs, "%s\n", buf);
				}
			}
			mprFree(cmd);
			cmd = 0;
			cmdLen = 0;
		}
	}
	return 0;
}

/******************************************************************************/

static int ifConsole()
{
#if WIN
	INPUT_RECORD	irec[1];
	int				records = 0;

	if (PeekConsoleInput(GetStdHandle(STD_INPUT_HANDLE), irec, 1, 
			&records) != 0) {
		return 1;
	}
#else
	return isatty(0);
#endif
	return 0;
}

/******************************************************************************/

static int memoryFailure(MprApp *app, uint size, uint total, bool granted)
{
	if (!granted) {
		mprPrintf(app, "Can't allocate memory block of size %d\n", size);
		mprPrintf(app, "Total memory used %d\n", total);
		exit(255);
	}
	mprPrintf(app, "Memory request for %d bytes exceeds memory red-line\n",
		size);
	mprPrintf(app, "Total memory used %d\n", total);
	return 0;
}

/******************************************************************************/

#else
void ejsCmdLineDummy() {}

/******************************************************************************/
#endif /* BLD_FEATURE_EJS */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
