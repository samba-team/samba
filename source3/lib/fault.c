/* 
   Unix SMB/CIFS implementation.
   Critical Fault handling
   Copyright (C) Andrew Tridgell 1992-1998
   
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

#include "includes.h"

#ifdef HAVE_SYS_PRCTL_H
#include <sys/prctl.h>
#endif

static void (*cont_fn)(void *);
static char *corepath;

/*******************************************************************
report a fault
********************************************************************/
static void fault_report(int sig)
{
	static int counter;

	if (counter) _exit(1);

	counter++;

	DEBUGSEP(0);
	DEBUG(0,("INTERNAL ERROR: Signal %d in pid %d (%s)",sig,(int)sys_getpid(),samba_version_string()));
	DEBUG(0,("\nPlease read the Trouble-Shooting section of the Samba3-HOWTO\n"));
	DEBUG(0,("\nFrom: http://www.samba.org/samba/docs/Samba3-HOWTO.pdf\n"));
	DEBUGSEP(0);
  
	smb_panic("internal error");

	if (cont_fn) {
		cont_fn(NULL);
#ifdef SIGSEGV
		CatchSignal(SIGSEGV,SIGNAL_CAST SIG_DFL);
#endif
#ifdef SIGBUS
		CatchSignal(SIGBUS,SIGNAL_CAST SIG_DFL);
#endif
#ifdef SIGABRT
		CatchSignal(SIGABRT,SIGNAL_CAST SIG_DFL);
#endif
		return; /* this should cause a core dump */
	}
	exit(1);
}

/****************************************************************************
catch serious errors
****************************************************************************/
static void sig_fault(int sig)
{
	fault_report(sig);
}

/*******************************************************************
setup our fault handlers
********************************************************************/
void fault_setup(void (*fn)(void *))
{
	cont_fn = fn;

#ifdef SIGSEGV
	CatchSignal(SIGSEGV,SIGNAL_CAST sig_fault);
#endif
#ifdef SIGBUS
	CatchSignal(SIGBUS,SIGNAL_CAST sig_fault);
#endif
#ifdef SIGABRT
	CatchSignal(SIGABRT,SIGNAL_CAST sig_fault);
#endif
}

/**
 * Build up the default corepath as "<logbase>/cores/<progname>"
 */
static char *get_default_corepath(const char *logbase, const char *progname)
{
	char *tmp_corepath;

	/* Setup core dir in logbase. */
	tmp_corepath = talloc_asprintf(NULL, "%s/cores", logbase);
	if (!tmp_corepath)
		return NULL;

	if ((mkdir(tmp_corepath, 0700) == -1) && errno != EEXIST)
		goto err_out;

	if (chmod(tmp_corepath, 0700) == -1)
		goto err_out;

	talloc_free(tmp_corepath);

	/* Setup progname-specific core subdir */
	tmp_corepath = talloc_asprintf(NULL, "%s/cores/%s", logbase, progname);
	if (!tmp_corepath)
		return NULL;

	if (mkdir(tmp_corepath, 0700) == -1 && errno != EEXIST)
		goto err_out;

	if (chown(tmp_corepath, getuid(), getgid()) == -1)
		goto err_out;

	if (chmod(tmp_corepath, 0700) == -1)
		goto err_out;

	return tmp_corepath;

 err_out:
	talloc_free(tmp_corepath);
	return NULL;
}

/*******************************************************************
make all the preparations to safely dump a core file
********************************************************************/

void dump_core_setup(const char *progname)
{
	char *logbase = NULL;
	char *end = NULL;

	if (lp_logfile() && *lp_logfile()) {
		if (asprintf(&logbase, "%s", lp_logfile()) < 0) {
			return;
		}
		if ((end = strrchr_m(logbase, '/'))) {
			*end = '\0';
		}
	} else {
		/* We will end up here if the log file is given on the command
		 * line by the -l option but the "log file" option is not set
		 * in smb.conf.
		 */
		if (asprintf(&logbase, "%s", get_dyn_LOGFILEBASE()) < 0) {
			return;
		}
	}

	SMB_ASSERT(progname != NULL);

	corepath = get_default_corepath(logbase, progname);
	if (!corepath) {
		DEBUG(0, ("Unable to setup corepath for %s: %s\n", progname,
			  strerror(errno)));
		goto out;
	}


#ifdef HAVE_GETRLIMIT
#ifdef RLIMIT_CORE
	{
		struct rlimit rlp;
		getrlimit(RLIMIT_CORE, &rlp);
		rlp.rlim_cur = MAX(16*1024*1024,rlp.rlim_cur);
		setrlimit(RLIMIT_CORE, &rlp);
		getrlimit(RLIMIT_CORE, &rlp);
		DEBUG(3,("Maximum core file size limits now %d(soft) %d(hard)\n",
			 (int)rlp.rlim_cur,(int)rlp.rlim_max));
	}
#endif
#endif

#if defined(HAVE_PRCTL) && defined(PR_SET_DUMPABLE)
	/* On Linux we lose the ability to dump core when we change our user
	 * ID. We know how to dump core safely, so let's make sure we have our
	 * dumpable flag set.
	 */
	prctl(PR_SET_DUMPABLE, 1);
#endif

	/* FIXME: if we have a core-plus-pid facility, configurably set
	 * this up here.
	 */
 out:
	SAFE_FREE(logbase);
}

 void dump_core(void)
{
	static bool called;

	if (called) {
		DEBUG(0, ("dump_core() called recursive\n"));
		exit(1);
	}
	called = true;

	/* Note that even if core dumping has been disabled, we still set up
	 * the core path. This is to handle the case where core dumping is
	 * turned on in smb.conf and the relevant daemon is not restarted.
	 */
	if (!lp_enable_core_files()) {
		DEBUG(0, ("Exiting on internal error (core file administratively disabled)\n"));
		exit(1);
	}

#if DUMP_CORE
	/* If we're running as non root we might not be able to dump the core
	 * file to the corepath.  There must not be an unbecome_root() before
	 * we call abort(). */
	if (geteuid() != 0) {
		become_root();
	}

	if (corepath == NULL) {
		DEBUG(0, ("Can not dump core: corepath not set up\n"));
		exit(1);
	}

	if (*corepath != '\0') {
		/* The chdir might fail if we dump core before we finish
		 * processing the config file.
		 */
		if (chdir(corepath) != 0) {
			DEBUG(0, ("unable to change to %s\n", corepath));
			DEBUGADD(0, ("refusing to dump core\n"));
			exit(1);
		}

		DEBUG(0,("dumping core in %s\n", corepath));
	}

	umask(~(0700));
	dbgflush();

	/* Ensure we don't have a signal handler for abort. */
#ifdef SIGABRT
	CatchSignal(SIGABRT,SIGNAL_CAST SIG_DFL);
#endif

	abort();

#else /* DUMP_CORE */
	exit(1);
#endif /* DUMP_CORE */
}

