#ifdef HAVE_CONFIG_H
#include <config.h>
RCSID("$Id$");
#endif

#include <signal.h>

/*
 * We would like to always use this signal but there is a link error
 * on NEXTSTEP
 */
#ifndef NeXT
/*
 * Bugs:
 *
 * Do we need any extra hacks for SIGCLD and/or SIGCHLD?
 */

typedef RETSIGTYPE (*SigAction)(/* int??? */);

SigAction
signal(int iSig, SigAction pAction)
{
    struct sigaction saNew, saOld;

    saNew.sa_handler = pAction;
    sigemptyset(&saNew.sa_mask);
    saNew.sa_flags = 0;

    if (iSig == SIGALRM)
	{
#ifdef SA_INTERRUPT
	    saNew.sa_flags |= SA_INTERRUPT;
#endif
	}
    else
	{
#ifdef SA_RESTART
	    saNew.sa_flags |= SA_RESTART;
#endif
	}

    if (sigaction(iSig, &saNew, &saOld) < 0)
	return(SIG_ERR);

    return(saOld.sa_handler);
}
#endif
