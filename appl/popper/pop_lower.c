/*
 * Copyright (c) 1989 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#if 0
static char copyright[] = "Copyright (c) 1990 Regents of the University of California.\nAll rights reserved.\n";
static char SccsId[] = "@(#)@(#)pop_lower.c	2.1  2.1 3/18/91";
#endif /* not lint */

#include <popper.h>

/* 
 *  lower:  Convert a string to lowercase
 */

void
pop_lower (char *buf)
{
    char        *   mp;

    for (mp = buf; *mp; mp++)
        if (isupper(*mp) && isupper(*mp)) *mp = (char)tolower((int)*mp);
}
