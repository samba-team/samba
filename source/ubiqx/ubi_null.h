#ifndef UBI_NULL_H
#define UBI_NULL_H
/* ========================================================================== **
 *                                 ubi_null.h
 *
 *  Copyright (C) 1998 by Christopher R. Hertel
 *
 *  Email: crh@ubiqx.mn.org
 * -------------------------------------------------------------------------- **
 *  This header provides declarations and data types used internally by the
 *  ubiqx modules.  It is not intended to be included elsewhere.
 * -------------------------------------------------------------------------- **
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Library General Public
 *  License as published by the Free Software Foundation; either
 *  version 2 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Library General Public License for more details.
 *
 *  You should have received a copy of the GNU Library General Public
 *  License along with this library; if not, write to the Free
 *  Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * -------------------------------------------------------------------------- **
 *
 *  You don't need this in your code.  It is used by the ubi_*.c files.
 *  At present, its only purpose is to provide a definition of NULL.
 *  Read on...
 *
 * -------------------------------------------------------------------------- **
 *
 * Log: ubi_null.h,v 
 * Revision 0.0  1998/05/20 04:38:38  crh
 * Initial Revision.
 *
 * ========================================================================== **
 */

/* -------------------------------------------------------------------------- **
 *  Looking for NULL.
 *
 *  The core ubiqx modules (all those beginning with 'ubi_') rely on very
 *  little from the outside world.  One exception is that we need a
 *  defintion for NULL.  This has turned out to be something of a problem,
 *  as NULL is NOT always defined in the same place on different systems.
 *
 *  Ahh... standards...
 *
 *  K&R 2nd Ed. (pg 102) says NULL should be in <stdio.h>.  I've heard
 *  that it is in <locale.h> on some systems.  I've also seen it in
 *  <stddef.h> and <stdlib.h>.  In most cases it's defined in multiple
 *  places.  We'll try several of them.  If none of these work on your
 *  system, please send E'mail and let me know where you get your NULL!
 *
 *  The purpose of the mess below, then, is simply to supply a definition
 *  of NULL to the ubi_*.c files.  Keep in mind that C compilers (all
 *  those of which I'm aware) will allow you to define a constant on the
 *  command line, eg.: -DNULL=((void *)0).
 *
 *  Also, 99.9% of the time, NULL is zero.  I have been informed of at
 *  least one exception.
 *
 *  crh; may 1998
 */

#ifndef NULL
#include <stddef.h>
#endif

#ifndef NULL
#include <stdlib.h>
#endif

#ifndef NULL
#include <stdio.h>
#endif

#ifndef NULL
#include <locale.h>
#endif

#ifndef NULL
#define NULL ((void *)0)
#endif

/* ================================ The End ================================= */
#endif /* UBI_NULL_H */

