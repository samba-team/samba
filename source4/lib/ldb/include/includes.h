/*
  a temporary includes file until I work on the ldb build system
*/

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdarg.h>
#include <signal.h>
#include <unistd.h>
#include <fnmatch.h>
#include <sys/time.h>
#include <time.h>
#include <stdint.h>

#include "ldb.h"
#include "ldb_private.h"
#include "talloc.h"

#if defined(__intptr_t_defined) || defined(HAVE_INTPTR_T)
#define discard_const(ptr) ((void *)((intptr_t)(ptr)))
#else
#define discard_const(ptr) ((void *)(ptr))
#endif
#define discard_const_p(type, ptr) ((type *)discard_const(ptr))
