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


#ifndef _PRINTF_ATTRIBUTE
#define _PRINTF_ATTRIBUTE(a,b)
#endif

#include "ldb.h"
#include "tdb.h"
#include "proto.h"

#ifdef HAVE_INTPTR_T
#define discard_const(ptr) ((void *)((intptr_t)(ptr)))
#else
#define discard_const(ptr) ((void *)(ptr))
#endif
#define discard_const_p(type, ptr) ((type *)discard_const(ptr))


