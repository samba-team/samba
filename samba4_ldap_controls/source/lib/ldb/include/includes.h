/*
  a temporary includes file until I work on the ldb build system
*/

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "config.h"
#include <stdio.h>
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
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "ldb.h"
#include "ldb_private.h"
#include "talloc.h"

#define discard_const(ptr) ((void *)((intptr_t)(ptr)))
#define discard_const_p(type, ptr) ((type *)discard_const(ptr))
