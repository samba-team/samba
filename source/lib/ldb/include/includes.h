/*
  a temporary includes file until I work on the ldb build system
*/

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
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
#include "ldb.h"
#include "ldb_parse.h"

#define malloc_p(type) (type *)malloc(sizeof(type))
#define malloc_array_p(type, count) (type *)realloc_array(NULL, sizeof(type), count)
#define realloc_p(p, type, count) (type *)realloc_array(p, sizeof(type), count)

#include "tdb/tdb.h"
#include "proto.h"
