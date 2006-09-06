#ifndef _LDB_PRIVATE_INCLUDES_H_
#define _LDB_PRIVATE_INCLUDES_H_
/*
  a temporary includes file until I work on the ldb build system
*/

#ifdef _SAMBA_BUILD_
/* tell ldb we have the internal ldap code */
#define HAVE_ILDAP 1
#endif

#define discard_const(ptr) ((void *)((intptr_t)(ptr)))
#define discard_const_p(type, ptr) ((type *)discard_const(ptr))

#include "replace.h"
#include "system/filesys.h"
#include "system/network.h"
#include "system/time.h"
#include "talloc.h"
#include "ldb.h"
#include "ldb_errors.h"
#include "ldb_private.h"
#include "dlinklist.h"

#endif /*_LDB_PRIVATE_INCLUDES_H_*/
