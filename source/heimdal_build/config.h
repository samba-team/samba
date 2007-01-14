/*
  this is a replacement config.h for building the heimdal parts of the
  Samba source tree
*/

#ifndef HAVE_HEIMDAL_CONFIG_H
#define HAVE_HEIMDAL_CONFIG_H

#include "include/config.h"
#include "lib/replace/replace.h"

#define RCSID(msg)
#define KRB5

/* This needs to be defined for roken too */
#ifdef VOID_RETSIGTYPE
#define SIGRETURN(x) return
#else
#define SIGRETURN(x) return (RETSIGTYPE)(x)
#endif

#endif
