#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "roken.h"

#ifndef HAVE_HSTRERROR

#include <stdio.h>
#include <netdb.h>

static char *msg[] = {
  "No error",
  "Authoritative Answer Host not found",
  "Non-Authoritive Host not found, or SERVERFAIL",
  "Non recoverable errors, FORMERR, REFUSED, NOTIMP",
  "Valid name, no data record of requested type"
};

char *hstrerror(int herr)
{
  if(herr >= 0 && herr <= 4)
    return msg[herr];
  return "Error number out of range (hstrerror)";
}

#endif

