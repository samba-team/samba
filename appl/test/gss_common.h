/* $Id$ */

#include "test_locl.h"
#include <gssapi.h>
RCSID("$Id$");

void write_token (int sock, gss_buffer_t buf);
void read_token (int sock, gss_buffer_t buf);
