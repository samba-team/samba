/* $Id$ */

#include <stddef.h>
#include <time.h>

#ifndef __asn1_common_definitions__
#define __asn1_common_definitions__

typedef struct octet_string {
    size_t length;
    void *data;
} octet_string;

typedef char *general_string;

#endif
