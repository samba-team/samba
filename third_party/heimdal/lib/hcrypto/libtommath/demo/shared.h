#include <string.h>
#include <stdlib.h>
#include <time.h>

/*
 * Configuration
 */
#ifndef LTM_DEMO_TEST_REDUCE_2K_L
/* This test takes a moment so we disable it by default, but it can be:
 * 0 to disable testing
 * 1 to make the test with P = 2^1024 - 0x2A434 B9FDEC95 D8F9D550 FFFFFFFF FFFFFFFF
 * 2 to make the test with P = 2^2048 - 0x1 00000000 00000000 00000000 00000000 4945DDBF 8EA2A91D 5776399B B83E188F
 */
#define LTM_DEMO_TEST_REDUCE_2K_L 0
#endif

#define MP_WUR /* TODO: result checks disabled for now */
#include "tommath_private.h"

extern void ndraw(mp_int* a, const char* name);
extern void print_header(void);
