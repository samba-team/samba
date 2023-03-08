/*
 * Copyright (c) 1999 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Timeval stuff
 */

#include <config.h>

#include "roken.h"

ROKEN_LIB_FUNCTION time_t ROKEN_LIB_CALL
rk_time_add(time_t t, time_t delta)
{
    if (delta == 0)
        return t;

#ifdef TIME_T_SIGNED
    /* Signed overflow is UB in C */
#if SIZEOF_TIME_T == 4
    if (t >= 0 && delta > 0 && INT32_MAX - t < delta)
        /* Time left to hit INT32_MAX is less than what we want to add */
        return INT32_MAX;
    else if (t == INT32_MIN && delta < 0)
        /* Avoid computing -t when t == INT32_MIN! */
        return INT32_MIN;
    else if (t < 0 && delta < 0 && INT32_MIN + (-t) > delta)
        /* Time left to hit INT32_MIN is less than what we want to subtract */
        return INT32_MIN;
    else
        return t + delta;
#elif SIZEOF_TIME_T == 8
    if (t >= 0 && delta > 0 && INT64_MAX - t < delta)
        return INT64_MAX;
    else if (t == INT64_MIN && delta < 0)
        /* Avoid computing -t when t == INT64_MIN! */
        return INT64_MIN;
    else if (t < 0 && delta < 0 && INT64_MIN + (-t) > delta)
        return INT64_MIN;
    else
        return t + delta;
#else
#error "Unexpected sizeof(time_t)"
#endif
#else

    /* Unsigned overflow is defined in C */
#if SIZEOF_TIME_T == 4
    if (t + delta < t)
        return UINT32_MAX;
#elif SIZEOF_TIME_T == 8
    if (t + delta < t)
        return UINT64_MAX;
#else
#error "Unexpected sizeof(time_t)"
#endif
    return t + delta;
#endif
}

ROKEN_LIB_FUNCTION time_t ROKEN_LIB_CALL
rk_time_sub(time_t t, time_t delta)
{
    if (delta == 0)
        return t;
#ifdef TIME_T_SIGNED
    if (delta > 0)
        return rk_time_add(t, -delta);
#if SIZEOF_TIME_T == 4
    if (delta == INT32_MIN) {
        if (t < 0) {
            t = t + INT32_MAX;
            return t + 1;
        }
        return INT32_MAX;
    }
    /* Safe to compute -delta, so use rk_time_add() to add -delta */
    return rk_time_add(t, -delta);
#elif SIZEOF_TIME_T == 8
    if (delta == INT64_MIN) {
        if (t < 0) {
            t = t + INT64_MAX;
            return t + 1;
        }
        return INT64_MAX;
    }
    return rk_time_add(t, -delta);
#else
#error "Unexpected sizeof(time_t)"
#endif
#else
    /* Both t and delta are non-negative. */
    if (delta > t)
        return 0;
    return t - delta;
#endif
}

/*
 * Make `t1' consistent.
 */

ROKEN_LIB_FUNCTION void ROKEN_LIB_CALL
timevalfix(struct timeval *t1)
{
    if (t1->tv_usec < 0) {
        t1->tv_sec = rk_time_sub(t1->tv_sec, 1);
        t1->tv_usec = 1000000;
    }
    if (t1->tv_usec >= 1000000) {
        t1->tv_sec = rk_time_add(t1->tv_sec, 1);
        t1->tv_usec -= 1000000;
    }
}

/*
 * t1 += t2
 */

ROKEN_LIB_FUNCTION void ROKEN_LIB_CALL
timevaladd(struct timeval *t1, const struct timeval *t2)
{
    t1->tv_sec   = rk_time_add(t1->tv_sec, t2->tv_sec);
    t1->tv_usec += t2->tv_usec;
    timevalfix(t1);
}

/*
 * t1 -= t2
 */

ROKEN_LIB_FUNCTION void ROKEN_LIB_CALL
timevalsub(struct timeval *t1, const struct timeval *t2)
{
    t1->tv_sec   = rk_time_sub(t1->tv_sec, t2->tv_sec);
    t1->tv_usec -= t2->tv_usec;
    timevalfix(t1);
}

#ifdef TEST
int
main(int argc, char **argv)
{
    time_t t, delta, r;
    int e = 0;

    if (argc == 0)
        return 0; /* Apparently POSIX and Linux allow this case */

    argc--;
    argv++;

    while (argc > 0) {
        int64_t n;
        time_t a;
        char *ends;

        if (argc < 3)
            errx(1, "Usage: [TIME +|- DELTA [== TIME]]");

        errno = 0;
        n = strtoll(argv[0], &ends, 0);
        if (errno)
            err(1, "Time value is invalid");
        if (*ends != '\0')
            errx(1, "Time value is invalid");
        t = n;

        n = strtoll(argv[2], &ends, 0);
        if (errno)
            err(1, "Delta value is invalid");
        if (*ends != '\0')
            errx(1, "Delta value is invalid");
        delta = n;

        if (argv[1][0] == '+' && argv[1][1] == '\0')
            r = rk_time_add(t, delta);
        else if (argv[1][0] == '-' && argv[1][1] == '\0')
            r = rk_time_sub(t, delta);
        else
            errx(1, "Operator must be a + or a - arithmetic operator");

        if (delta == 0 && r != t) {
            warnx("%s %s %s != %s!", argv[0], argv[1], argv[2], argv[0]);
            e = 1;
        }
        if (t == 0 && r != delta) {
            warnx("%s %s %s != %s!", argv[0], argv[1], argv[2], argv[2]);
            e = 1;
        }

        if (argc > 4 && strcmp(argv[3], "==") == 0) {
            n = strtoll(argv[4], &ends, 0);
            if (errno)
                err(1, "Time value is invalid");
            if (*ends != '\0')
                errx(1, "Time value is invalid");
            a = n;
            if (a != r) {
                warnx("%s %s %s != %s!", argv[0], argv[1], argv[2], argv[4]);
                e = 1;
            }
            argc -= 5;
            argv += 5;
        } else {
#ifdef TIME_T_SIGNED
            printf("%s %s %s == %lld\n", argv[0], argv[1], argv[2],
                   (long long)r);
#else
            printf("%s %s %s == %llu\n", argv[0], argv[1], argv[2],
                   (unsigned long long)r);
#endif
            argc -= 3;
            argv += 3;
        }
    }

#define CHECK(e) do { if (!(e)) errx(1, "Expression not true: " #e "!"); } while (0)
#ifdef TIME_T_SIGNED
#if SIZEOF_TIME_T == 4
    CHECK(rk_time_add(INT32_MIN, -1) == INT32_MIN);
    CHECK(rk_time_sub(INT32_MIN,  1) == INT32_MIN);
    CHECK(rk_time_sub(-1, INT32_MAX) == INT32_MIN);
    CHECK(rk_time_add(INT32_MAX,  0) == INT32_MAX);
    CHECK(rk_time_add(INT32_MAX,  1) == INT32_MAX);
    CHECK(rk_time_add(1,  INT32_MAX) == INT32_MAX);
    CHECK(rk_time_add(0,  INT32_MAX) == INT32_MAX);
#elif SIZEOF_TIME_T == 8
    CHECK(rk_time_add(INT64_MIN, -1) == INT64_MIN);
    CHECK(rk_time_sub(INT64_MIN,  1) == INT64_MIN);
    CHECK(rk_time_sub(-1, INT64_MAX) == INT64_MIN);
    CHECK(rk_time_add(INT64_MAX,  0) == INT64_MAX);
    CHECK(rk_time_add(INT64_MAX,  1) == INT64_MAX);
    CHECK(rk_time_add(1,  INT64_MAX) == INT64_MAX);
    CHECK(rk_time_add(0,  INT64_MAX) == INT64_MAX);
#endif
    CHECK(rk_time_add(0, -1) == -1);
    CHECK(rk_time_sub(0,  1) == -1);
#else
#if SIZEOF_TIME_T == 4
    CHECK(rk_time_add(UINT32_MAX, 0) == UINT32_MAX);
    CHECK(rk_time_add(UINT32_MAX, 1) == UINT32_MAX);
    CHECK(rk_time_add(1, UINT32_MAX) == UINT32_MAX);
    CHECK(rk_time_add(0, UINT32_MAX) == UINT32_MAX);
#elif SIZEOF_TIME_T == 8
    CHECK(rk_time_add(UINT64_MAX, 0) == UINT64_MAX);
    CHECK(rk_time_add(UINT64_MAX, 1) == UINT64_MAX);
    CHECK(rk_time_add(1, UINT64_MAX) == UINT64_MAX);
    CHECK(rk_time_add(0, UINT64_MAX) == UINT64_MAX);
#endif
#endif
    CHECK(rk_time_add(0, 1) == 1);
    CHECK(rk_time_add(1, 0) == 1);
    return e;
}
#endif
