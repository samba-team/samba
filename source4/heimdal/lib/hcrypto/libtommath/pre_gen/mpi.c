/* Start: bn_cutoffs.c */
#include "tommath_private.h"
#ifdef BN_CUTOFFS_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

#ifndef MP_FIXED_CUTOFFS
#include "tommath_cutoffs.h"
int KARATSUBA_MUL_CUTOFF = MP_DEFAULT_KARATSUBA_MUL_CUTOFF,
    KARATSUBA_SQR_CUTOFF = MP_DEFAULT_KARATSUBA_SQR_CUTOFF,
    TOOM_MUL_CUTOFF = MP_DEFAULT_TOOM_MUL_CUTOFF,
    TOOM_SQR_CUTOFF = MP_DEFAULT_TOOM_SQR_CUTOFF;
#endif

#endif

/* End: bn_cutoffs.c */

/* Start: bn_deprecated.c */
#include "tommath_private.h"
#ifdef BN_DEPRECATED_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

#ifdef BN_MP_GET_BIT_C
int mp_get_bit(const mp_int *a, int b)
{
   if (b < 0) {
      return MP_VAL;
   }
   return (s_mp_get_bit(a, (unsigned int)b) == MP_YES) ? MP_YES : MP_NO;
}
#endif
#ifdef BN_MP_JACOBI_C
mp_err mp_jacobi(const mp_int *a, const mp_int *n, int *c)
{
   if (a->sign == MP_NEG) {
      return MP_VAL;
   }
   if (mp_cmp_d(n, 0uL) != MP_GT) {
      return MP_VAL;
   }
   return mp_kronecker(a, n, c);
}
#endif
#ifdef BN_MP_PRIME_RANDOM_EX_C
mp_err mp_prime_random_ex(mp_int *a, int t, int size, int flags, private_mp_prime_callback cb, void *dat)
{
   return s_mp_prime_random_ex(a, t, size, flags, cb, dat);
}
#endif
#ifdef BN_MP_RAND_DIGIT_C
mp_err mp_rand_digit(mp_digit *r)
{
   mp_err err = s_mp_rand_source(r, sizeof(mp_digit));
   *r &= MP_MASK;
   return err;
}
#endif
#ifdef BN_FAST_MP_INVMOD_C
mp_err fast_mp_invmod(const mp_int *a, const mp_int *b, mp_int *c)
{
   return s_mp_invmod_fast(a, b, c);
}
#endif
#ifdef BN_FAST_MP_MONTGOMERY_REDUCE_C
mp_err fast_mp_montgomery_reduce(mp_int *x, const mp_int *n, mp_digit rho)
{
   return s_mp_montgomery_reduce_fast(x, n, rho);
}
#endif
#ifdef BN_FAST_S_MP_MUL_DIGS_C
mp_err fast_s_mp_mul_digs(const mp_int *a, const mp_int *b, mp_int *c, int digs)
{
   return s_mp_mul_digs_fast(a, b, c, digs);
}
#endif
#ifdef BN_FAST_S_MP_MUL_HIGH_DIGS_C
mp_err fast_s_mp_mul_high_digs(const mp_int *a, const mp_int *b, mp_int *c, int digs)
{
   return s_mp_mul_high_digs_fast(a, b, c, digs);
}
#endif
#ifdef BN_FAST_S_MP_SQR_C
mp_err fast_s_mp_sqr(const mp_int *a, mp_int *b)
{
   return s_mp_sqr_fast(a, b);
}
#endif
#ifdef BN_MP_BALANCE_MUL_C
mp_err mp_balance_mul(const mp_int *a, const mp_int *b, mp_int *c)
{
   return s_mp_balance_mul(a, b, c);
}
#endif
#ifdef BN_MP_EXPTMOD_FAST_C
mp_err mp_exptmod_fast(const mp_int *G, const mp_int *X, const mp_int *P, mp_int *Y, int redmode)
{
   return s_mp_exptmod_fast(G, X, P, Y, redmode);
}
#endif
#ifdef BN_MP_INVMOD_SLOW_C
mp_err mp_invmod_slow(const mp_int *a, const mp_int *b, mp_int *c)
{
   return s_mp_invmod_slow(a, b, c);
}
#endif
#ifdef BN_MP_KARATSUBA_MUL_C
mp_err mp_karatsuba_mul(const mp_int *a, const mp_int *b, mp_int *c)
{
   return s_mp_karatsuba_mul(a, b, c);
}
#endif
#ifdef BN_MP_KARATSUBA_SQR_C
mp_err mp_karatsuba_sqr(const mp_int *a, mp_int *b)
{
   return s_mp_karatsuba_sqr(a, b);
}
#endif
#ifdef BN_MP_TOOM_MUL_C
mp_err mp_toom_mul(const mp_int *a, const mp_int *b, mp_int *c)
{
   return s_mp_toom_mul(a, b, c);
}
#endif
#ifdef BN_MP_TOOM_SQR_C
mp_err mp_toom_sqr(const mp_int *a, mp_int *b)
{
   return s_mp_toom_sqr(a, b);
}
#endif
#ifdef S_MP_REVERSE_C
void bn_reverse(unsigned char *s, int len)
{
   if (len > 0) {
      s_mp_reverse(s, (size_t)len);
   }
}
#endif
#ifdef BN_MP_TC_AND_C
mp_err mp_tc_and(const mp_int *a, const mp_int *b, mp_int *c)
{
   return mp_and(a, b, c);
}
#endif
#ifdef BN_MP_TC_OR_C
mp_err mp_tc_or(const mp_int *a, const mp_int *b, mp_int *c)
{
   return mp_or(a, b, c);
}
#endif
#ifdef BN_MP_TC_XOR_C
mp_err mp_tc_xor(const mp_int *a, const mp_int *b, mp_int *c)
{
   return mp_xor(a, b, c);
}
#endif
#ifdef BN_MP_TC_DIV_2D_C
mp_err mp_tc_div_2d(const mp_int *a, int b, mp_int *c)
{
   return mp_signed_rsh(a, b, c);
}
#endif
#ifdef BN_MP_INIT_SET_INT_C
mp_err mp_init_set_int(mp_int *a, unsigned long b)
{
   return mp_init_u32(a, (uint32_t)b);
}
#endif
#ifdef BN_MP_SET_INT_C
mp_err mp_set_int(mp_int *a, unsigned long b)
{
   mp_set_u32(a, (uint32_t)b);
   return MP_OKAY;
}
#endif
#ifdef BN_MP_SET_LONG_C
mp_err mp_set_long(mp_int *a, unsigned long b)
{
   mp_set_u64(a, b);
   return MP_OKAY;
}
#endif
#ifdef BN_MP_SET_LONG_LONG_C
mp_err mp_set_long_long(mp_int *a, unsigned long long b)
{
   mp_set_u64(a, b);
   return MP_OKAY;
}
#endif
#ifdef BN_MP_GET_INT_C
unsigned long mp_get_int(const mp_int *a)
{
   return (unsigned long)mp_get_mag_u32(a);
}
#endif
#ifdef BN_MP_GET_LONG_C
unsigned long mp_get_long(const mp_int *a)
{
   return (unsigned long)mp_get_mag_ul(a);
}
#endif
#ifdef BN_MP_GET_LONG_LONG_C
unsigned long long mp_get_long_long(const mp_int *a)
{
   return mp_get_mag_ull(a);
}
#endif
#ifdef BN_MP_PRIME_IS_DIVISIBLE_C
mp_err mp_prime_is_divisible(const mp_int *a, mp_bool *result)
{
   return s_mp_prime_is_divisible(a, result);
}
#endif
#ifdef BN_MP_EXPT_D_EX_C
mp_err mp_expt_d_ex(const mp_int *a, mp_digit b, mp_int *c, int fast)
{
   (void)fast;
   if (b > MP_MIN(MP_DIGIT_MAX, UINT32_MAX)) {
      return MP_VAL;
   }
   return mp_expt_u32(a, (uint32_t)b, c);
}
#endif
#ifdef BN_MP_EXPT_D_C
mp_err mp_expt_d(const mp_int *a, mp_digit b, mp_int *c)
{
   if (b > MP_MIN(MP_DIGIT_MAX, UINT32_MAX)) {
      return MP_VAL;
   }
   return mp_expt_u32(a, (uint32_t)b, c);
}
#endif
#ifdef BN_MP_N_ROOT_EX_C
mp_err mp_n_root_ex(const mp_int *a, mp_digit b, mp_int *c, int fast)
{
   (void)fast;
   if (b > MP_MIN(MP_DIGIT_MAX, UINT32_MAX)) {
      return MP_VAL;
   }
   return mp_root_u32(a, (uint32_t)b, c);
}
#endif
#ifdef BN_MP_N_ROOT_C
mp_err mp_n_root(const mp_int *a, mp_digit b, mp_int *c)
{
   if (b > MP_MIN(MP_DIGIT_MAX, UINT32_MAX)) {
      return MP_VAL;
   }
   return mp_root_u32(a, (uint32_t)b, c);
}
#endif
#ifdef BN_MP_UNSIGNED_BIN_SIZE_C
int mp_unsigned_bin_size(const mp_int *a)
{
   return (int)mp_ubin_size(a);
}
#endif
#ifdef BN_MP_READ_UNSIGNED_BIN_C
mp_err mp_read_unsigned_bin(mp_int *a, const unsigned char *b, int c)
{
   return mp_from_ubin(a, b, (size_t) c);
}
#endif
#ifdef BN_MP_TO_UNSIGNED_BIN_C
mp_err mp_to_unsigned_bin(const mp_int *a, unsigned char *b)
{
   return mp_to_ubin(a, b, SIZE_MAX, NULL);
}
#endif
#ifdef BN_MP_TO_UNSIGNED_BIN_N_C
mp_err mp_to_unsigned_bin_n(const mp_int *a, unsigned char *b, unsigned long *outlen)
{
   size_t n = mp_ubin_size(a);
   if (*outlen < (unsigned long)n) {
      return MP_VAL;
   }
   *outlen = (unsigned long)n;
   return mp_to_ubin(a, b, n, NULL);
}
#endif
#ifdef BN_MP_SIGNED_BIN_SIZE_C
int mp_signed_bin_size(const mp_int *a)
{
   return (int)mp_sbin_size(a);
}
#endif
#ifdef BN_MP_READ_SIGNED_BIN_C
mp_err mp_read_signed_bin(mp_int *a, const unsigned char *b, int c)
{
   return mp_from_sbin(a, b, (size_t) c);
}
#endif
#ifdef BN_MP_TO_SIGNED_BIN_C
mp_err mp_to_signed_bin(const mp_int *a, unsigned char *b)
{
   return mp_to_sbin(a, b, SIZE_MAX, NULL);
}
#endif
#ifdef BN_MP_TO_SIGNED_BIN_N_C
mp_err mp_to_signed_bin_n(const mp_int *a, unsigned char *b, unsigned long *outlen)
{
   size_t n = mp_sbin_size(a);
   if (*outlen < (unsigned long)n) {
      return MP_VAL;
   }
   *outlen = (unsigned long)n;
   return mp_to_sbin(a, b, n, NULL);
}
#endif
#ifdef BN_MP_TORADIX_N_C
mp_err mp_toradix_n(const mp_int *a, char *str, int radix, int maxlen)
{
   if (maxlen < 0) {
      return MP_VAL;
   }
   return mp_to_radix(a, str, (size_t)maxlen, NULL, radix);
}
#endif
#ifdef BN_MP_TORADIX_C
mp_err mp_toradix(const mp_int *a, char *str, int radix)
{
   return mp_to_radix(a, str, SIZE_MAX, NULL, radix);
}
#endif
#ifdef BN_MP_IMPORT_C
mp_err mp_import(mp_int *rop, size_t count, int order, size_t size, int endian, size_t nails,
                 const void *op)
{
   return mp_unpack(rop, count, order, size, endian, nails, op);
}
#endif
#ifdef BN_MP_EXPORT_C
mp_err mp_export(void *rop, size_t *countp, int order, size_t size,
                 int endian, size_t nails, const mp_int *op)
{
   return mp_pack(rop, SIZE_MAX, countp, order, size, endian, nails, op);
}
#endif
#endif

/* End: bn_deprecated.c */

/* Start: bn_mp_2expt.c */
#include "tommath_private.h"
#ifdef BN_MP_2EXPT_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* computes a = 2**b
 *
 * Simple algorithm which zeroes the int, grows it then just sets one bit
 * as required.
 */
mp_err mp_2expt(mp_int *a, int b)
{
   mp_err    err;

   /* zero a as per default */
   mp_zero(a);

   /* grow a to accomodate the single bit */
   if ((err = mp_grow(a, (b / MP_DIGIT_BIT) + 1)) != MP_OKAY) {
      return err;
   }

   /* set the used count of where the bit will go */
   a->used = (b / MP_DIGIT_BIT) + 1;

   /* put the single bit in its place */
   a->dp[b / MP_DIGIT_BIT] = (mp_digit)1 << (mp_digit)(b % MP_DIGIT_BIT);

   return MP_OKAY;
}
#endif

/* End: bn_mp_2expt.c */

/* Start: bn_mp_abs.c */
#include "tommath_private.h"
#ifdef BN_MP_ABS_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* b = |a|
 *
 * Simple function copies the input and fixes the sign to positive
 */
mp_err mp_abs(const mp_int *a, mp_int *b)
{
   mp_err     err;

   /* copy a to b */
   if (a != b) {
      if ((err = mp_copy(a, b)) != MP_OKAY) {
         return err;
      }
   }

   /* force the sign of b to positive */
   b->sign = MP_ZPOS;

   return MP_OKAY;
}
#endif

/* End: bn_mp_abs.c */

/* Start: bn_mp_add.c */
#include "tommath_private.h"
#ifdef BN_MP_ADD_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* high level addition (handles signs) */
mp_err mp_add(const mp_int *a, const mp_int *b, mp_int *c)
{
   mp_sign sa, sb;
   mp_err err;

   /* get sign of both inputs */
   sa = a->sign;
   sb = b->sign;

   /* handle two cases, not four */
   if (sa == sb) {
      /* both positive or both negative */
      /* add their magnitudes, copy the sign */
      c->sign = sa;
      err = s_mp_add(a, b, c);
   } else {
      /* one positive, the other negative */
      /* subtract the one with the greater magnitude from */
      /* the one of the lesser magnitude.  The result gets */
      /* the sign of the one with the greater magnitude. */
      if (mp_cmp_mag(a, b) == MP_LT) {
         c->sign = sb;
         err = s_mp_sub(b, a, c);
      } else {
         c->sign = sa;
         err = s_mp_sub(a, b, c);
      }
   }
   return err;
}

#endif

/* End: bn_mp_add.c */

/* Start: bn_mp_add_d.c */
#include "tommath_private.h"
#ifdef BN_MP_ADD_D_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* single digit addition */
mp_err mp_add_d(const mp_int *a, mp_digit b, mp_int *c)
{
   mp_err     err;
   int ix, oldused;
   mp_digit *tmpa, *tmpc;

   /* grow c as required */
   if (c->alloc < (a->used + 1)) {
      if ((err = mp_grow(c, a->used + 1)) != MP_OKAY) {
         return err;
      }
   }

   /* if a is negative and |a| >= b, call c = |a| - b */
   if ((a->sign == MP_NEG) && ((a->used > 1) || (a->dp[0] >= b))) {
      mp_int a_ = *a;
      /* temporarily fix sign of a */
      a_.sign = MP_ZPOS;

      /* c = |a| - b */
      err = mp_sub_d(&a_, b, c);

      /* fix sign  */
      c->sign = MP_NEG;

      /* clamp */
      mp_clamp(c);

      return err;
   }

   /* old number of used digits in c */
   oldused = c->used;

   /* source alias */
   tmpa    = a->dp;

   /* destination alias */
   tmpc    = c->dp;

   /* if a is positive */
   if (a->sign == MP_ZPOS) {
      /* add digits, mu is carry */
      mp_digit mu = b;
      for (ix = 0; ix < a->used; ix++) {
         *tmpc   = *tmpa++ + mu;
         mu      = *tmpc >> MP_DIGIT_BIT;
         *tmpc++ &= MP_MASK;
      }
      /* set final carry */
      ix++;
      *tmpc++  = mu;

      /* setup size */
      c->used = a->used + 1;
   } else {
      /* a was negative and |a| < b */
      c->used  = 1;

      /* the result is a single digit */
      if (a->used == 1) {
         *tmpc++  =  b - a->dp[0];
      } else {
         *tmpc++  =  b;
      }

      /* setup count so the clearing of oldused
       * can fall through correctly
       */
      ix       = 1;
   }

   /* sign always positive */
   c->sign = MP_ZPOS;

   /* now zero to oldused */
   MP_ZERO_DIGITS(tmpc, oldused - ix);
   mp_clamp(c);

   return MP_OKAY;
}

#endif

/* End: bn_mp_add_d.c */

/* Start: bn_mp_addmod.c */
#include "tommath_private.h"
#ifdef BN_MP_ADDMOD_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* d = a + b (mod c) */
mp_err mp_addmod(const mp_int *a, const mp_int *b, const mp_int *c, mp_int *d)
{
   mp_err  err;
   mp_int  t;

   if ((err = mp_init(&t)) != MP_OKAY) {
      return err;
   }

   if ((err = mp_add(a, b, &t)) != MP_OKAY) {
      goto LBL_ERR;
   }
   err = mp_mod(&t, c, d);

LBL_ERR:
   mp_clear(&t);
   return err;
}
#endif

/* End: bn_mp_addmod.c */

/* Start: bn_mp_and.c */
#include "tommath_private.h"
#ifdef BN_MP_AND_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* two complement and */
mp_err mp_and(const mp_int *a, const mp_int *b, mp_int *c)
{
   int used = MP_MAX(a->used, b->used) + 1, i;
   mp_err err;
   mp_digit ac = 1, bc = 1, cc = 1;
   mp_sign csign = ((a->sign == MP_NEG) && (b->sign == MP_NEG)) ? MP_NEG : MP_ZPOS;

   if (c->alloc < used) {
      if ((err = mp_grow(c, used)) != MP_OKAY) {
         return err;
      }
   }

   for (i = 0; i < used; i++) {
      mp_digit x, y;

      /* convert to two complement if negative */
      if (a->sign == MP_NEG) {
         ac += (i >= a->used) ? MP_MASK : (~a->dp[i] & MP_MASK);
         x = ac & MP_MASK;
         ac >>= MP_DIGIT_BIT;
      } else {
         x = (i >= a->used) ? 0uL : a->dp[i];
      }

      /* convert to two complement if negative */
      if (b->sign == MP_NEG) {
         bc += (i >= b->used) ? MP_MASK : (~b->dp[i] & MP_MASK);
         y = bc & MP_MASK;
         bc >>= MP_DIGIT_BIT;
      } else {
         y = (i >= b->used) ? 0uL : b->dp[i];
      }

      c->dp[i] = x & y;

      /* convert to to sign-magnitude if negative */
      if (csign == MP_NEG) {
         cc += ~c->dp[i] & MP_MASK;
         c->dp[i] = cc & MP_MASK;
         cc >>= MP_DIGIT_BIT;
      }
   }

   c->used = used;
   c->sign = csign;
   mp_clamp(c);
   return MP_OKAY;
}
#endif

/* End: bn_mp_and.c */

/* Start: bn_mp_clamp.c */
#include "tommath_private.h"
#ifdef BN_MP_CLAMP_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* trim unused digits
 *
 * This is used to ensure that leading zero digits are
 * trimed and the leading "used" digit will be non-zero
 * Typically very fast.  Also fixes the sign if there
 * are no more leading digits
 */
void mp_clamp(mp_int *a)
{
   /* decrease used while the most significant digit is
    * zero.
    */
   while ((a->used > 0) && (a->dp[a->used - 1] == 0u)) {
      --(a->used);
   }

   /* reset the sign flag if used == 0 */
   if (a->used == 0) {
      a->sign = MP_ZPOS;
   }
}
#endif

/* End: bn_mp_clamp.c */

/* Start: bn_mp_clear.c */
#include "tommath_private.h"
#ifdef BN_MP_CLEAR_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* clear one (frees)  */
void mp_clear(mp_int *a)
{
   /* only do anything if a hasn't been freed previously */
   if (a->dp != NULL) {
      /* free ram */
      MP_FREE_DIGITS(a->dp, a->alloc);

      /* reset members to make debugging easier */
      a->dp    = NULL;
      a->alloc = a->used = 0;
      a->sign  = MP_ZPOS;
   }
}
#endif

/* End: bn_mp_clear.c */

/* Start: bn_mp_clear_multi.c */
#include "tommath_private.h"
#ifdef BN_MP_CLEAR_MULTI_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

#include <stdarg.h>

void mp_clear_multi(mp_int *mp, ...)
{
   mp_int *next_mp = mp;
   va_list args;
   va_start(args, mp);
   while (next_mp != NULL) {
      mp_clear(next_mp);
      next_mp = va_arg(args, mp_int *);
   }
   va_end(args);
}
#endif

/* End: bn_mp_clear_multi.c */

/* Start: bn_mp_cmp.c */
#include "tommath_private.h"
#ifdef BN_MP_CMP_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* compare two ints (signed)*/
mp_ord mp_cmp(const mp_int *a, const mp_int *b)
{
   /* compare based on sign */
   if (a->sign != b->sign) {
      if (a->sign == MP_NEG) {
         return MP_LT;
      } else {
         return MP_GT;
      }
   }

   /* compare digits */
   if (a->sign == MP_NEG) {
      /* if negative compare opposite direction */
      return mp_cmp_mag(b, a);
   } else {
      return mp_cmp_mag(a, b);
   }
}
#endif

/* End: bn_mp_cmp.c */

/* Start: bn_mp_cmp_d.c */
#include "tommath_private.h"
#ifdef BN_MP_CMP_D_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* compare a digit */
mp_ord mp_cmp_d(const mp_int *a, mp_digit b)
{
   /* compare based on sign */
   if (a->sign == MP_NEG) {
      return MP_LT;
   }

   /* compare based on magnitude */
   if (a->used > 1) {
      return MP_GT;
   }

   /* compare the only digit of a to b */
   if (a->dp[0] > b) {
      return MP_GT;
   } else if (a->dp[0] < b) {
      return MP_LT;
   } else {
      return MP_EQ;
   }
}
#endif

/* End: bn_mp_cmp_d.c */

/* Start: bn_mp_cmp_mag.c */
#include "tommath_private.h"
#ifdef BN_MP_CMP_MAG_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* compare maginitude of two ints (unsigned) */
mp_ord mp_cmp_mag(const mp_int *a, const mp_int *b)
{
   int     n;
   const mp_digit *tmpa, *tmpb;

   /* compare based on # of non-zero digits */
   if (a->used > b->used) {
      return MP_GT;
   }

   if (a->used < b->used) {
      return MP_LT;
   }

   /* alias for a */
   tmpa = a->dp + (a->used - 1);

   /* alias for b */
   tmpb = b->dp + (a->used - 1);

   /* compare based on digits  */
   for (n = 0; n < a->used; ++n, --tmpa, --tmpb) {
      if (*tmpa > *tmpb) {
         return MP_GT;
      }

      if (*tmpa < *tmpb) {
         return MP_LT;
      }
   }
   return MP_EQ;
}
#endif

/* End: bn_mp_cmp_mag.c */

/* Start: bn_mp_cnt_lsb.c */
#include "tommath_private.h"
#ifdef BN_MP_CNT_LSB_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

static const int lnz[16] = {
   4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0
};

/* Counts the number of lsbs which are zero before the first zero bit */
int mp_cnt_lsb(const mp_int *a)
{
   int x;
   mp_digit q, qq;

   /* easy out */
   if (MP_IS_ZERO(a)) {
      return 0;
   }

   /* scan lower digits until non-zero */
   for (x = 0; (x < a->used) && (a->dp[x] == 0u); x++) {}
   q = a->dp[x];
   x *= MP_DIGIT_BIT;

   /* now scan this digit until a 1 is found */
   if ((q & 1u) == 0u) {
      do {
         qq  = q & 15u;
         x  += lnz[qq];
         q >>= 4;
      } while (qq == 0u);
   }
   return x;
}

#endif

/* End: bn_mp_cnt_lsb.c */

/* Start: bn_mp_complement.c */
#include "tommath_private.h"
#ifdef BN_MP_COMPLEMENT_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* b = ~a */
mp_err mp_complement(const mp_int *a, mp_int *b)
{
   mp_err err = mp_neg(a, b);
   return (err == MP_OKAY) ? mp_sub_d(b, 1uL, b) : err;
}
#endif

/* End: bn_mp_complement.c */

/* Start: bn_mp_copy.c */
#include "tommath_private.h"
#ifdef BN_MP_COPY_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* copy, b = a */
mp_err mp_copy(const mp_int *a, mp_int *b)
{
   int n;
   mp_digit *tmpa, *tmpb;
   mp_err err;

   /* if dst == src do nothing */
   if (a == b) {
      return MP_OKAY;
   }

   /* grow dest */
   if (b->alloc < a->used) {
      if ((err = mp_grow(b, a->used)) != MP_OKAY) {
         return err;
      }
   }

   /* zero b and copy the parameters over */
   /* pointer aliases */

   /* source */
   tmpa = a->dp;

   /* destination */
   tmpb = b->dp;

   /* copy all the digits */
   for (n = 0; n < a->used; n++) {
      *tmpb++ = *tmpa++;
   }

   /* clear high digits */
   MP_ZERO_DIGITS(tmpb, b->used - n);

   /* copy used count and sign */
   b->used = a->used;
   b->sign = a->sign;
   return MP_OKAY;
}
#endif

/* End: bn_mp_copy.c */

/* Start: bn_mp_count_bits.c */
#include "tommath_private.h"
#ifdef BN_MP_COUNT_BITS_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* returns the number of bits in an int */
int mp_count_bits(const mp_int *a)
{
   int     r;
   mp_digit q;

   /* shortcut */
   if (MP_IS_ZERO(a)) {
      return 0;
   }

   /* get number of digits and add that */
   r = (a->used - 1) * MP_DIGIT_BIT;

   /* take the last digit and count the bits in it */
   q = a->dp[a->used - 1];
   while (q > 0u) {
      ++r;
      q >>= 1u;
   }
   return r;
}
#endif

/* End: bn_mp_count_bits.c */

/* Start: bn_mp_decr.c */
#include "tommath_private.h"
#ifdef BN_MP_DECR_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* Decrement "a" by one like "a--". Changes input! */
mp_err mp_decr(mp_int *a)
{
   if (MP_IS_ZERO(a)) {
      mp_set(a,1uL);
      a->sign = MP_NEG;
      return MP_OKAY;
   } else if (a->sign == MP_NEG) {
      mp_err err;
      a->sign = MP_ZPOS;
      if ((err = mp_incr(a)) != MP_OKAY) {
         return err;
      }
      /* There is no -0 in LTM */
      if (!MP_IS_ZERO(a)) {
         a->sign = MP_NEG;
      }
      return MP_OKAY;
   } else if (a->dp[0] > 1uL) {
      a->dp[0]--;
      if (a->dp[0] == 0u) {
         mp_zero(a);
      }
      return MP_OKAY;
   } else {
      return mp_sub_d(a, 1uL,a);
   }
}
#endif

/* End: bn_mp_decr.c */

/* Start: bn_mp_div.c */
#include "tommath_private.h"
#ifdef BN_MP_DIV_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

#ifdef BN_MP_DIV_SMALL

/* slower bit-bang division... also smaller */
mp_err mp_div(const mp_int *a, const mp_int *b, mp_int *c, mp_int *d)
{
   mp_int ta, tb, tq, q;
   int     n, n2;
   mp_err err;

   /* is divisor zero ? */
   if (MP_IS_ZERO(b)) {
      return MP_VAL;
   }

   /* if a < b then q=0, r = a */
   if (mp_cmp_mag(a, b) == MP_LT) {
      if (d != NULL) {
         err = mp_copy(a, d);
      } else {
         err = MP_OKAY;
      }
      if (c != NULL) {
         mp_zero(c);
      }
      return err;
   }

   /* init our temps */
   if ((err = mp_init_multi(&ta, &tb, &tq, &q, NULL)) != MP_OKAY) {
      return err;
   }


   mp_set(&tq, 1uL);
   n = mp_count_bits(a) - mp_count_bits(b);
   if ((err = mp_abs(a, &ta)) != MP_OKAY)                         goto LBL_ERR;
   if ((err = mp_abs(b, &tb)) != MP_OKAY)                         goto LBL_ERR;
   if ((err = mp_mul_2d(&tb, n, &tb)) != MP_OKAY)                 goto LBL_ERR;
   if ((err = mp_mul_2d(&tq, n, &tq)) != MP_OKAY)                 goto LBL_ERR;

   while (n-- >= 0) {
      if (mp_cmp(&tb, &ta) != MP_GT) {
         if ((err = mp_sub(&ta, &tb, &ta)) != MP_OKAY)            goto LBL_ERR;
         if ((err = mp_add(&q, &tq, &q)) != MP_OKAY)              goto LBL_ERR;
      }
      if ((err = mp_div_2d(&tb, 1, &tb, NULL)) != MP_OKAY)        goto LBL_ERR;
      if ((err = mp_div_2d(&tq, 1, &tq, NULL)) != MP_OKAY)        goto LBL_ERR;
   }

   /* now q == quotient and ta == remainder */
   n  = a->sign;
   n2 = (a->sign == b->sign) ? MP_ZPOS : MP_NEG;
   if (c != NULL) {
      mp_exch(c, &q);
      c->sign  = MP_IS_ZERO(c) ? MP_ZPOS : n2;
   }
   if (d != NULL) {
      mp_exch(d, &ta);
      d->sign = MP_IS_ZERO(d) ? MP_ZPOS : n;
   }
LBL_ERR:
   mp_clear_multi(&ta, &tb, &tq, &q, NULL);
   return err;
}

#else

/* integer signed division.
 * c*b + d == a [e.g. a/b, c=quotient, d=remainder]
 * HAC pp.598 Algorithm 14.20
 *
 * Note that the description in HAC is horribly
 * incomplete.  For example, it doesn't consider
 * the case where digits are removed from 'x' in
 * the inner loop.  It also doesn't consider the
 * case that y has fewer than three digits, etc..
 *
 * The overall algorithm is as described as
 * 14.20 from HAC but fixed to treat these cases.
*/
mp_err mp_div(const mp_int *a, const mp_int *b, mp_int *c, mp_int *d)
{
   mp_int  q, x, y, t1, t2;
   int     n, t, i, norm;
   mp_sign neg;
   mp_err  err;

   /* is divisor zero ? */
   if (MP_IS_ZERO(b)) {
      return MP_VAL;
   }

   /* if a < b then q=0, r = a */
   if (mp_cmp_mag(a, b) == MP_LT) {
      if (d != NULL) {
         err = mp_copy(a, d);
      } else {
         err = MP_OKAY;
      }
      if (c != NULL) {
         mp_zero(c);
      }
      return err;
   }

   if ((err = mp_init_size(&q, a->used + 2)) != MP_OKAY) {
      return err;
   }
   q.used = a->used + 2;

   if ((err = mp_init(&t1)) != MP_OKAY)                           goto LBL_Q;

   if ((err = mp_init(&t2)) != MP_OKAY)                           goto LBL_T1;

   if ((err = mp_init_copy(&x, a)) != MP_OKAY)                    goto LBL_T2;

   if ((err = mp_init_copy(&y, b)) != MP_OKAY)                    goto LBL_X;

   /* fix the sign */
   neg = (a->sign == b->sign) ? MP_ZPOS : MP_NEG;
   x.sign = y.sign = MP_ZPOS;

   /* normalize both x and y, ensure that y >= b/2, [b == 2**MP_DIGIT_BIT] */
   norm = mp_count_bits(&y) % MP_DIGIT_BIT;
   if (norm < (MP_DIGIT_BIT - 1)) {
      norm = (MP_DIGIT_BIT - 1) - norm;
      if ((err = mp_mul_2d(&x, norm, &x)) != MP_OKAY)             goto LBL_Y;
      if ((err = mp_mul_2d(&y, norm, &y)) != MP_OKAY)             goto LBL_Y;
   } else {
      norm = 0;
   }

   /* note hac does 0 based, so if used==5 then its 0,1,2,3,4, e.g. use 4 */
   n = x.used - 1;
   t = y.used - 1;

   /* while (x >= y*b**n-t) do { q[n-t] += 1; x -= y*b**{n-t} } */
   /* y = y*b**{n-t} */
   if ((err = mp_lshd(&y, n - t)) != MP_OKAY)                     goto LBL_Y;

   while (mp_cmp(&x, &y) != MP_LT) {
      ++(q.dp[n - t]);
      if ((err = mp_sub(&x, &y, &x)) != MP_OKAY)                  goto LBL_Y;
   }

   /* reset y by shifting it back down */
   mp_rshd(&y, n - t);

   /* step 3. for i from n down to (t + 1) */
   for (i = n; i >= (t + 1); i--) {
      if (i > x.used) {
         continue;
      }

      /* step 3.1 if xi == yt then set q{i-t-1} to b-1,
       * otherwise set q{i-t-1} to (xi*b + x{i-1})/yt */
      if (x.dp[i] == y.dp[t]) {
         q.dp[(i - t) - 1] = ((mp_digit)1 << (mp_digit)MP_DIGIT_BIT) - (mp_digit)1;
      } else {
         mp_word tmp;
         tmp = (mp_word)x.dp[i] << (mp_word)MP_DIGIT_BIT;
         tmp |= (mp_word)x.dp[i - 1];
         tmp /= (mp_word)y.dp[t];
         if (tmp > (mp_word)MP_MASK) {
            tmp = MP_MASK;
         }
         q.dp[(i - t) - 1] = (mp_digit)(tmp & (mp_word)MP_MASK);
      }

      /* while (q{i-t-1} * (yt * b + y{t-1})) >
               xi * b**2 + xi-1 * b + xi-2

         do q{i-t-1} -= 1;
      */
      q.dp[(i - t) - 1] = (q.dp[(i - t) - 1] + 1uL) & (mp_digit)MP_MASK;
      do {
         q.dp[(i - t) - 1] = (q.dp[(i - t) - 1] - 1uL) & (mp_digit)MP_MASK;

         /* find left hand */
         mp_zero(&t1);
         t1.dp[0] = ((t - 1) < 0) ? 0u : y.dp[t - 1];
         t1.dp[1] = y.dp[t];
         t1.used = 2;
         if ((err = mp_mul_d(&t1, q.dp[(i - t) - 1], &t1)) != MP_OKAY) goto LBL_Y;

         /* find right hand */
         t2.dp[0] = ((i - 2) < 0) ? 0u : x.dp[i - 2];
         t2.dp[1] = x.dp[i - 1]; /* i >= 1 always holds */
         t2.dp[2] = x.dp[i];
         t2.used = 3;
      } while (mp_cmp_mag(&t1, &t2) == MP_GT);

      /* step 3.3 x = x - q{i-t-1} * y * b**{i-t-1} */
      if ((err = mp_mul_d(&y, q.dp[(i - t) - 1], &t1)) != MP_OKAY) goto LBL_Y;

      if ((err = mp_lshd(&t1, (i - t) - 1)) != MP_OKAY)           goto LBL_Y;

      if ((err = mp_sub(&x, &t1, &x)) != MP_OKAY)                 goto LBL_Y;

      /* if x < 0 then { x = x + y*b**{i-t-1}; q{i-t-1} -= 1; } */
      if (x.sign == MP_NEG) {
         if ((err = mp_copy(&y, &t1)) != MP_OKAY)                 goto LBL_Y;
         if ((err = mp_lshd(&t1, (i - t) - 1)) != MP_OKAY)        goto LBL_Y;
         if ((err = mp_add(&x, &t1, &x)) != MP_OKAY)              goto LBL_Y;

         q.dp[(i - t) - 1] = (q.dp[(i - t) - 1] - 1uL) & MP_MASK;
      }
   }

   /* now q is the quotient and x is the remainder
    * [which we have to normalize]
    */

   /* get sign before writing to c */
   x.sign = (x.used == 0) ? MP_ZPOS : a->sign;

   if (c != NULL) {
      mp_clamp(&q);
      mp_exch(&q, c);
      c->sign = neg;
   }

   if (d != NULL) {
      if ((err = mp_div_2d(&x, norm, &x, NULL)) != MP_OKAY)       goto LBL_Y;
      mp_exch(&x, d);
   }

   err = MP_OKAY;

LBL_Y:
   mp_clear(&y);
LBL_X:
   mp_clear(&x);
LBL_T2:
   mp_clear(&t2);
LBL_T1:
   mp_clear(&t1);
LBL_Q:
   mp_clear(&q);
   return err;
}

#endif

#endif

/* End: bn_mp_div.c */

/* Start: bn_mp_div_2.c */
#include "tommath_private.h"
#ifdef BN_MP_DIV_2_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* b = a/2 */
mp_err mp_div_2(const mp_int *a, mp_int *b)
{
   int     x, oldused;
   mp_digit r, rr, *tmpa, *tmpb;
   mp_err err;

   /* copy */
   if (b->alloc < a->used) {
      if ((err = mp_grow(b, a->used)) != MP_OKAY) {
         return err;
      }
   }

   oldused = b->used;
   b->used = a->used;

   /* source alias */
   tmpa = a->dp + b->used - 1;

   /* dest alias */
   tmpb = b->dp + b->used - 1;

   /* carry */
   r = 0;
   for (x = b->used - 1; x >= 0; x--) {
      /* get the carry for the next iteration */
      rr = *tmpa & 1u;

      /* shift the current digit, add in carry and store */
      *tmpb-- = (*tmpa-- >> 1) | (r << (MP_DIGIT_BIT - 1));

      /* forward carry to next iteration */
      r = rr;
   }

   /* zero excess digits */
   MP_ZERO_DIGITS(b->dp + b->used, oldused - b->used);

   b->sign = a->sign;
   mp_clamp(b);
   return MP_OKAY;
}
#endif

/* End: bn_mp_div_2.c */

/* Start: bn_mp_div_2d.c */
#include "tommath_private.h"
#ifdef BN_MP_DIV_2D_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* shift right by a certain bit count (store quotient in c, optional remainder in d) */
mp_err mp_div_2d(const mp_int *a, int b, mp_int *c, mp_int *d)
{
   mp_digit D, r, rr;
   int     x;
   mp_err err;

   /* if the shift count is <= 0 then we do no work */
   if (b <= 0) {
      err = mp_copy(a, c);
      if (d != NULL) {
         mp_zero(d);
      }
      return err;
   }

   /* copy */
   if ((err = mp_copy(a, c)) != MP_OKAY) {
      return err;
   }
   /* 'a' should not be used after here - it might be the same as d */

   /* get the remainder */
   if (d != NULL) {
      if ((err = mp_mod_2d(a, b, d)) != MP_OKAY) {
         return err;
      }
   }

   /* shift by as many digits in the bit count */
   if (b >= MP_DIGIT_BIT) {
      mp_rshd(c, b / MP_DIGIT_BIT);
   }

   /* shift any bit count < MP_DIGIT_BIT */
   D = (mp_digit)(b % MP_DIGIT_BIT);
   if (D != 0u) {
      mp_digit *tmpc, mask, shift;

      /* mask */
      mask = ((mp_digit)1 << D) - 1uL;

      /* shift for lsb */
      shift = (mp_digit)MP_DIGIT_BIT - D;

      /* alias */
      tmpc = c->dp + (c->used - 1);

      /* carry */
      r = 0;
      for (x = c->used - 1; x >= 0; x--) {
         /* get the lower  bits of this word in a temp */
         rr = *tmpc & mask;

         /* shift the current word and mix in the carry bits from the previous word */
         *tmpc = (*tmpc >> D) | (r << shift);
         --tmpc;

         /* set the carry to the carry bits of the current word found above */
         r = rr;
      }
   }
   mp_clamp(c);
   return MP_OKAY;
}
#endif

/* End: bn_mp_div_2d.c */

/* Start: bn_mp_div_3.c */
#include "tommath_private.h"
#ifdef BN_MP_DIV_3_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* divide by three (based on routine from MPI and the GMP manual) */
mp_err mp_div_3(const mp_int *a, mp_int *c, mp_digit *d)
{
   mp_int   q;
   mp_word  w, t;
   mp_digit b;
   mp_err   err;
   int      ix;

   /* b = 2**MP_DIGIT_BIT / 3 */
   b = ((mp_word)1 << (mp_word)MP_DIGIT_BIT) / (mp_word)3;

   if ((err = mp_init_size(&q, a->used)) != MP_OKAY) {
      return err;
   }

   q.used = a->used;
   q.sign = a->sign;
   w = 0;
   for (ix = a->used - 1; ix >= 0; ix--) {
      w = (w << (mp_word)MP_DIGIT_BIT) | (mp_word)a->dp[ix];

      if (w >= 3u) {
         /* multiply w by [1/3] */
         t = (w * (mp_word)b) >> (mp_word)MP_DIGIT_BIT;

         /* now subtract 3 * [w/3] from w, to get the remainder */
         w -= t+t+t;

         /* fixup the remainder as required since
          * the optimization is not exact.
          */
         while (w >= 3u) {
            t += 1u;
            w -= 3u;
         }
      } else {
         t = 0;
      }
      q.dp[ix] = (mp_digit)t;
   }

   /* [optional] store the remainder */
   if (d != NULL) {
      *d = (mp_digit)w;
   }

   /* [optional] store the quotient */
   if (c != NULL) {
      mp_clamp(&q);
      mp_exch(&q, c);
   }
   mp_clear(&q);

   return err;
}

#endif

/* End: bn_mp_div_3.c */

/* Start: bn_mp_div_d.c */
#include "tommath_private.h"
#ifdef BN_MP_DIV_D_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* single digit division (based on routine from MPI) */
mp_err mp_div_d(const mp_int *a, mp_digit b, mp_int *c, mp_digit *d)
{
   mp_int  q;
   mp_word w;
   mp_digit t;
   mp_err err;
   int ix;

   /* cannot divide by zero */
   if (b == 0u) {
      return MP_VAL;
   }

   /* quick outs */
   if ((b == 1u) || MP_IS_ZERO(a)) {
      if (d != NULL) {
         *d = 0;
      }
      if (c != NULL) {
         return mp_copy(a, c);
      }
      return MP_OKAY;
   }

   /* power of two ? */
   if ((b & (b - 1u)) == 0u) {
      ix = 1;
      while ((ix < MP_DIGIT_BIT) && (b != (((mp_digit)1)<<ix))) {
         ix++;
      }
      if (d != NULL) {
         *d = a->dp[0] & (((mp_digit)1<<(mp_digit)ix) - 1uL);
      }
      if (c != NULL) {
         return mp_div_2d(a, ix, c, NULL);
      }
      return MP_OKAY;
   }

   /* three? */
   if (MP_HAS(MP_DIV_3) && (b == 3u)) {
      return mp_div_3(a, c, d);
   }

   /* no easy answer [c'est la vie].  Just division */
   if ((err = mp_init_size(&q, a->used)) != MP_OKAY) {
      return err;
   }

   q.used = a->used;
   q.sign = a->sign;
   w = 0;
   for (ix = a->used - 1; ix >= 0; ix--) {
      w = (w << (mp_word)MP_DIGIT_BIT) | (mp_word)a->dp[ix];

      if (w >= b) {
         t = (mp_digit)(w / b);
         w -= (mp_word)t * (mp_word)b;
      } else {
         t = 0;
      }
      q.dp[ix] = t;
   }

   if (d != NULL) {
      *d = (mp_digit)w;
   }

   if (c != NULL) {
      mp_clamp(&q);
      mp_exch(&q, c);
   }
   mp_clear(&q);

   return err;
}

#endif

/* End: bn_mp_div_d.c */

/* Start: bn_mp_dr_is_modulus.c */
#include "tommath_private.h"
#ifdef BN_MP_DR_IS_MODULUS_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* determines if a number is a valid DR modulus */
mp_bool mp_dr_is_modulus(const mp_int *a)
{
   int ix;

   /* must be at least two digits */
   if (a->used < 2) {
      return MP_NO;
   }

   /* must be of the form b**k - a [a <= b] so all
    * but the first digit must be equal to -1 (mod b).
    */
   for (ix = 1; ix < a->used; ix++) {
      if (a->dp[ix] != MP_MASK) {
         return MP_NO;
      }
   }
   return MP_YES;
}

#endif

/* End: bn_mp_dr_is_modulus.c */

/* Start: bn_mp_dr_reduce.c */
#include "tommath_private.h"
#ifdef BN_MP_DR_REDUCE_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* reduce "x" in place modulo "n" using the Diminished Radix algorithm.
 *
 * Based on algorithm from the paper
 *
 * "Generating Efficient Primes for Discrete Log Cryptosystems"
 *                 Chae Hoon Lim, Pil Joong Lee,
 *          POSTECH Information Research Laboratories
 *
 * The modulus must be of a special format [see manual]
 *
 * Has been modified to use algorithm 7.10 from the LTM book instead
 *
 * Input x must be in the range 0 <= x <= (n-1)**2
 */
mp_err mp_dr_reduce(mp_int *x, const mp_int *n, mp_digit k)
{
   mp_err      err;
   int i, m;
   mp_word  r;
   mp_digit mu, *tmpx1, *tmpx2;

   /* m = digits in modulus */
   m = n->used;

   /* ensure that "x" has at least 2m digits */
   if (x->alloc < (m + m)) {
      if ((err = mp_grow(x, m + m)) != MP_OKAY) {
         return err;
      }
   }

   /* top of loop, this is where the code resumes if
    * another reduction pass is required.
    */
top:
   /* aliases for digits */
   /* alias for lower half of x */
   tmpx1 = x->dp;

   /* alias for upper half of x, or x/B**m */
   tmpx2 = x->dp + m;

   /* set carry to zero */
   mu = 0;

   /* compute (x mod B**m) + k * [x/B**m] inline and inplace */
   for (i = 0; i < m; i++) {
      r         = ((mp_word)*tmpx2++ * (mp_word)k) + *tmpx1 + mu;
      *tmpx1++  = (mp_digit)(r & MP_MASK);
      mu        = (mp_digit)(r >> ((mp_word)MP_DIGIT_BIT));
   }

   /* set final carry */
   *tmpx1++ = mu;

   /* zero words above m */
   MP_ZERO_DIGITS(tmpx1, (x->used - m) - 1);

   /* clamp, sub and return */
   mp_clamp(x);

   /* if x >= n then subtract and reduce again
    * Each successive "recursion" makes the input smaller and smaller.
    */
   if (mp_cmp_mag(x, n) != MP_LT) {
      if ((err = s_mp_sub(x, n, x)) != MP_OKAY) {
         return err;
      }
      goto top;
   }
   return MP_OKAY;
}
#endif

/* End: bn_mp_dr_reduce.c */

/* Start: bn_mp_dr_setup.c */
#include "tommath_private.h"
#ifdef BN_MP_DR_SETUP_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* determines the setup value */
void mp_dr_setup(const mp_int *a, mp_digit *d)
{
   /* the casts are required if MP_DIGIT_BIT is one less than
    * the number of bits in a mp_digit [e.g. MP_DIGIT_BIT==31]
    */
   *d = (mp_digit)(((mp_word)1 << (mp_word)MP_DIGIT_BIT) - (mp_word)a->dp[0]);
}

#endif

/* End: bn_mp_dr_setup.c */

/* Start: bn_mp_error_to_string.c */
#include "tommath_private.h"
#ifdef BN_MP_ERROR_TO_STRING_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* return a char * string for a given code */
const char *mp_error_to_string(mp_err code)
{
   switch (code) {
   case MP_OKAY:
      return "Successful";
   case MP_ERR:
      return "Unknown error";
   case MP_MEM:
      return "Out of heap";
   case MP_VAL:
      return "Value out of range";
   case MP_ITER:
      return "Max. iterations reached";
   case MP_BUF:
      return "Buffer overflow";
   default:
      return "Invalid error code";
   }
}

#endif

/* End: bn_mp_error_to_string.c */

/* Start: bn_mp_exch.c */
#include "tommath_private.h"
#ifdef BN_MP_EXCH_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* swap the elements of two integers, for cases where you can't simply swap the
 * mp_int pointers around
 */
void mp_exch(mp_int *a, mp_int *b)
{
   mp_int  t;

   t  = *a;
   *a = *b;
   *b = t;
}
#endif

/* End: bn_mp_exch.c */

/* Start: bn_mp_expt_u32.c */
#include "tommath_private.h"
#ifdef BN_MP_EXPT_U32_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* calculate c = a**b  using a square-multiply algorithm */
mp_err mp_expt_u32(const mp_int *a, uint32_t b, mp_int *c)
{
   mp_err err;

   mp_int  g;

   if ((err = mp_init_copy(&g, a)) != MP_OKAY) {
      return err;
   }

   /* set initial result */
   mp_set(c, 1uL);

   while (b > 0u) {
      /* if the bit is set multiply */
      if ((b & 1u) != 0u) {
         if ((err = mp_mul(c, &g, c)) != MP_OKAY) {
            goto LBL_ERR;
         }
      }

      /* square */
      if (b > 1u) {
         if ((err = mp_sqr(&g, &g)) != MP_OKAY) {
            goto LBL_ERR;
         }
      }

      /* shift to next bit */
      b >>= 1;
   }

   err = MP_OKAY;

LBL_ERR:
   mp_clear(&g);
   return err;
}

#endif

/* End: bn_mp_expt_u32.c */

/* Start: bn_mp_exptmod.c */
#include "tommath_private.h"
#ifdef BN_MP_EXPTMOD_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* this is a shell function that calls either the normal or Montgomery
 * exptmod functions.  Originally the call to the montgomery code was
 * embedded in the normal function but that wasted alot of stack space
 * for nothing (since 99% of the time the Montgomery code would be called)
 */
mp_err mp_exptmod(const mp_int *G, const mp_int *X, const mp_int *P, mp_int *Y)
{
   int dr;

   /* modulus P must be positive */
   if (P->sign == MP_NEG) {
      return MP_VAL;
   }

   /* if exponent X is negative we have to recurse */
   if (X->sign == MP_NEG) {
      mp_int tmpG, tmpX;
      mp_err err;

      if (!MP_HAS(MP_INVMOD)) {
         return MP_VAL;
      }

      if ((err = mp_init_multi(&tmpG, &tmpX, NULL)) != MP_OKAY) {
         return err;
      }

      /* first compute 1/G mod P */
      if ((err = mp_invmod(G, P, &tmpG)) != MP_OKAY) {
         goto LBL_ERR;
      }

      /* now get |X| */
      if ((err = mp_abs(X, &tmpX)) != MP_OKAY) {
         goto LBL_ERR;
      }

      /* and now compute (1/G)**|X| instead of G**X [X < 0] */
      err = mp_exptmod(&tmpG, &tmpX, P, Y);
LBL_ERR:
      mp_clear_multi(&tmpG, &tmpX, NULL);
      return err;
   }

   /* modified diminished radix reduction */
   if (MP_HAS(MP_REDUCE_IS_2K_L) && MP_HAS(MP_REDUCE_2K_L) && MP_HAS(S_MP_EXPTMOD) &&
       (mp_reduce_is_2k_l(P) == MP_YES)) {
      return s_mp_exptmod(G, X, P, Y, 1);
   }

   /* is it a DR modulus? default to no */
   dr = (MP_HAS(MP_DR_IS_MODULUS) && (mp_dr_is_modulus(P) == MP_YES)) ? 1 : 0;

   /* if not, is it a unrestricted DR modulus? */
   if (MP_HAS(MP_REDUCE_IS_2K) && (dr == 0)) {
      dr = (mp_reduce_is_2k(P) == MP_YES) ? 2 : 0;
   }

   /* if the modulus is odd or dr != 0 use the montgomery method */
   if (MP_HAS(S_MP_EXPTMOD_FAST) && (MP_IS_ODD(P) || (dr != 0))) {
      return s_mp_exptmod_fast(G, X, P, Y, dr);
   } else if (MP_HAS(S_MP_EXPTMOD)) {
      /* otherwise use the generic Barrett reduction technique */
      return s_mp_exptmod(G, X, P, Y, 0);
   } else {
      /* no exptmod for evens */
      return MP_VAL;
   }
}

#endif

/* End: bn_mp_exptmod.c */

/* Start: bn_mp_exteuclid.c */
#include "tommath_private.h"
#ifdef BN_MP_EXTEUCLID_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* Extended euclidean algorithm of (a, b) produces
   a*u1 + b*u2 = u3
 */
mp_err mp_exteuclid(const mp_int *a, const mp_int *b, mp_int *U1, mp_int *U2, mp_int *U3)
{
   mp_int u1, u2, u3, v1, v2, v3, t1, t2, t3, q, tmp;
   mp_err err;

   if ((err = mp_init_multi(&u1, &u2, &u3, &v1, &v2, &v3, &t1, &t2, &t3, &q, &tmp, NULL)) != MP_OKAY) {
      return err;
   }

   /* initialize, (u1,u2,u3) = (1,0,a) */
   mp_set(&u1, 1uL);
   if ((err = mp_copy(a, &u3)) != MP_OKAY)                        goto LBL_ERR;

   /* initialize, (v1,v2,v3) = (0,1,b) */
   mp_set(&v2, 1uL);
   if ((err = mp_copy(b, &v3)) != MP_OKAY)                        goto LBL_ERR;

   /* loop while v3 != 0 */
   while (!MP_IS_ZERO(&v3)) {
      /* q = u3/v3 */
      if ((err = mp_div(&u3, &v3, &q, NULL)) != MP_OKAY)          goto LBL_ERR;

      /* (t1,t2,t3) = (u1,u2,u3) - (v1,v2,v3)q */
      if ((err = mp_mul(&v1, &q, &tmp)) != MP_OKAY)               goto LBL_ERR;
      if ((err = mp_sub(&u1, &tmp, &t1)) != MP_OKAY)              goto LBL_ERR;
      if ((err = mp_mul(&v2, &q, &tmp)) != MP_OKAY)               goto LBL_ERR;
      if ((err = mp_sub(&u2, &tmp, &t2)) != MP_OKAY)              goto LBL_ERR;
      if ((err = mp_mul(&v3, &q, &tmp)) != MP_OKAY)               goto LBL_ERR;
      if ((err = mp_sub(&u3, &tmp, &t3)) != MP_OKAY)              goto LBL_ERR;

      /* (u1,u2,u3) = (v1,v2,v3) */
      if ((err = mp_copy(&v1, &u1)) != MP_OKAY)                   goto LBL_ERR;
      if ((err = mp_copy(&v2, &u2)) != MP_OKAY)                   goto LBL_ERR;
      if ((err = mp_copy(&v3, &u3)) != MP_OKAY)                   goto LBL_ERR;

      /* (v1,v2,v3) = (t1,t2,t3) */
      if ((err = mp_copy(&t1, &v1)) != MP_OKAY)                   goto LBL_ERR;
      if ((err = mp_copy(&t2, &v2)) != MP_OKAY)                   goto LBL_ERR;
      if ((err = mp_copy(&t3, &v3)) != MP_OKAY)                   goto LBL_ERR;
   }

   /* make sure U3 >= 0 */
   if (u3.sign == MP_NEG) {
      if ((err = mp_neg(&u1, &u1)) != MP_OKAY)                    goto LBL_ERR;
      if ((err = mp_neg(&u2, &u2)) != MP_OKAY)                    goto LBL_ERR;
      if ((err = mp_neg(&u3, &u3)) != MP_OKAY)                    goto LBL_ERR;
   }

   /* copy result out */
   if (U1 != NULL) {
      mp_exch(U1, &u1);
   }
   if (U2 != NULL) {
      mp_exch(U2, &u2);
   }
   if (U3 != NULL) {
      mp_exch(U3, &u3);
   }

   err = MP_OKAY;
LBL_ERR:
   mp_clear_multi(&u1, &u2, &u3, &v1, &v2, &v3, &t1, &t2, &t3, &q, &tmp, NULL);
   return err;
}
#endif

/* End: bn_mp_exteuclid.c */

/* Start: bn_mp_fread.c */
#include "tommath_private.h"
#ifdef BN_MP_FREAD_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

#ifndef MP_NO_FILE
/* read a bigint from a file stream in ASCII */
mp_err mp_fread(mp_int *a, int radix, FILE *stream)
{
   mp_err err;
   mp_sign neg;

   /* if first digit is - then set negative */
   int ch = fgetc(stream);
   if (ch == (int)'-') {
      neg = MP_NEG;
      ch = fgetc(stream);
   } else {
      neg = MP_ZPOS;
   }

   /* no digits, return error */
   if (ch == EOF) {
      return MP_ERR;
   }

   /* clear a */
   mp_zero(a);

   do {
      int y;
      unsigned pos = (unsigned)(ch - (int)'(');
      if (mp_s_rmap_reverse_sz < pos) {
         break;
      }

      y = (int)mp_s_rmap_reverse[pos];

      if ((y == 0xff) || (y >= radix)) {
         break;
      }

      /* shift up and add */
      if ((err = mp_mul_d(a, (mp_digit)radix, a)) != MP_OKAY) {
         return err;
      }
      if ((err = mp_add_d(a, (mp_digit)y, a)) != MP_OKAY) {
         return err;
      }
   } while ((ch = fgetc(stream)) != EOF);

   if (a->used != 0) {
      a->sign = neg;
   }

   return MP_OKAY;
}
#endif

#endif

/* End: bn_mp_fread.c */

/* Start: bn_mp_from_sbin.c */
#include "tommath_private.h"
#ifdef BN_MP_FROM_SBIN_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* read signed bin, big endian, first byte is 0==positive or 1==negative */
mp_err mp_from_sbin(mp_int *a, const unsigned char *buf, size_t size)
{
   mp_err err;

   /* read magnitude */
   if ((err = mp_from_ubin(a, buf + 1, size - 1u)) != MP_OKAY) {
      return err;
   }

   /* first byte is 0 for positive, non-zero for negative */
   if (buf[0] == (unsigned char)0) {
      a->sign = MP_ZPOS;
   } else {
      a->sign = MP_NEG;
   }

   return MP_OKAY;
}
#endif

/* End: bn_mp_from_sbin.c */

/* Start: bn_mp_from_ubin.c */
#include "tommath_private.h"
#ifdef BN_MP_FROM_UBIN_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* reads a unsigned char array, assumes the msb is stored first [big endian] */
mp_err mp_from_ubin(mp_int *a, const unsigned char *buf, size_t size)
{
   mp_err err;

   /* make sure there are at least two digits */
   if (a->alloc < 2) {
      if ((err = mp_grow(a, 2)) != MP_OKAY) {
         return err;
      }
   }

   /* zero the int */
   mp_zero(a);

   /* read the bytes in */
   while (size-- > 0u) {
      if ((err = mp_mul_2d(a, 8, a)) != MP_OKAY) {
         return err;
      }

#ifndef MP_8BIT
      a->dp[0] |= *buf++;
      a->used += 1;
#else
      a->dp[0] = (*buf & MP_MASK);
      a->dp[1] |= ((*buf++ >> 7) & 1u);
      a->used += 2;
#endif
   }
   mp_clamp(a);
   return MP_OKAY;
}
#endif

/* End: bn_mp_from_ubin.c */

/* Start: bn_mp_fwrite.c */
#include "tommath_private.h"
#ifdef BN_MP_FWRITE_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

#ifndef MP_NO_FILE
mp_err mp_fwrite(const mp_int *a, int radix, FILE *stream)
{
   char *buf;
   mp_err err;
   int len;
   size_t written;

   /* TODO: this function is not in this PR */
   if (MP_HAS(MP_RADIX_SIZE_OVERESTIMATE)) {
      /* if ((err = mp_radix_size_overestimate(&t, base, &len)) != MP_OKAY)      goto LBL_ERR; */
   } else {
      if ((err = mp_radix_size(a, radix, &len)) != MP_OKAY) {
         return err;
      }
   }

   buf = (char *) MP_MALLOC((size_t)len);
   if (buf == NULL) {
      return MP_MEM;
   }

   if ((err = mp_to_radix(a, buf, (size_t)len, &written, radix)) != MP_OKAY) {
      goto LBL_ERR;
   }

   if (fwrite(buf, written, 1uL, stream) != 1uL) {
      err = MP_ERR;
      goto LBL_ERR;
   }
   err = MP_OKAY;


LBL_ERR:
   MP_FREE_BUFFER(buf, (size_t)len);
   return err;
}
#endif

#endif

/* End: bn_mp_fwrite.c */

/* Start: bn_mp_gcd.c */
#include "tommath_private.h"
#ifdef BN_MP_GCD_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* Greatest Common Divisor using the binary method */
mp_err mp_gcd(const mp_int *a, const mp_int *b, mp_int *c)
{
   mp_int  u, v;
   int     k, u_lsb, v_lsb;
   mp_err err;

   /* either zero than gcd is the largest */
   if (MP_IS_ZERO(a)) {
      return mp_abs(b, c);
   }
   if (MP_IS_ZERO(b)) {
      return mp_abs(a, c);
   }

   /* get copies of a and b we can modify */
   if ((err = mp_init_copy(&u, a)) != MP_OKAY) {
      return err;
   }

   if ((err = mp_init_copy(&v, b)) != MP_OKAY) {
      goto LBL_U;
   }

   /* must be positive for the remainder of the algorithm */
   u.sign = v.sign = MP_ZPOS;

   /* B1.  Find the common power of two for u and v */
   u_lsb = mp_cnt_lsb(&u);
   v_lsb = mp_cnt_lsb(&v);
   k     = MP_MIN(u_lsb, v_lsb);

   if (k > 0) {
      /* divide the power of two out */
      if ((err = mp_div_2d(&u, k, &u, NULL)) != MP_OKAY) {
         goto LBL_V;
      }

      if ((err = mp_div_2d(&v, k, &v, NULL)) != MP_OKAY) {
         goto LBL_V;
      }
   }

   /* divide any remaining factors of two out */
   if (u_lsb != k) {
      if ((err = mp_div_2d(&u, u_lsb - k, &u, NULL)) != MP_OKAY) {
         goto LBL_V;
      }
   }

   if (v_lsb != k) {
      if ((err = mp_div_2d(&v, v_lsb - k, &v, NULL)) != MP_OKAY) {
         goto LBL_V;
      }
   }

   while (!MP_IS_ZERO(&v)) {
      /* make sure v is the largest */
      if (mp_cmp_mag(&u, &v) == MP_GT) {
         /* swap u and v to make sure v is >= u */
         mp_exch(&u, &v);
      }

      /* subtract smallest from largest */
      if ((err = s_mp_sub(&v, &u, &v)) != MP_OKAY) {
         goto LBL_V;
      }

      /* Divide out all factors of two */
      if ((err = mp_div_2d(&v, mp_cnt_lsb(&v), &v, NULL)) != MP_OKAY) {
         goto LBL_V;
      }
   }

   /* multiply by 2**k which we divided out at the beginning */
   if ((err = mp_mul_2d(&u, k, c)) != MP_OKAY) {
      goto LBL_V;
   }
   c->sign = MP_ZPOS;
   err = MP_OKAY;
LBL_V:
   mp_clear(&u);
LBL_U:
   mp_clear(&v);
   return err;
}
#endif

/* End: bn_mp_gcd.c */

/* Start: bn_mp_get_double.c */
#include "tommath_private.h"
#ifdef BN_MP_GET_DOUBLE_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

double mp_get_double(const mp_int *a)
{
   int i;
   double d = 0.0, fac = 1.0;
   for (i = 0; i < MP_DIGIT_BIT; ++i) {
      fac *= 2.0;
   }
   for (i = a->used; i --> 0;) {
      d = (d * fac) + (double)a->dp[i];
   }
   return (a->sign == MP_NEG) ? -d : d;
}
#endif

/* End: bn_mp_get_double.c */

/* Start: bn_mp_get_i32.c */
#include "tommath_private.h"
#ifdef BN_MP_GET_I32_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

MP_GET_SIGNED(mp_get_i32, mp_get_mag_u32, int32_t, uint32_t)
#endif

/* End: bn_mp_get_i32.c */

/* Start: bn_mp_get_i64.c */
#include "tommath_private.h"
#ifdef BN_MP_GET_I64_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

MP_GET_SIGNED(mp_get_i64, mp_get_mag_u64, int64_t, uint64_t)
#endif

/* End: bn_mp_get_i64.c */

/* Start: bn_mp_get_l.c */
#include "tommath_private.h"
#ifdef BN_MP_GET_L_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

MP_GET_SIGNED(mp_get_l, mp_get_mag_ul, long, unsigned long)
#endif

/* End: bn_mp_get_l.c */

/* Start: bn_mp_get_ll.c */
#include "tommath_private.h"
#ifdef BN_MP_GET_LL_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

MP_GET_SIGNED(mp_get_ll, mp_get_mag_ull, long long, unsigned long long)
#endif

/* End: bn_mp_get_ll.c */

/* Start: bn_mp_get_mag_u32.c */
#include "tommath_private.h"
#ifdef BN_MP_GET_MAG_U32_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

MP_GET_MAG(mp_get_mag_u32, uint32_t)
#endif

/* End: bn_mp_get_mag_u32.c */

/* Start: bn_mp_get_mag_u64.c */
#include "tommath_private.h"
#ifdef BN_MP_GET_MAG_U64_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

MP_GET_MAG(mp_get_mag_u64, uint64_t)
#endif

/* End: bn_mp_get_mag_u64.c */

/* Start: bn_mp_get_mag_ul.c */
#include "tommath_private.h"
#ifdef BN_MP_GET_MAG_UL_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

MP_GET_MAG(mp_get_mag_ul, unsigned long)
#endif

/* End: bn_mp_get_mag_ul.c */

/* Start: bn_mp_get_mag_ull.c */
#include "tommath_private.h"
#ifdef BN_MP_GET_MAG_ULL_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

MP_GET_MAG(mp_get_mag_ull, unsigned long long)
#endif

/* End: bn_mp_get_mag_ull.c */

/* Start: bn_mp_grow.c */
#include "tommath_private.h"
#ifdef BN_MP_GROW_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* grow as required */
mp_err mp_grow(mp_int *a, int size)
{
   int     i;
   mp_digit *tmp;

   /* if the alloc size is smaller alloc more ram */
   if (a->alloc < size) {
      /* reallocate the array a->dp
       *
       * We store the return in a temporary variable
       * in case the operation failed we don't want
       * to overwrite the dp member of a.
       */
      tmp = (mp_digit *) MP_REALLOC(a->dp,
                                    (size_t)a->alloc * sizeof(mp_digit),
                                    (size_t)size * sizeof(mp_digit));
      if (tmp == NULL) {
         /* reallocation failed but "a" is still valid [can be freed] */
         return MP_MEM;
      }

      /* reallocation succeeded so set a->dp */
      a->dp = tmp;

      /* zero excess digits */
      i        = a->alloc;
      a->alloc = size;
      MP_ZERO_DIGITS(a->dp + i, a->alloc - i);
   }
   return MP_OKAY;
}
#endif

/* End: bn_mp_grow.c */

/* Start: bn_mp_incr.c */
#include "tommath_private.h"
#ifdef BN_MP_INCR_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* Increment "a" by one like "a++". Changes input! */
mp_err mp_incr(mp_int *a)
{
   if (MP_IS_ZERO(a)) {
      mp_set(a,1uL);
      return MP_OKAY;
   } else if (a->sign == MP_NEG) {
      mp_err err;
      a->sign = MP_ZPOS;
      if ((err = mp_decr(a)) != MP_OKAY) {
         return err;
      }
      /* There is no -0 in LTM */
      if (!MP_IS_ZERO(a)) {
         a->sign = MP_NEG;
      }
      return MP_OKAY;
   } else if (a->dp[0] < MP_DIGIT_MAX) {
      a->dp[0]++;
      return MP_OKAY;
   } else {
      return mp_add_d(a, 1uL,a);
   }
}
#endif

/* End: bn_mp_incr.c */

/* Start: bn_mp_init.c */
#include "tommath_private.h"
#ifdef BN_MP_INIT_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* init a new mp_int */
mp_err mp_init(mp_int *a)
{
   /* allocate memory required and clear it */
   a->dp = (mp_digit *) MP_CALLOC((size_t)MP_PREC, sizeof(mp_digit));
   if (a->dp == NULL) {
      return MP_MEM;
   }

   /* set the used to zero, allocated digits to the default precision
    * and sign to positive */
   a->used  = 0;
   a->alloc = MP_PREC;
   a->sign  = MP_ZPOS;

   return MP_OKAY;
}
#endif

/* End: bn_mp_init.c */

/* Start: bn_mp_init_copy.c */
#include "tommath_private.h"
#ifdef BN_MP_INIT_COPY_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* creates "a" then copies b into it */
mp_err mp_init_copy(mp_int *a, const mp_int *b)
{
   mp_err     err;

   if ((err = mp_init_size(a, b->used)) != MP_OKAY) {
      return err;
   }

   if ((err = mp_copy(b, a)) != MP_OKAY) {
      mp_clear(a);
   }

   return err;
}
#endif

/* End: bn_mp_init_copy.c */

/* Start: bn_mp_init_i32.c */
#include "tommath_private.h"
#ifdef BN_MP_INIT_I32_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

MP_INIT_INT(mp_init_i32, mp_set_i32, int32_t)
#endif

/* End: bn_mp_init_i32.c */

/* Start: bn_mp_init_i64.c */
#include "tommath_private.h"
#ifdef BN_MP_INIT_I64_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

MP_INIT_INT(mp_init_i64, mp_set_i64, int64_t)
#endif

/* End: bn_mp_init_i64.c */

/* Start: bn_mp_init_l.c */
#include "tommath_private.h"
#ifdef BN_MP_INIT_L_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

MP_INIT_INT(mp_init_l, mp_set_l, long)
#endif

/* End: bn_mp_init_l.c */

/* Start: bn_mp_init_ll.c */
#include "tommath_private.h"
#ifdef BN_MP_INIT_LL_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

MP_INIT_INT(mp_init_ll, mp_set_ll, long long)
#endif

/* End: bn_mp_init_ll.c */

/* Start: bn_mp_init_multi.c */
#include "tommath_private.h"
#ifdef BN_MP_INIT_MULTI_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

#include <stdarg.h>

mp_err mp_init_multi(mp_int *mp, ...)
{
   mp_err err = MP_OKAY;      /* Assume ok until proven otherwise */
   int n = 0;                 /* Number of ok inits */
   mp_int *cur_arg = mp;
   va_list args;

   va_start(args, mp);        /* init args to next argument from caller */
   while (cur_arg != NULL) {
      if (mp_init(cur_arg) != MP_OKAY) {
         /* Oops - error! Back-track and mp_clear what we already
            succeeded in init-ing, then return error.
         */
         va_list clean_args;

         /* now start cleaning up */
         cur_arg = mp;
         va_start(clean_args, mp);
         while (n-- != 0) {
            mp_clear(cur_arg);
            cur_arg = va_arg(clean_args, mp_int *);
         }
         va_end(clean_args);
         err = MP_MEM;
         break;
      }
      n++;
      cur_arg = va_arg(args, mp_int *);
   }
   va_end(args);
   return err;                /* Assumed ok, if error flagged above. */
}

#endif

/* End: bn_mp_init_multi.c */

/* Start: bn_mp_init_set.c */
#include "tommath_private.h"
#ifdef BN_MP_INIT_SET_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* initialize and set a digit */
mp_err mp_init_set(mp_int *a, mp_digit b)
{
   mp_err err;
   if ((err = mp_init(a)) != MP_OKAY) {
      return err;
   }
   mp_set(a, b);
   return err;
}
#endif

/* End: bn_mp_init_set.c */

/* Start: bn_mp_init_size.c */
#include "tommath_private.h"
#ifdef BN_MP_INIT_SIZE_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* init an mp_init for a given size */
mp_err mp_init_size(mp_int *a, int size)
{
   size = MP_MAX(MP_MIN_PREC, size);

   /* alloc mem */
   a->dp = (mp_digit *) MP_CALLOC((size_t)size, sizeof(mp_digit));
   if (a->dp == NULL) {
      return MP_MEM;
   }

   /* set the members */
   a->used  = 0;
   a->alloc = size;
   a->sign  = MP_ZPOS;

   return MP_OKAY;
}
#endif

/* End: bn_mp_init_size.c */

/* Start: bn_mp_init_u32.c */
#include "tommath_private.h"
#ifdef BN_MP_INIT_U32_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

MP_INIT_INT(mp_init_u32, mp_set_u32, uint32_t)
#endif

/* End: bn_mp_init_u32.c */

/* Start: bn_mp_init_u64.c */
#include "tommath_private.h"
#ifdef BN_MP_INIT_U64_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

MP_INIT_INT(mp_init_u64, mp_set_u64, uint64_t)
#endif

/* End: bn_mp_init_u64.c */

/* Start: bn_mp_init_ul.c */
#include "tommath_private.h"
#ifdef BN_MP_INIT_UL_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

MP_INIT_INT(mp_init_ul, mp_set_ul, unsigned long)
#endif

/* End: bn_mp_init_ul.c */

/* Start: bn_mp_init_ull.c */
#include "tommath_private.h"
#ifdef BN_MP_INIT_ULL_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

MP_INIT_INT(mp_init_ull, mp_set_ull, unsigned long long)
#endif

/* End: bn_mp_init_ull.c */

/* Start: bn_mp_invmod.c */
#include "tommath_private.h"
#ifdef BN_MP_INVMOD_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* hac 14.61, pp608 */
mp_err mp_invmod(const mp_int *a, const mp_int *b, mp_int *c)
{
   /* b cannot be negative and has to be >1 */
   if ((b->sign == MP_NEG) || (mp_cmp_d(b, 1uL) != MP_GT)) {
      return MP_VAL;
   }

   /* if the modulus is odd we can use a faster routine instead */
   if (MP_HAS(S_MP_INVMOD_FAST) && MP_IS_ODD(b)) {
      return s_mp_invmod_fast(a, b, c);
   }

   return MP_HAS(S_MP_INVMOD_SLOW)
          ? s_mp_invmod_slow(a, b, c)
          : MP_VAL;
}
#endif

/* End: bn_mp_invmod.c */

/* Start: bn_mp_is_square.c */
#include "tommath_private.h"
#ifdef BN_MP_IS_SQUARE_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* Check if remainders are possible squares - fast exclude non-squares */
static const char rem_128[128] = {
   0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1,
   0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1,
   1, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1,
   1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1,
   0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1,
   1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1,
   1, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1,
   1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1
};

static const char rem_105[105] = {
   0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1,
   0, 0, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1,
   0, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1,
   1, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1,
   0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1,
   1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1,
   1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1
};

/* Store non-zero to ret if arg is square, and zero if not */
mp_err mp_is_square(const mp_int *arg, mp_bool *ret)
{
   mp_err        err;
   mp_digit      c;
   mp_int        t;
   unsigned long r;

   /* Default to Non-square :) */
   *ret = MP_NO;

   if (arg->sign == MP_NEG) {
      return MP_VAL;
   }

   if (MP_IS_ZERO(arg)) {
      return MP_OKAY;
   }

   /* First check mod 128 (suppose that MP_DIGIT_BIT is at least 7) */
   if (rem_128[127u & arg->dp[0]] == (char)1) {
      return MP_OKAY;
   }

   /* Next check mod 105 (3*5*7) */
   if ((err = mp_mod_d(arg, 105uL, &c)) != MP_OKAY) {
      return err;
   }
   if (rem_105[c] == (char)1) {
      return MP_OKAY;
   }


   if ((err = mp_init_u32(&t, 11u*13u*17u*19u*23u*29u*31u)) != MP_OKAY) {
      return err;
   }
   if ((err = mp_mod(arg, &t, &t)) != MP_OKAY) {
      goto LBL_ERR;
   }
   r = mp_get_u32(&t);
   /* Check for other prime modules, note it's not an ERROR but we must
    * free "t" so the easiest way is to goto LBL_ERR.  We know that err
    * is already equal to MP_OKAY from the mp_mod call
    */
   if (((1uL<<(r%11uL)) & 0x5C4uL) != 0uL)         goto LBL_ERR;
   if (((1uL<<(r%13uL)) & 0x9E4uL) != 0uL)         goto LBL_ERR;
   if (((1uL<<(r%17uL)) & 0x5CE8uL) != 0uL)        goto LBL_ERR;
   if (((1uL<<(r%19uL)) & 0x4F50CuL) != 0uL)       goto LBL_ERR;
   if (((1uL<<(r%23uL)) & 0x7ACCA0uL) != 0uL)      goto LBL_ERR;
   if (((1uL<<(r%29uL)) & 0xC2EDD0CuL) != 0uL)     goto LBL_ERR;
   if (((1uL<<(r%31uL)) & 0x6DE2B848uL) != 0uL)    goto LBL_ERR;

   /* Final check - is sqr(sqrt(arg)) == arg ? */
   if ((err = mp_sqrt(arg, &t)) != MP_OKAY) {
      goto LBL_ERR;
   }
   if ((err = mp_sqr(&t, &t)) != MP_OKAY) {
      goto LBL_ERR;
   }

   *ret = (mp_cmp_mag(&t, arg) == MP_EQ) ? MP_YES : MP_NO;
LBL_ERR:
   mp_clear(&t);
   return err;
}
#endif

/* End: bn_mp_is_square.c */

/* Start: bn_mp_iseven.c */
#include "tommath_private.h"
#ifdef BN_MP_ISEVEN_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

mp_bool mp_iseven(const mp_int *a)
{
   return MP_IS_EVEN(a) ? MP_YES : MP_NO;
}
#endif

/* End: bn_mp_iseven.c */

/* Start: bn_mp_isodd.c */
#include "tommath_private.h"
#ifdef BN_MP_ISODD_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

mp_bool mp_isodd(const mp_int *a)
{
   return MP_IS_ODD(a) ? MP_YES : MP_NO;
}
#endif

/* End: bn_mp_isodd.c */

/* Start: bn_mp_kronecker.c */
#include "tommath_private.h"
#ifdef BN_MP_KRONECKER_C

/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/*
   Kronecker symbol (a|p)
   Straightforward implementation of algorithm 1.4.10 in
   Henri Cohen: "A Course in Computational Algebraic Number Theory"

   @book{cohen2013course,
     title={A course in computational algebraic number theory},
     author={Cohen, Henri},
     volume={138},
     year={2013},
     publisher={Springer Science \& Business Media}
    }
 */
mp_err mp_kronecker(const mp_int *a, const mp_int *p, int *c)
{
   mp_int a1, p1, r;
   mp_err err;
   int v, k;

   static const int table[8] = {0, 1, 0, -1, 0, -1, 0, 1};

   if (MP_IS_ZERO(p)) {
      if ((a->used == 1) && (a->dp[0] == 1u)) {
         *c = 1;
      } else {
         *c = 0;
      }
      return MP_OKAY;
   }

   if (MP_IS_EVEN(a) && MP_IS_EVEN(p)) {
      *c = 0;
      return MP_OKAY;
   }

   if ((err = mp_init_copy(&a1, a)) != MP_OKAY) {
      return err;
   }
   if ((err = mp_init_copy(&p1, p)) != MP_OKAY) {
      goto LBL_KRON_0;
   }

   v = mp_cnt_lsb(&p1);
   if ((err = mp_div_2d(&p1, v, &p1, NULL)) != MP_OKAY) {
      goto LBL_KRON_1;
   }

   if ((v & 1) == 0) {
      k = 1;
   } else {
      k = table[a->dp[0] & 7u];
   }

   if (p1.sign == MP_NEG) {
      p1.sign = MP_ZPOS;
      if (a1.sign == MP_NEG) {
         k = -k;
      }
   }

   if ((err = mp_init(&r)) != MP_OKAY) {
      goto LBL_KRON_1;
   }

   for (;;) {
      if (MP_IS_ZERO(&a1)) {
         if (mp_cmp_d(&p1, 1uL) == MP_EQ) {
            *c = k;
            goto LBL_KRON;
         } else {
            *c = 0;
            goto LBL_KRON;
         }
      }

      v = mp_cnt_lsb(&a1);
      if ((err = mp_div_2d(&a1, v, &a1, NULL)) != MP_OKAY) {
         goto LBL_KRON;
      }

      if ((v & 1) == 1) {
         k = k * table[p1.dp[0] & 7u];
      }

      if (a1.sign == MP_NEG) {
         /*
          * Compute k = (-1)^((a1)*(p1-1)/4) * k
          * a1.dp[0] + 1 cannot overflow because the MSB
          * of the type mp_digit is not set by definition
          */
         if (((a1.dp[0] + 1u) & p1.dp[0] & 2u) != 0u) {
            k = -k;
         }
      } else {
         /* compute k = (-1)^((a1-1)*(p1-1)/4) * k */
         if ((a1.dp[0] & p1.dp[0] & 2u) != 0u) {
            k = -k;
         }
      }

      if ((err = mp_copy(&a1, &r)) != MP_OKAY) {
         goto LBL_KRON;
      }
      r.sign = MP_ZPOS;
      if ((err = mp_mod(&p1, &r, &a1)) != MP_OKAY) {
         goto LBL_KRON;
      }
      if ((err = mp_copy(&r, &p1)) != MP_OKAY) {
         goto LBL_KRON;
      }
   }

LBL_KRON:
   mp_clear(&r);
LBL_KRON_1:
   mp_clear(&p1);
LBL_KRON_0:
   mp_clear(&a1);

   return err;
}

#endif

/* End: bn_mp_kronecker.c */

/* Start: bn_mp_lcm.c */
#include "tommath_private.h"
#ifdef BN_MP_LCM_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* computes least common multiple as |a*b|/(a, b) */
mp_err mp_lcm(const mp_int *a, const mp_int *b, mp_int *c)
{
   mp_err  err;
   mp_int  t1, t2;


   if ((err = mp_init_multi(&t1, &t2, NULL)) != MP_OKAY) {
      return err;
   }

   /* t1 = get the GCD of the two inputs */
   if ((err = mp_gcd(a, b, &t1)) != MP_OKAY) {
      goto LBL_T;
   }

   /* divide the smallest by the GCD */
   if (mp_cmp_mag(a, b) == MP_LT) {
      /* store quotient in t2 such that t2 * b is the LCM */
      if ((err = mp_div(a, &t1, &t2, NULL)) != MP_OKAY) {
         goto LBL_T;
      }
      err = mp_mul(b, &t2, c);
   } else {
      /* store quotient in t2 such that t2 * a is the LCM */
      if ((err = mp_div(b, &t1, &t2, NULL)) != MP_OKAY) {
         goto LBL_T;
      }
      err = mp_mul(a, &t2, c);
   }

   /* fix the sign to positive */
   c->sign = MP_ZPOS;

LBL_T:
   mp_clear_multi(&t1, &t2, NULL);
   return err;
}
#endif

/* End: bn_mp_lcm.c */

/* Start: bn_mp_log_u32.c */
#include "tommath_private.h"
#ifdef BN_MP_LOG_U32_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* Compute log_{base}(a) */
static mp_word s_pow(mp_word base, mp_word exponent)
{
   mp_word result = 1uLL;
   while (exponent != 0u) {
      if ((exponent & 1u) == 1u) {
         result *= base;
      }
      exponent >>= 1;
      base *= base;
   }

   return result;
}

static mp_digit s_digit_ilogb(mp_digit base, mp_digit n)
{
   mp_word bracket_low = 1uLL, bracket_mid, bracket_high, N;
   mp_digit ret, high = 1uL, low = 0uL, mid;

   if (n < base) {
      return 0uL;
   }
   if (n == base) {
      return 1uL;
   }

   bracket_high = (mp_word) base ;
   N = (mp_word) n;

   while (bracket_high < N) {
      low = high;
      bracket_low = bracket_high;
      high <<= 1;
      bracket_high *= bracket_high;
   }

   while (((mp_digit)(high - low)) > 1uL) {
      mid = (low + high) >> 1;
      bracket_mid = bracket_low * s_pow(base, (mp_word)(mid - low));

      if (N < bracket_mid) {
         high = mid ;
         bracket_high = bracket_mid ;
      }
      if (N > bracket_mid) {
         low = mid ;
         bracket_low = bracket_mid ;
      }
      if (N == bracket_mid) {
         return (mp_digit) mid;
      }
   }

   if (bracket_high == N) {
      ret = high;
   } else {
      ret = low;
   }

   return ret;
}

/* TODO: output could be "int" because the output of mp_radix_size is int, too,
         as is the output of mp_bitcount.
         With the same problem: max size is INT_MAX * MP_DIGIT not INT_MAX only!
*/
mp_err mp_log_u32(const mp_int *a, uint32_t base, uint32_t *c)
{
   mp_err err;
   mp_ord cmp;
   uint32_t high, low, mid;
   mp_int bracket_low, bracket_high, bracket_mid, t, bi_base;

   err = MP_OKAY;

   if (a->sign == MP_NEG) {
      return MP_VAL;
   }

   if (MP_IS_ZERO(a)) {
      return MP_VAL;
   }

   if (base < 2u) {
      return MP_VAL;
   }

   /* A small shortcut for bases that are powers of two. */
   if ((base & (base - 1u)) == 0u) {
      int y, bit_count;
      for (y=0; (y < 7) && ((base & 1u) == 0u); y++) {
         base >>= 1;
      }
      bit_count = mp_count_bits(a) - 1;
      *c = (uint32_t)(bit_count/y);
      return MP_OKAY;
   }

   if (a->used == 1) {
      *c = (uint32_t)s_digit_ilogb(base, a->dp[0]);
      return err;
   }

   cmp = mp_cmp_d(a, base);
   if ((cmp == MP_LT) || (cmp == MP_EQ)) {
      *c = cmp == MP_EQ;
      return err;
   }

   if ((err =
           mp_init_multi(&bracket_low, &bracket_high,
                         &bracket_mid, &t, &bi_base, NULL)) != MP_OKAY) {
      return err;
   }

   low = 0u;
   mp_set(&bracket_low, 1uL);
   high = 1u;

   mp_set(&bracket_high, base);

   /*
       A kind of Giant-step/baby-step algorithm.
       Idea shamelessly stolen from https://programmingpraxis.com/2010/05/07/integer-logarithms/2/
       The effect is asymptotic, hence needs benchmarks to test if the Giant-step should be skipped
       for small n.
    */
   while (mp_cmp(&bracket_high, a) == MP_LT) {
      low = high;
      if ((err = mp_copy(&bracket_high, &bracket_low)) != MP_OKAY) {
         goto LBL_ERR;
      }
      high <<= 1;
      if ((err = mp_sqr(&bracket_high, &bracket_high)) != MP_OKAY) {
         goto LBL_ERR;
      }
   }
   mp_set(&bi_base, base);

   while ((high - low) > 1u) {
      mid = (high + low) >> 1;

      if ((err = mp_expt_u32(&bi_base, (uint32_t)(mid - low), &t)) != MP_OKAY) {
         goto LBL_ERR;
      }
      if ((err = mp_mul(&bracket_low, &t, &bracket_mid)) != MP_OKAY) {
         goto LBL_ERR;
      }
      cmp = mp_cmp(a, &bracket_mid);
      if (cmp == MP_LT) {
         high = mid;
         mp_exch(&bracket_mid, &bracket_high);
      }
      if (cmp == MP_GT) {
         low = mid;
         mp_exch(&bracket_mid, &bracket_low);
      }
      if (cmp == MP_EQ) {
         *c = mid;
         goto LBL_END;
      }
   }

   *c = (mp_cmp(&bracket_high, a) == MP_EQ) ? high : low;

LBL_END:
LBL_ERR:
   mp_clear_multi(&bracket_low, &bracket_high, &bracket_mid,
                  &t, &bi_base, NULL);
   return err;
}


#endif

/* End: bn_mp_log_u32.c */

/* Start: bn_mp_lshd.c */
#include "tommath_private.h"
#ifdef BN_MP_LSHD_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* shift left a certain amount of digits */
mp_err mp_lshd(mp_int *a, int b)
{
   int x;
   mp_err err;
   mp_digit *top, *bottom;

   /* if its less than zero return */
   if (b <= 0) {
      return MP_OKAY;
   }
   /* no need to shift 0 around */
   if (MP_IS_ZERO(a)) {
      return MP_OKAY;
   }

   /* grow to fit the new digits */
   if (a->alloc < (a->used + b)) {
      if ((err = mp_grow(a, a->used + b)) != MP_OKAY) {
         return err;
      }
   }

   /* increment the used by the shift amount then copy upwards */
   a->used += b;

   /* top */
   top = a->dp + a->used - 1;

   /* base */
   bottom = (a->dp + a->used - 1) - b;

   /* much like mp_rshd this is implemented using a sliding window
    * except the window goes the otherway around.  Copying from
    * the bottom to the top.  see bn_mp_rshd.c for more info.
    */
   for (x = a->used - 1; x >= b; x--) {
      *top-- = *bottom--;
   }

   /* zero the lower digits */
   MP_ZERO_DIGITS(a->dp, b);

   return MP_OKAY;
}
#endif

/* End: bn_mp_lshd.c */

/* Start: bn_mp_mod.c */
#include "tommath_private.h"
#ifdef BN_MP_MOD_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* c = a mod b, 0 <= c < b if b > 0, b < c <= 0 if b < 0 */
mp_err mp_mod(const mp_int *a, const mp_int *b, mp_int *c)
{
   mp_int  t;
   mp_err  err;

   if ((err = mp_init_size(&t, b->used)) != MP_OKAY) {
      return err;
   }

   if ((err = mp_div(a, b, NULL, &t)) != MP_OKAY) {
      goto LBL_ERR;
   }

   if (MP_IS_ZERO(&t) || (t.sign == b->sign)) {
      err = MP_OKAY;
      mp_exch(&t, c);
   } else {
      err = mp_add(b, &t, c);
   }

LBL_ERR:
   mp_clear(&t);
   return err;
}
#endif

/* End: bn_mp_mod.c */

/* Start: bn_mp_mod_2d.c */
#include "tommath_private.h"
#ifdef BN_MP_MOD_2D_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* calc a value mod 2**b */
mp_err mp_mod_2d(const mp_int *a, int b, mp_int *c)
{
   int x;
   mp_err err;

   /* if b is <= 0 then zero the int */
   if (b <= 0) {
      mp_zero(c);
      return MP_OKAY;
   }

   /* if the modulus is larger than the value than return */
   if (b >= (a->used * MP_DIGIT_BIT)) {
      return mp_copy(a, c);
   }

   /* copy */
   if ((err = mp_copy(a, c)) != MP_OKAY) {
      return err;
   }

   /* zero digits above the last digit of the modulus */
   x = (b / MP_DIGIT_BIT) + (((b % MP_DIGIT_BIT) == 0) ? 0 : 1);
   MP_ZERO_DIGITS(c->dp + x, c->used - x);

   /* clear the digit that is not completely outside/inside the modulus */
   c->dp[b / MP_DIGIT_BIT] &=
      ((mp_digit)1 << (mp_digit)(b % MP_DIGIT_BIT)) - (mp_digit)1;
   mp_clamp(c);
   return MP_OKAY;
}
#endif

/* End: bn_mp_mod_2d.c */

/* Start: bn_mp_mod_d.c */
#include "tommath_private.h"
#ifdef BN_MP_MOD_D_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

mp_err mp_mod_d(const mp_int *a, mp_digit b, mp_digit *c)
{
   return mp_div_d(a, b, NULL, c);
}
#endif

/* End: bn_mp_mod_d.c */

/* Start: bn_mp_montgomery_calc_normalization.c */
#include "tommath_private.h"
#ifdef BN_MP_MONTGOMERY_CALC_NORMALIZATION_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/*
 * shifts with subtractions when the result is greater than b.
 *
 * The method is slightly modified to shift B unconditionally upto just under
 * the leading bit of b.  This saves alot of multiple precision shifting.
 */
mp_err mp_montgomery_calc_normalization(mp_int *a, const mp_int *b)
{
   int    x, bits;
   mp_err err;

   /* how many bits of last digit does b use */
   bits = mp_count_bits(b) % MP_DIGIT_BIT;

   if (b->used > 1) {
      if ((err = mp_2expt(a, ((b->used - 1) * MP_DIGIT_BIT) + bits - 1)) != MP_OKAY) {
         return err;
      }
   } else {
      mp_set(a, 1uL);
      bits = 1;
   }


   /* now compute C = A * B mod b */
   for (x = bits - 1; x < (int)MP_DIGIT_BIT; x++) {
      if ((err = mp_mul_2(a, a)) != MP_OKAY) {
         return err;
      }
      if (mp_cmp_mag(a, b) != MP_LT) {
         if ((err = s_mp_sub(a, b, a)) != MP_OKAY) {
            return err;
         }
      }
   }

   return MP_OKAY;
}
#endif

/* End: bn_mp_montgomery_calc_normalization.c */

/* Start: bn_mp_montgomery_reduce.c */
#include "tommath_private.h"
#ifdef BN_MP_MONTGOMERY_REDUCE_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* computes xR**-1 == x (mod N) via Montgomery Reduction */
mp_err mp_montgomery_reduce(mp_int *x, const mp_int *n, mp_digit rho)
{
   int      ix, digs;
   mp_err   err;
   mp_digit mu;

   /* can the fast reduction [comba] method be used?
    *
    * Note that unlike in mul you're safely allowed *less*
    * than the available columns [255 per default] since carries
    * are fixed up in the inner loop.
    */
   digs = (n->used * 2) + 1;
   if ((digs < MP_WARRAY) &&
       (x->used <= MP_WARRAY) &&
       (n->used < MP_MAXFAST)) {
      return s_mp_montgomery_reduce_fast(x, n, rho);
   }

   /* grow the input as required */
   if (x->alloc < digs) {
      if ((err = mp_grow(x, digs)) != MP_OKAY) {
         return err;
      }
   }
   x->used = digs;

   for (ix = 0; ix < n->used; ix++) {
      /* mu = ai * rho mod b
       *
       * The value of rho must be precalculated via
       * montgomery_setup() such that
       * it equals -1/n0 mod b this allows the
       * following inner loop to reduce the
       * input one digit at a time
       */
      mu = (mp_digit)(((mp_word)x->dp[ix] * (mp_word)rho) & MP_MASK);

      /* a = a + mu * m * b**i */
      {
         int iy;
         mp_digit *tmpn, *tmpx, u;
         mp_word r;

         /* alias for digits of the modulus */
         tmpn = n->dp;

         /* alias for the digits of x [the input] */
         tmpx = x->dp + ix;

         /* set the carry to zero */
         u = 0;

         /* Multiply and add in place */
         for (iy = 0; iy < n->used; iy++) {
            /* compute product and sum */
            r       = ((mp_word)mu * (mp_word)*tmpn++) +
                      (mp_word)u + (mp_word)*tmpx;

            /* get carry */
            u       = (mp_digit)(r >> (mp_word)MP_DIGIT_BIT);

            /* fix digit */
            *tmpx++ = (mp_digit)(r & (mp_word)MP_MASK);
         }
         /* At this point the ix'th digit of x should be zero */


         /* propagate carries upwards as required*/
         while (u != 0u) {
            *tmpx   += u;
            u        = *tmpx >> MP_DIGIT_BIT;
            *tmpx++ &= MP_MASK;
         }
      }
   }

   /* at this point the n.used'th least
    * significant digits of x are all zero
    * which means we can shift x to the
    * right by n.used digits and the
    * residue is unchanged.
    */

   /* x = x/b**n.used */
   mp_clamp(x);
   mp_rshd(x, n->used);

   /* if x >= n then x = x - n */
   if (mp_cmp_mag(x, n) != MP_LT) {
      return s_mp_sub(x, n, x);
   }

   return MP_OKAY;
}
#endif

/* End: bn_mp_montgomery_reduce.c */

/* Start: bn_mp_montgomery_setup.c */
#include "tommath_private.h"
#ifdef BN_MP_MONTGOMERY_SETUP_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* setups the montgomery reduction stuff */
mp_err mp_montgomery_setup(const mp_int *n, mp_digit *rho)
{
   mp_digit x, b;

   /* fast inversion mod 2**k
    *
    * Based on the fact that
    *
    * XA = 1 (mod 2**n)  =>  (X(2-XA)) A = 1 (mod 2**2n)
    *                    =>  2*X*A - X*X*A*A = 1
    *                    =>  2*(1) - (1)     = 1
    */
   b = n->dp[0];

   if ((b & 1u) == 0u) {
      return MP_VAL;
   }

   x = (((b + 2u) & 4u) << 1) + b; /* here x*a==1 mod 2**4 */
   x *= 2u - (b * x);              /* here x*a==1 mod 2**8 */
#if !defined(MP_8BIT)
   x *= 2u - (b * x);              /* here x*a==1 mod 2**16 */
#endif
#if defined(MP_64BIT) || !(defined(MP_8BIT) || defined(MP_16BIT))
   x *= 2u - (b * x);              /* here x*a==1 mod 2**32 */
#endif
#ifdef MP_64BIT
   x *= 2u - (b * x);              /* here x*a==1 mod 2**64 */
#endif

   /* rho = -1/m mod b */
   *rho = (mp_digit)(((mp_word)1 << (mp_word)MP_DIGIT_BIT) - x) & MP_MASK;

   return MP_OKAY;
}
#endif

/* End: bn_mp_montgomery_setup.c */

/* Start: bn_mp_mul.c */
#include "tommath_private.h"
#ifdef BN_MP_MUL_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* high level multiplication (handles sign) */
mp_err mp_mul(const mp_int *a, const mp_int *b, mp_int *c)
{
   mp_err err;
   int min_len = MP_MIN(a->used, b->used),
       max_len = MP_MAX(a->used, b->used),
       digs = a->used + b->used + 1;
   mp_sign neg = (a->sign == b->sign) ? MP_ZPOS : MP_NEG;

   if (MP_HAS(S_MP_BALANCE_MUL) &&
       /* Check sizes. The smaller one needs to be larger than the Karatsuba cut-off.
        * The bigger one needs to be at least about one MP_KARATSUBA_MUL_CUTOFF bigger
        * to make some sense, but it depends on architecture, OS, position of the
        * stars... so YMMV.
        * Using it to cut the input into slices small enough for fast_s_mp_mul_digs
        * was actually slower on the author's machine, but YMMV.
        */
       (min_len >= MP_KARATSUBA_MUL_CUTOFF) &&
       ((max_len / 2) >= MP_KARATSUBA_MUL_CUTOFF) &&
       /* Not much effect was observed below a ratio of 1:2, but again: YMMV. */
       (max_len >= (2 * min_len))) {
      err = s_mp_balance_mul(a,b,c);
   } else if (MP_HAS(S_MP_TOOM_MUL) &&
              (min_len >= MP_TOOM_MUL_CUTOFF)) {
      err = s_mp_toom_mul(a, b, c);
   } else if (MP_HAS(S_MP_KARATSUBA_MUL) &&
              (min_len >= MP_KARATSUBA_MUL_CUTOFF)) {
      err = s_mp_karatsuba_mul(a, b, c);
   } else if (MP_HAS(S_MP_MUL_DIGS_FAST) &&
              /* can we use the fast multiplier?
               *
               * The fast multiplier can be used if the output will
               * have less than MP_WARRAY digits and the number of
               * digits won't affect carry propagation
               */
              (digs < MP_WARRAY) &&
              (min_len <= MP_MAXFAST)) {
      err = s_mp_mul_digs_fast(a, b, c, digs);
   } else if (MP_HAS(S_MP_MUL_DIGS)) {
      err = s_mp_mul_digs(a, b, c, digs);
   } else {
      err = MP_VAL;
   }
   c->sign = (c->used > 0) ? neg : MP_ZPOS;
   return err;
}
#endif

/* End: bn_mp_mul.c */

/* Start: bn_mp_mul_2.c */
#include "tommath_private.h"
#ifdef BN_MP_MUL_2_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* b = a*2 */
mp_err mp_mul_2(const mp_int *a, mp_int *b)
{
   int     x, oldused;
   mp_err err;

   /* grow to accomodate result */
   if (b->alloc < (a->used + 1)) {
      if ((err = mp_grow(b, a->used + 1)) != MP_OKAY) {
         return err;
      }
   }

   oldused = b->used;
   b->used = a->used;

   {
      mp_digit r, rr, *tmpa, *tmpb;

      /* alias for source */
      tmpa = a->dp;

      /* alias for dest */
      tmpb = b->dp;

      /* carry */
      r = 0;
      for (x = 0; x < a->used; x++) {

         /* get what will be the *next* carry bit from the
          * MSB of the current digit
          */
         rr = *tmpa >> (mp_digit)(MP_DIGIT_BIT - 1);

         /* now shift up this digit, add in the carry [from the previous] */
         *tmpb++ = ((*tmpa++ << 1uL) | r) & MP_MASK;

         /* copy the carry that would be from the source
          * digit into the next iteration
          */
         r = rr;
      }

      /* new leading digit? */
      if (r != 0u) {
         /* add a MSB which is always 1 at this point */
         *tmpb = 1;
         ++(b->used);
      }

      /* now zero any excess digits on the destination
       * that we didn't write to
       */
      MP_ZERO_DIGITS(b->dp + b->used, oldused - b->used);
   }
   b->sign = a->sign;
   return MP_OKAY;
}
#endif

/* End: bn_mp_mul_2.c */

/* Start: bn_mp_mul_2d.c */
#include "tommath_private.h"
#ifdef BN_MP_MUL_2D_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* shift left by a certain bit count */
mp_err mp_mul_2d(const mp_int *a, int b, mp_int *c)
{
   mp_digit d;
   mp_err   err;

   /* copy */
   if (a != c) {
      if ((err = mp_copy(a, c)) != MP_OKAY) {
         return err;
      }
   }

   if (c->alloc < (c->used + (b / MP_DIGIT_BIT) + 1)) {
      if ((err = mp_grow(c, c->used + (b / MP_DIGIT_BIT) + 1)) != MP_OKAY) {
         return err;
      }
   }

   /* shift by as many digits in the bit count */
   if (b >= MP_DIGIT_BIT) {
      if ((err = mp_lshd(c, b / MP_DIGIT_BIT)) != MP_OKAY) {
         return err;
      }
   }

   /* shift any bit count < MP_DIGIT_BIT */
   d = (mp_digit)(b % MP_DIGIT_BIT);
   if (d != 0u) {
      mp_digit *tmpc, shift, mask, r, rr;
      int x;

      /* bitmask for carries */
      mask = ((mp_digit)1 << d) - (mp_digit)1;

      /* shift for msbs */
      shift = (mp_digit)MP_DIGIT_BIT - d;

      /* alias */
      tmpc = c->dp;

      /* carry */
      r    = 0;
      for (x = 0; x < c->used; x++) {
         /* get the higher bits of the current word */
         rr = (*tmpc >> shift) & mask;

         /* shift the current word and OR in the carry */
         *tmpc = ((*tmpc << d) | r) & MP_MASK;
         ++tmpc;

         /* set the carry to the carry bits of the current word */
         r = rr;
      }

      /* set final carry */
      if (r != 0u) {
         c->dp[(c->used)++] = r;
      }
   }
   mp_clamp(c);
   return MP_OKAY;
}
#endif

/* End: bn_mp_mul_2d.c */

/* Start: bn_mp_mul_d.c */
#include "tommath_private.h"
#ifdef BN_MP_MUL_D_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* multiply by a digit */
mp_err mp_mul_d(const mp_int *a, mp_digit b, mp_int *c)
{
   mp_digit u, *tmpa, *tmpc;
   mp_word  r;
   mp_err   err;
   int      ix, olduse;

   /* make sure c is big enough to hold a*b */
   if (c->alloc < (a->used + 1)) {
      if ((err = mp_grow(c, a->used + 1)) != MP_OKAY) {
         return err;
      }
   }

   /* get the original destinations used count */
   olduse = c->used;

   /* set the sign */
   c->sign = a->sign;

   /* alias for a->dp [source] */
   tmpa = a->dp;

   /* alias for c->dp [dest] */
   tmpc = c->dp;

   /* zero carry */
   u = 0;

   /* compute columns */
   for (ix = 0; ix < a->used; ix++) {
      /* compute product and carry sum for this term */
      r       = (mp_word)u + ((mp_word)*tmpa++ * (mp_word)b);

      /* mask off higher bits to get a single digit */
      *tmpc++ = (mp_digit)(r & (mp_word)MP_MASK);

      /* send carry into next iteration */
      u       = (mp_digit)(r >> (mp_word)MP_DIGIT_BIT);
   }

   /* store final carry [if any] and increment ix offset  */
   *tmpc++ = u;
   ++ix;

   /* now zero digits above the top */
   MP_ZERO_DIGITS(tmpc, olduse - ix);

   /* set used count */
   c->used = a->used + 1;
   mp_clamp(c);

   return MP_OKAY;
}
#endif

/* End: bn_mp_mul_d.c */

/* Start: bn_mp_mulmod.c */
#include "tommath_private.h"
#ifdef BN_MP_MULMOD_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* d = a * b (mod c) */
mp_err mp_mulmod(const mp_int *a, const mp_int *b, const mp_int *c, mp_int *d)
{
   mp_err err;
   mp_int t;

   if ((err = mp_init_size(&t, c->used)) != MP_OKAY) {
      return err;
   }

   if ((err = mp_mul(a, b, &t)) != MP_OKAY) {
      goto LBL_ERR;
   }
   err = mp_mod(&t, c, d);

LBL_ERR:
   mp_clear(&t);
   return err;
}
#endif

/* End: bn_mp_mulmod.c */

/* Start: bn_mp_neg.c */
#include "tommath_private.h"
#ifdef BN_MP_NEG_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* b = -a */
mp_err mp_neg(const mp_int *a, mp_int *b)
{
   mp_err err;
   if (a != b) {
      if ((err = mp_copy(a, b)) != MP_OKAY) {
         return err;
      }
   }

   if (!MP_IS_ZERO(b)) {
      b->sign = (a->sign == MP_ZPOS) ? MP_NEG : MP_ZPOS;
   } else {
      b->sign = MP_ZPOS;
   }

   return MP_OKAY;
}
#endif

/* End: bn_mp_neg.c */

/* Start: bn_mp_or.c */
#include "tommath_private.h"
#ifdef BN_MP_OR_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* two complement or */
mp_err mp_or(const mp_int *a, const mp_int *b, mp_int *c)
{
   int used = MP_MAX(a->used, b->used) + 1, i;
   mp_err err;
   mp_digit ac = 1, bc = 1, cc = 1;
   mp_sign csign = ((a->sign == MP_NEG) || (b->sign == MP_NEG)) ? MP_NEG : MP_ZPOS;

   if (c->alloc < used) {
      if ((err = mp_grow(c, used)) != MP_OKAY) {
         return err;
      }
   }

   for (i = 0; i < used; i++) {
      mp_digit x, y;

      /* convert to two complement if negative */
      if (a->sign == MP_NEG) {
         ac += (i >= a->used) ? MP_MASK : (~a->dp[i] & MP_MASK);
         x = ac & MP_MASK;
         ac >>= MP_DIGIT_BIT;
      } else {
         x = (i >= a->used) ? 0uL : a->dp[i];
      }

      /* convert to two complement if negative */
      if (b->sign == MP_NEG) {
         bc += (i >= b->used) ? MP_MASK : (~b->dp[i] & MP_MASK);
         y = bc & MP_MASK;
         bc >>= MP_DIGIT_BIT;
      } else {
         y = (i >= b->used) ? 0uL : b->dp[i];
      }

      c->dp[i] = x | y;

      /* convert to to sign-magnitude if negative */
      if (csign == MP_NEG) {
         cc += ~c->dp[i] & MP_MASK;
         c->dp[i] = cc & MP_MASK;
         cc >>= MP_DIGIT_BIT;
      }
   }

   c->used = used;
   c->sign = csign;
   mp_clamp(c);
   return MP_OKAY;
}
#endif

/* End: bn_mp_or.c */

/* Start: bn_mp_pack.c */
#include "tommath_private.h"
#ifdef BN_MP_PACK_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* based on gmp's mpz_export.
 * see http://gmplib.org/manual/Integer-Import-and-Export.html
 */
mp_err mp_pack(void *rop, size_t maxcount, size_t *written, mp_order order, size_t size,
               mp_endian endian, size_t nails, const mp_int *op)
{
   mp_err err;
   size_t odd_nails, nail_bytes, i, j, count;
   unsigned char odd_nail_mask;

   mp_int t;

   count = mp_pack_count(op, nails, size);

   if (count > maxcount) {
      return MP_BUF;
   }

   if ((err = mp_init_copy(&t, op)) != MP_OKAY) {
      return err;
   }

   if (endian == MP_NATIVE_ENDIAN) {
      MP_GET_ENDIANNESS(endian);
   }

   odd_nails = (nails % 8u);
   odd_nail_mask = 0xff;
   for (i = 0u; i < odd_nails; ++i) {
      odd_nail_mask ^= (unsigned char)(1u << (7u - i));
   }
   nail_bytes = nails / 8u;

   for (i = 0u; i < count; ++i) {
      for (j = 0u; j < size; ++j) {
         unsigned char *byte = (unsigned char *)rop +
                               (((order == MP_LSB_FIRST) ? i : ((count - 1u) - i)) * size) +
                               ((endian == MP_LITTLE_ENDIAN) ? j : ((size - 1u) - j));

         if (j >= (size - nail_bytes)) {
            *byte = 0;
            continue;
         }

         *byte = (unsigned char)((j == ((size - nail_bytes) - 1u)) ? (t.dp[0] & odd_nail_mask) : (t.dp[0] & 0xFFuL));

         if ((err = mp_div_2d(&t, (j == ((size - nail_bytes) - 1u)) ? (int)(8u - odd_nails) : 8, &t, NULL)) != MP_OKAY) {
            goto LBL_ERR;
         }

      }
   }

   if (written != NULL) {
      *written = count;
   }
   err = MP_OKAY;

LBL_ERR:
   mp_clear(&t);
   return err;
}

#endif

/* End: bn_mp_pack.c */

/* Start: bn_mp_pack_count.c */
#include "tommath_private.h"
#ifdef BN_MP_PACK_COUNT_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

size_t mp_pack_count(const mp_int *a, size_t nails, size_t size)
{
   size_t bits = (size_t)mp_count_bits(a);
   return ((bits / ((size * 8u) - nails)) + (((bits % ((size * 8u) - nails)) != 0u) ? 1u : 0u));
}

#endif

/* End: bn_mp_pack_count.c */

/* Start: bn_mp_prime_fermat.c */
#include "tommath_private.h"
#ifdef BN_MP_PRIME_FERMAT_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* performs one Fermat test.
 *
 * If "a" were prime then b**a == b (mod a) since the order of
 * the multiplicative sub-group would be phi(a) = a-1.  That means
 * it would be the same as b**(a mod (a-1)) == b**1 == b (mod a).
 *
 * Sets result to 1 if the congruence holds, or zero otherwise.
 */
mp_err mp_prime_fermat(const mp_int *a, const mp_int *b, mp_bool *result)
{
   mp_int  t;
   mp_err  err;

   /* default to composite  */
   *result = MP_NO;

   /* ensure b > 1 */
   if (mp_cmp_d(b, 1uL) != MP_GT) {
      return MP_VAL;
   }

   /* init t */
   if ((err = mp_init(&t)) != MP_OKAY) {
      return err;
   }

   /* compute t = b**a mod a */
   if ((err = mp_exptmod(b, a, a, &t)) != MP_OKAY) {
      goto LBL_T;
   }

   /* is it equal to b? */
   if (mp_cmp(&t, b) == MP_EQ) {
      *result = MP_YES;
   }

   err = MP_OKAY;
LBL_T:
   mp_clear(&t);
   return err;
}
#endif

/* End: bn_mp_prime_fermat.c */

/* Start: bn_mp_prime_frobenius_underwood.c */
#include "tommath_private.h"
#ifdef BN_MP_PRIME_FROBENIUS_UNDERWOOD_C

/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/*
 *  See file bn_mp_prime_is_prime.c or the documentation in doc/bn.tex for the details
 */
#ifndef LTM_USE_ONLY_MR

#ifdef MP_8BIT
/*
 * floor of positive solution of
 * (2^16)-1 = (a+4)*(2*a+5)
 * TODO: Both values are smaller than N^(1/4), would have to use a bigint
 *       for a instead but any a biger than about 120 are already so rare that
 *       it is possible to ignore them and still get enough pseudoprimes.
 *       But it is still a restriction of the set of available pseudoprimes
 *       which makes this implementation less secure if used stand-alone.
 */
#define LTM_FROBENIUS_UNDERWOOD_A 177
#else
#define LTM_FROBENIUS_UNDERWOOD_A 32764
#endif
mp_err mp_prime_frobenius_underwood(const mp_int *N, mp_bool *result)
{
   mp_int T1z, T2z, Np1z, sz, tz;

   int a, ap2, length, i, j;
   mp_err err;

   *result = MP_NO;

   if ((err = mp_init_multi(&T1z, &T2z, &Np1z, &sz, &tz, NULL)) != MP_OKAY) {
      return err;
   }

   for (a = 0; a < LTM_FROBENIUS_UNDERWOOD_A; a++) {
      /* TODO: That's ugly! No, really, it is! */
      if ((a==2) || (a==4) || (a==7) || (a==8) || (a==10) ||
          (a==14) || (a==18) || (a==23) || (a==26) || (a==28)) {
         continue;
      }
      /* (32764^2 - 4) < 2^31, no bigint for >MP_8BIT needed) */
      mp_set_u32(&T1z, (uint32_t)a);

      if ((err = mp_sqr(&T1z, &T1z)) != MP_OKAY)                  goto LBL_FU_ERR;

      if ((err = mp_sub_d(&T1z, 4uL, &T1z)) != MP_OKAY)           goto LBL_FU_ERR;

      if ((err = mp_kronecker(&T1z, N, &j)) != MP_OKAY)           goto LBL_FU_ERR;

      if (j == -1) {
         break;
      }

      if (j == 0) {
         /* composite */
         goto LBL_FU_ERR;
      }
   }
   /* Tell it a composite and set return value accordingly */
   if (a >= LTM_FROBENIUS_UNDERWOOD_A) {
      err = MP_ITER;
      goto LBL_FU_ERR;
   }
   /* Composite if N and (a+4)*(2*a+5) are not coprime */
   mp_set_u32(&T1z, (uint32_t)((a+4)*((2*a)+5)));

   if ((err = mp_gcd(N, &T1z, &T1z)) != MP_OKAY)                  goto LBL_FU_ERR;

   if (!((T1z.used == 1) && (T1z.dp[0] == 1u)))                   goto LBL_FU_ERR;

   ap2 = a + 2;
   if ((err = mp_add_d(N, 1uL, &Np1z)) != MP_OKAY)                goto LBL_FU_ERR;

   mp_set(&sz, 1uL);
   mp_set(&tz, 2uL);
   length = mp_count_bits(&Np1z);

   for (i = length - 2; i >= 0; i--) {
      /*
       * temp = (sz*(a*sz+2*tz))%N;
       * tz   = ((tz-sz)*(tz+sz))%N;
       * sz   = temp;
       */
      if ((err = mp_mul_2(&tz, &T2z)) != MP_OKAY)                 goto LBL_FU_ERR;

      /* a = 0 at about 50% of the cases (non-square and odd input) */
      if (a != 0) {
         if ((err = mp_mul_d(&sz, (mp_digit)a, &T1z)) != MP_OKAY) goto LBL_FU_ERR;
         if ((err = mp_add(&T1z, &T2z, &T2z)) != MP_OKAY)         goto LBL_FU_ERR;
      }

      if ((err = mp_mul(&T2z, &sz, &T1z)) != MP_OKAY)             goto LBL_FU_ERR;
      if ((err = mp_sub(&tz, &sz, &T2z)) != MP_OKAY)              goto LBL_FU_ERR;
      if ((err = mp_add(&sz, &tz, &sz)) != MP_OKAY)               goto LBL_FU_ERR;
      if ((err = mp_mul(&sz, &T2z, &tz)) != MP_OKAY)              goto LBL_FU_ERR;
      if ((err = mp_mod(&tz, N, &tz)) != MP_OKAY)                 goto LBL_FU_ERR;
      if ((err = mp_mod(&T1z, N, &sz)) != MP_OKAY)                goto LBL_FU_ERR;
      if (s_mp_get_bit(&Np1z, (unsigned int)i) == MP_YES) {
         /*
          *  temp = (a+2) * sz + tz
          *  tz   = 2 * tz - sz
          *  sz   = temp
          */
         if (a == 0) {
            if ((err = mp_mul_2(&sz, &T1z)) != MP_OKAY)           goto LBL_FU_ERR;
         } else {
            if ((err = mp_mul_d(&sz, (mp_digit)ap2, &T1z)) != MP_OKAY) goto LBL_FU_ERR;
         }
         if ((err = mp_add(&T1z, &tz, &T1z)) != MP_OKAY)          goto LBL_FU_ERR;
         if ((err = mp_mul_2(&tz, &T2z)) != MP_OKAY)              goto LBL_FU_ERR;
         if ((err = mp_sub(&T2z, &sz, &tz)) != MP_OKAY)           goto LBL_FU_ERR;
         mp_exch(&sz, &T1z);
      }
   }

   mp_set_u32(&T1z, (uint32_t)((2 * a) + 5));
   if ((err = mp_mod(&T1z, N, &T1z)) != MP_OKAY)                  goto LBL_FU_ERR;
   if (MP_IS_ZERO(&sz) && (mp_cmp(&tz, &T1z) == MP_EQ)) {
      *result = MP_YES;
   }

LBL_FU_ERR:
   mp_clear_multi(&tz, &sz, &Np1z, &T2z, &T1z, NULL);
   return err;
}

#endif
#endif

/* End: bn_mp_prime_frobenius_underwood.c */

/* Start: bn_mp_prime_is_prime.c */
#include "tommath_private.h"
#ifdef BN_MP_PRIME_IS_PRIME_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* portable integer log of two with small footprint */
static unsigned int s_floor_ilog2(int value)
{
   unsigned int r = 0;
   while ((value >>= 1) != 0) {
      r++;
   }
   return r;
}


mp_err mp_prime_is_prime(const mp_int *a, int t, mp_bool *result)
{
   mp_int  b;
   int     ix, p_max = 0, size_a, len;
   mp_bool res;
   mp_err  err;
   unsigned int fips_rand, mask;

   /* default to no */
   *result = MP_NO;

   /* Some shortcuts */
   /* N > 3 */
   if (a->used == 1) {
      if ((a->dp[0] == 0u) || (a->dp[0] == 1u)) {
         *result = MP_NO;
         return MP_OKAY;
      }
      if (a->dp[0] == 2u) {
         *result = MP_YES;
         return MP_OKAY;
      }
   }

   /* N must be odd */
   if (MP_IS_EVEN(a)) {
      return MP_OKAY;
   }
   /* N is not a perfect square: floor(sqrt(N))^2 != N */
   if ((err = mp_is_square(a, &res)) != MP_OKAY) {
      return err;
   }
   if (res != MP_NO) {
      return MP_OKAY;
   }

   /* is the input equal to one of the primes in the table? */
   for (ix = 0; ix < PRIVATE_MP_PRIME_TAB_SIZE; ix++) {
      if (mp_cmp_d(a, s_mp_prime_tab[ix]) == MP_EQ) {
         *result = MP_YES;
         return MP_OKAY;
      }
   }
#ifdef MP_8BIT
   /* The search in the loop above was exhaustive in this case */
   if ((a->used == 1) && (PRIVATE_MP_PRIME_TAB_SIZE >= 31)) {
      return MP_OKAY;
   }
#endif

   /* first perform trial division */
   if ((err = s_mp_prime_is_divisible(a, &res)) != MP_OKAY) {
      return err;
   }

   /* return if it was trivially divisible */
   if (res == MP_YES) {
      return MP_OKAY;
   }

   /*
       Run the Miller-Rabin test with base 2 for the BPSW test.
    */
   if ((err = mp_init_set(&b, 2uL)) != MP_OKAY) {
      return err;
   }

   if ((err = mp_prime_miller_rabin(a, &b, &res)) != MP_OKAY) {
      goto LBL_B;
   }
   if (res == MP_NO) {
      goto LBL_B;
   }
   /*
      Rumours have it that Mathematica does a second M-R test with base 3.
      Other rumours have it that their strong L-S test is slightly different.
      It does not hurt, though, beside a bit of extra runtime.
   */
   b.dp[0]++;
   if ((err = mp_prime_miller_rabin(a, &b, &res)) != MP_OKAY) {
      goto LBL_B;
   }
   if (res == MP_NO) {
      goto LBL_B;
   }

   /*
    * Both, the Frobenius-Underwood test and the the Lucas-Selfridge test are quite
    * slow so if speed is an issue, define LTM_USE_ONLY_MR to use M-R tests with
    * bases 2, 3 and t random bases.
    */
#ifndef LTM_USE_ONLY_MR
   if (t >= 0) {
      /*
       * Use a Frobenius-Underwood test instead of the Lucas-Selfridge test for
       * MP_8BIT (It is unknown if the Lucas-Selfridge test works with 16-bit
       * integers but the necesssary analysis is on the todo-list).
       */
#if defined (MP_8BIT) || defined (LTM_USE_FROBENIUS_TEST)
      err = mp_prime_frobenius_underwood(a, &res);
      if ((err != MP_OKAY) && (err != MP_ITER)) {
         goto LBL_B;
      }
      if (res == MP_NO) {
         goto LBL_B;
      }
#else
      if ((err = mp_prime_strong_lucas_selfridge(a, &res)) != MP_OKAY) {
         goto LBL_B;
      }
      if (res == MP_NO) {
         goto LBL_B;
      }
#endif
   }
#endif

   /* run at least one Miller-Rabin test with a random base */
   if (t == 0) {
      t = 1;
   }

   /*
      Only recommended if the input range is known to be < 3317044064679887385961981

      It uses the bases necessary for a deterministic M-R test if the input is
      smaller than  3317044064679887385961981
      The caller has to check the size.
      TODO: can be made a bit finer grained but comparing is not free.
   */
   if (t < 0) {
      /*
          Sorenson, Jonathan; Webster, Jonathan (2015).
           "Strong Pseudoprimes to Twelve Prime Bases".
       */
      /* 0x437ae92817f9fc85b7e5 = 318665857834031151167461 */
      if ((err =   mp_read_radix(&b, "437ae92817f9fc85b7e5", 16)) != MP_OKAY) {
         goto LBL_B;
      }

      if (mp_cmp(a, &b) == MP_LT) {
         p_max = 12;
      } else {
         /* 0x2be6951adc5b22410a5fd = 3317044064679887385961981 */
         if ((err = mp_read_radix(&b, "2be6951adc5b22410a5fd", 16)) != MP_OKAY) {
            goto LBL_B;
         }

         if (mp_cmp(a, &b) == MP_LT) {
            p_max = 13;
         } else {
            err = MP_VAL;
            goto LBL_B;
         }
      }

      /* we did bases 2 and 3  already, skip them */
      for (ix = 2; ix < p_max; ix++) {
         mp_set(&b, s_mp_prime_tab[ix]);
         if ((err = mp_prime_miller_rabin(a, &b, &res)) != MP_OKAY) {
            goto LBL_B;
         }
         if (res == MP_NO) {
            goto LBL_B;
         }
      }
   }
   /*
       Do "t" M-R tests with random bases between 3 and "a".
       See Fips 186.4 p. 126ff
   */
   else if (t > 0) {
      /*
       * The mp_digit's have a defined bit-size but the size of the
       * array a.dp is a simple 'int' and this library can not assume full
       * compliance to the current C-standard (ISO/IEC 9899:2011) because
       * it gets used for small embeded processors, too. Some of those MCUs
       * have compilers that one cannot call standard compliant by any means.
       * Hence the ugly type-fiddling in the following code.
       */
      size_a = mp_count_bits(a);
      mask = (1u << s_floor_ilog2(size_a)) - 1u;
      /*
         Assuming the General Rieman hypothesis (never thought to write that in a
         comment) the upper bound can be lowered to  2*(log a)^2.
         E. Bach, "Explicit bounds for primality testing and related problems,"
         Math. Comp. 55 (1990), 355-380.

            size_a = (size_a/10) * 7;
            len = 2 * (size_a * size_a);

         E.g.: a number of size 2^2048 would be reduced to the upper limit

            floor(2048/10)*7 = 1428
            2 * 1428^2       = 4078368

         (would have been ~4030331.9962 with floats and natural log instead)
         That number is smaller than 2^28, the default bit-size of mp_digit.
      */

      /*
        How many tests, you might ask? Dana Jacobsen of Math::Prime::Util fame
        does exactly 1. In words: one. Look at the end of _GMP_is_prime() in
        Math-Prime-Util-GMP-0.50/primality.c if you do not believe it.

        The function mp_rand() goes to some length to use a cryptographically
        good PRNG. That also means that the chance to always get the same base
        in the loop is non-zero, although very low.
        If the BPSW test and/or the addtional Frobenious test have been
        performed instead of just the Miller-Rabin test with the bases 2 and 3,
        a single extra test should suffice, so such a very unlikely event
        will not do much harm.

        To preemptivly answer the dangling question: no, a witness does not
        need to be prime.
      */
      for (ix = 0; ix < t; ix++) {
         /* mp_rand() guarantees the first digit to be non-zero */
         if ((err = mp_rand(&b, 1)) != MP_OKAY) {
            goto LBL_B;
         }
         /*
          * Reduce digit before casting because mp_digit might be bigger than
          * an unsigned int and "mask" on the other side is most probably not.
          */
         fips_rand = (unsigned int)(b.dp[0] & (mp_digit) mask);
#ifdef MP_8BIT
         /*
          * One 8-bit digit is too small, so concatenate two if the size of
          * unsigned int allows for it.
          */
         if ((MP_SIZEOF_BITS(unsigned int)/2) >= MP_SIZEOF_BITS(mp_digit)) {
            if ((err = mp_rand(&b, 1)) != MP_OKAY) {
               goto LBL_B;
            }
            fips_rand <<= MP_SIZEOF_BITS(mp_digit);
            fips_rand |= (unsigned int) b.dp[0];
            fips_rand &= mask;
         }
#endif
         if (fips_rand > (unsigned int)(INT_MAX - MP_DIGIT_BIT)) {
            len = INT_MAX / MP_DIGIT_BIT;
         } else {
            len = (((int)fips_rand + MP_DIGIT_BIT) / MP_DIGIT_BIT);
         }
         /*  Unlikely. */
         if (len < 0) {
            ix--;
            continue;
         }
         /*
          * As mentioned above, one 8-bit digit is too small and
          * although it can only happen in the unlikely case that
          * an "unsigned int" is smaller than 16 bit a simple test
          * is cheap and the correction even cheaper.
          */
#ifdef MP_8BIT
         /* All "a" < 2^8 have been caught before */
         if (len == 1) {
            len++;
         }
#endif
         if ((err = mp_rand(&b, len)) != MP_OKAY) {
            goto LBL_B;
         }
         /*
          * That number might got too big and the witness has to be
          * smaller than "a"
          */
         len = mp_count_bits(&b);
         if (len >= size_a) {
            len = (len - size_a) + 1;
            if ((err = mp_div_2d(&b, len, &b, NULL)) != MP_OKAY) {
               goto LBL_B;
            }
         }
         /* Although the chance for b <= 3 is miniscule, try again. */
         if (mp_cmp_d(&b, 3uL) != MP_GT) {
            ix--;
            continue;
         }
         if ((err = mp_prime_miller_rabin(a, &b, &res)) != MP_OKAY) {
            goto LBL_B;
         }
         if (res == MP_NO) {
            goto LBL_B;
         }
      }
   }

   /* passed the test */
   *result = MP_YES;
LBL_B:
   mp_clear(&b);
   return err;
}

#endif

/* End: bn_mp_prime_is_prime.c */

/* Start: bn_mp_prime_miller_rabin.c */
#include "tommath_private.h"
#ifdef BN_MP_PRIME_MILLER_RABIN_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* Miller-Rabin test of "a" to the base of "b" as described in
 * HAC pp. 139 Algorithm 4.24
 *
 * Sets result to 0 if definitely composite or 1 if probably prime.
 * Randomly the chance of error is no more than 1/4 and often
 * very much lower.
 */
mp_err mp_prime_miller_rabin(const mp_int *a, const mp_int *b, mp_bool *result)
{
   mp_int  n1, y, r;
   mp_err  err;
   int     s, j;

   /* default */
   *result = MP_NO;

   /* ensure b > 1 */
   if (mp_cmp_d(b, 1uL) != MP_GT) {
      return MP_VAL;
   }

   /* get n1 = a - 1 */
   if ((err = mp_init_copy(&n1, a)) != MP_OKAY) {
      return err;
   }
   if ((err = mp_sub_d(&n1, 1uL, &n1)) != MP_OKAY) {
      goto LBL_N1;
   }

   /* set 2**s * r = n1 */
   if ((err = mp_init_copy(&r, &n1)) != MP_OKAY) {
      goto LBL_N1;
   }

   /* count the number of least significant bits
    * which are zero
    */
   s = mp_cnt_lsb(&r);

   /* now divide n - 1 by 2**s */
   if ((err = mp_div_2d(&r, s, &r, NULL)) != MP_OKAY) {
      goto LBL_R;
   }

   /* compute y = b**r mod a */
   if ((err = mp_init(&y)) != MP_OKAY) {
      goto LBL_R;
   }
   if ((err = mp_exptmod(b, &r, a, &y)) != MP_OKAY) {
      goto LBL_Y;
   }

   /* if y != 1 and y != n1 do */
   if ((mp_cmp_d(&y, 1uL) != MP_EQ) && (mp_cmp(&y, &n1) != MP_EQ)) {
      j = 1;
      /* while j <= s-1 and y != n1 */
      while ((j <= (s - 1)) && (mp_cmp(&y, &n1) != MP_EQ)) {
         if ((err = mp_sqrmod(&y, a, &y)) != MP_OKAY) {
            goto LBL_Y;
         }

         /* if y == 1 then composite */
         if (mp_cmp_d(&y, 1uL) == MP_EQ) {
            goto LBL_Y;
         }

         ++j;
      }

      /* if y != n1 then composite */
      if (mp_cmp(&y, &n1) != MP_EQ) {
         goto LBL_Y;
      }
   }

   /* probably prime now */
   *result = MP_YES;
LBL_Y:
   mp_clear(&y);
LBL_R:
   mp_clear(&r);
LBL_N1:
   mp_clear(&n1);
   return err;
}
#endif

/* End: bn_mp_prime_miller_rabin.c */

/* Start: bn_mp_prime_next_prime.c */
#include "tommath_private.h"
#ifdef BN_MP_PRIME_NEXT_PRIME_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* finds the next prime after the number "a" using "t" trials
 * of Miller-Rabin.
 *
 * bbs_style = 1 means the prime must be congruent to 3 mod 4
 */
mp_err mp_prime_next_prime(mp_int *a, int t, int bbs_style)
{
   int      x, y;
   mp_ord   cmp;
   mp_err   err;
   mp_bool  res = MP_NO;
   mp_digit res_tab[PRIVATE_MP_PRIME_TAB_SIZE], step, kstep;
   mp_int   b;

   /* force positive */
   a->sign = MP_ZPOS;

   /* simple algo if a is less than the largest prime in the table */
   if (mp_cmp_d(a, s_mp_prime_tab[PRIVATE_MP_PRIME_TAB_SIZE-1]) == MP_LT) {
      /* find which prime it is bigger than "a" */
      for (x = 0; x < PRIVATE_MP_PRIME_TAB_SIZE; x++) {
         cmp = mp_cmp_d(a, s_mp_prime_tab[x]);
         if (cmp == MP_EQ) {
            continue;
         }
         if (cmp != MP_GT) {
            if ((bbs_style == 1) && ((s_mp_prime_tab[x] & 3u) != 3u)) {
               /* try again until we get a prime congruent to 3 mod 4 */
               continue;
            } else {
               mp_set(a, s_mp_prime_tab[x]);
               return MP_OKAY;
            }
         }
      }
      /* fall through to the sieve */
   }

   /* generate a prime congruent to 3 mod 4 or 1/3 mod 4? */
   if (bbs_style == 1) {
      kstep   = 4;
   } else {
      kstep   = 2;
   }

   /* at this point we will use a combination of a sieve and Miller-Rabin */

   if (bbs_style == 1) {
      /* if a mod 4 != 3 subtract the correct value to make it so */
      if ((a->dp[0] & 3u) != 3u) {
         if ((err = mp_sub_d(a, (a->dp[0] & 3u) + 1u, a)) != MP_OKAY) {
            return err;
         }
      }
   } else {
      if (MP_IS_EVEN(a)) {
         /* force odd */
         if ((err = mp_sub_d(a, 1uL, a)) != MP_OKAY) {
            return err;
         }
      }
   }

   /* generate the restable */
   for (x = 1; x < PRIVATE_MP_PRIME_TAB_SIZE; x++) {
      if ((err = mp_mod_d(a, s_mp_prime_tab[x], res_tab + x)) != MP_OKAY) {
         return err;
      }
   }

   /* init temp used for Miller-Rabin Testing */
   if ((err = mp_init(&b)) != MP_OKAY) {
      return err;
   }

   for (;;) {
      /* skip to the next non-trivially divisible candidate */
      step = 0;
      do {
         /* y == 1 if any residue was zero [e.g. cannot be prime] */
         y     =  0;

         /* increase step to next candidate */
         step += kstep;

         /* compute the new residue without using division */
         for (x = 1; x < PRIVATE_MP_PRIME_TAB_SIZE; x++) {
            /* add the step to each residue */
            res_tab[x] += kstep;

            /* subtract the modulus [instead of using division] */
            if (res_tab[x] >= s_mp_prime_tab[x]) {
               res_tab[x]  -= s_mp_prime_tab[x];
            }

            /* set flag if zero */
            if (res_tab[x] == 0u) {
               y = 1;
            }
         }
      } while ((y == 1) && (step < (((mp_digit)1 << MP_DIGIT_BIT) - kstep)));

      /* add the step */
      if ((err = mp_add_d(a, step, a)) != MP_OKAY) {
         goto LBL_ERR;
      }

      /* if didn't pass sieve and step == MP_MAX then skip test */
      if ((y == 1) && (step >= (((mp_digit)1 << MP_DIGIT_BIT) - kstep))) {
         continue;
      }

      if ((err = mp_prime_is_prime(a, t, &res)) != MP_OKAY) {
         goto LBL_ERR;
      }
      if (res == MP_YES) {
         break;
      }
   }

   err = MP_OKAY;
LBL_ERR:
   mp_clear(&b);
   return err;
}

#endif

/* End: bn_mp_prime_next_prime.c */

/* Start: bn_mp_prime_rabin_miller_trials.c */
#include "tommath_private.h"
#ifdef BN_MP_PRIME_RABIN_MILLER_TRIALS_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

static const struct {
   int k, t;
} sizes[] = {
   {    80, -1 }, /* Use deterministic algorithm for size <= 80 bits */
   {    81, 37 }, /* max. error = 2^(-96)*/
   {    96, 32 }, /* max. error = 2^(-96)*/
   {   128, 40 }, /* max. error = 2^(-112)*/
   {   160, 35 }, /* max. error = 2^(-112)*/
   {   256, 27 }, /* max. error = 2^(-128)*/
   {   384, 16 }, /* max. error = 2^(-128)*/
   {   512, 18 }, /* max. error = 2^(-160)*/
   {   768, 11 }, /* max. error = 2^(-160)*/
   {   896, 10 }, /* max. error = 2^(-160)*/
   {  1024, 12 }, /* max. error = 2^(-192)*/
   {  1536, 8  }, /* max. error = 2^(-192)*/
   {  2048, 6  }, /* max. error = 2^(-192)*/
   {  3072, 4  }, /* max. error = 2^(-192)*/
   {  4096, 5  }, /* max. error = 2^(-256)*/
   {  5120, 4  }, /* max. error = 2^(-256)*/
   {  6144, 4  }, /* max. error = 2^(-256)*/
   {  8192, 3  }, /* max. error = 2^(-256)*/
   {  9216, 3  }, /* max. error = 2^(-256)*/
   { 10240, 2  }  /* For bigger keysizes use always at least 2 Rounds */
};

/* returns # of RM trials required for a given bit size */
int mp_prime_rabin_miller_trials(int size)
{
   int x;

   for (x = 0; x < (int)(sizeof(sizes)/(sizeof(sizes[0]))); x++) {
      if (sizes[x].k == size) {
         return sizes[x].t;
      } else if (sizes[x].k > size) {
         return (x == 0) ? sizes[0].t : sizes[x - 1].t;
      }
   }
   return sizes[x-1].t;
}


#endif

/* End: bn_mp_prime_rabin_miller_trials.c */

/* Start: bn_mp_prime_rand.c */
#include "tommath_private.h"
#ifdef BN_MP_PRIME_RAND_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* makes a truly random prime of a given size (bits),
 *
 * Flags are as follows:
 *
 *   MP_PRIME_BBS      - make prime congruent to 3 mod 4
 *   MP_PRIME_SAFE     - make sure (p-1)/2 is prime as well (implies MP_PRIME_BBS)
 *   MP_PRIME_2MSB_ON  - make the 2nd highest bit one
 *
 * You have to supply a callback which fills in a buffer with random bytes.  "dat" is a parameter you can
 * have passed to the callback (e.g. a state or something).  This function doesn't use "dat" itself
 * so it can be NULL
 *
 */

/* This is possibly the mother of all prime generation functions, muahahahahaha! */
mp_err s_mp_prime_random_ex(mp_int *a, int t, int size, int flags, private_mp_prime_callback cb, void *dat)
{
   unsigned char *tmp, maskAND, maskOR_msb, maskOR_lsb;
   int bsize, maskOR_msb_offset;
   mp_bool res;
   mp_err err;

   /* sanity check the input */
   if ((size <= 1) || (t <= 0)) {
      return MP_VAL;
   }

   /* MP_PRIME_SAFE implies MP_PRIME_BBS */
   if ((flags & MP_PRIME_SAFE) != 0) {
      flags |= MP_PRIME_BBS;
   }

   /* calc the byte size */
   bsize = (size>>3) + ((size&7)?1:0);

   /* we need a buffer of bsize bytes */
   tmp = (unsigned char *) MP_MALLOC((size_t)bsize);
   if (tmp == NULL) {
      return MP_MEM;
   }

   /* calc the maskAND value for the MSbyte*/
   maskAND = ((size&7) == 0) ? 0xFFu : (unsigned char)(0xFFu >> (8 - (size & 7)));

   /* calc the maskOR_msb */
   maskOR_msb        = 0;
   maskOR_msb_offset = ((size & 7) == 1) ? 1 : 0;
   if ((flags & MP_PRIME_2MSB_ON) != 0) {
      maskOR_msb       |= (unsigned char)(0x80 >> ((9 - size) & 7));
   }

   /* get the maskOR_lsb */
   maskOR_lsb         = 1u;
   if ((flags & MP_PRIME_BBS) != 0) {
      maskOR_lsb     |= 3u;
   }

   do {
      /* read the bytes */
      if (cb(tmp, bsize, dat) != bsize) {
         err = MP_VAL;
         goto error;
      }

      /* work over the MSbyte */
      tmp[0]    &= maskAND;
      tmp[0]    |= (unsigned char)(1 << ((size - 1) & 7));

      /* mix in the maskORs */
      tmp[maskOR_msb_offset]   |= maskOR_msb;
      tmp[bsize-1]             |= maskOR_lsb;

      /* read it in */
      /* TODO: casting only for now until all lengths have been changed to the type "size_t"*/
      if ((err = mp_from_ubin(a, tmp, (size_t)bsize)) != MP_OKAY) {
         goto error;
      }

      /* is it prime? */
      if ((err = mp_prime_is_prime(a, t, &res)) != MP_OKAY) {
         goto error;
      }
      if (res == MP_NO) {
         continue;
      }

      if ((flags & MP_PRIME_SAFE) != 0) {
         /* see if (a-1)/2 is prime */
         if ((err = mp_sub_d(a, 1uL, a)) != MP_OKAY) {
            goto error;
         }
         if ((err = mp_div_2(a, a)) != MP_OKAY) {
            goto error;
         }

         /* is it prime? */
         if ((err = mp_prime_is_prime(a, t, &res)) != MP_OKAY) {
            goto error;
         }
      }
   } while (res == MP_NO);

   if ((flags & MP_PRIME_SAFE) != 0) {
      /* restore a to the original value */
      if ((err = mp_mul_2(a, a)) != MP_OKAY) {
         goto error;
      }
      if ((err = mp_add_d(a, 1uL, a)) != MP_OKAY) {
         goto error;
      }
   }

   err = MP_OKAY;
error:
   MP_FREE_BUFFER(tmp, (size_t)bsize);
   return err;
}

static int s_mp_rand_cb(unsigned char *dst, int len, void *dat)
{
   (void)dat;
   if (len <= 0) {
      return len;
   }
   if (s_mp_rand_source(dst, (size_t)len) != MP_OKAY) {
      return 0;
   }
   return len;
}

mp_err mp_prime_rand(mp_int *a, int t, int size, int flags)
{
   return s_mp_prime_random_ex(a, t, size, flags, s_mp_rand_cb, NULL);
}

#endif

/* End: bn_mp_prime_rand.c */

/* Start: bn_mp_prime_strong_lucas_selfridge.c */
#include "tommath_private.h"
#ifdef BN_MP_PRIME_STRONG_LUCAS_SELFRIDGE_C

/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/*
 *  See file bn_mp_prime_is_prime.c or the documentation in doc/bn.tex for the details
 */
#ifndef LTM_USE_ONLY_MR

/*
 *  8-bit is just too small. You can try the Frobenius test
 *  but that frobenius test can fail, too, for the same reason.
 */
#ifndef MP_8BIT

/*
 * multiply bigint a with int d and put the result in c
 * Like mp_mul_d() but with a signed long as the small input
 */
static mp_err s_mp_mul_si(const mp_int *a, int32_t d, mp_int *c)
{
   mp_int t;
   mp_err err;

   if ((err = mp_init(&t)) != MP_OKAY) {
      return err;
   }

   /*
    * mp_digit might be smaller than a long, which excludes
    * the use of mp_mul_d() here.
    */
   mp_set_i32(&t, d);
   err = mp_mul(a, &t, c);
   mp_clear(&t);
   return err;
}
/*
    Strong Lucas-Selfridge test.
    returns MP_YES if it is a strong L-S prime, MP_NO if it is composite

    Code ported from  Thomas Ray Nicely's implementation of the BPSW test
    at http://www.trnicely.net/misc/bpsw.html

    Freeware copyright (C) 2016 Thomas R. Nicely <http://www.trnicely.net>.
    Released into the public domain by the author, who disclaims any legal
    liability arising from its use

    The multi-line comments are made by Thomas R. Nicely and are copied verbatim.
    Additional comments marked "CZ" (without the quotes) are by the code-portist.

    (If that name sounds familiar, he is the guy who found the fdiv bug in the
     Pentium (P5x, I think) Intel processor)
*/
mp_err mp_prime_strong_lucas_selfridge(const mp_int *a, mp_bool *result)
{
   /* CZ TODO: choose better variable names! */
   mp_int Dz, gcd, Np1, Uz, Vz, U2mz, V2mz, Qmz, Q2mz, Qkdz, T1z, T2z, T3z, T4z, Q2kdz;
   /* CZ TODO: Some of them need the full 32 bit, hence the (temporary) exclusion of MP_8BIT */
   int32_t D, Ds, J, sign, P, Q, r, s, u, Nbits;
   mp_err err;
   mp_bool oddness;

   *result = MP_NO;
   /*
   Find the first element D in the sequence {5, -7, 9, -11, 13, ...}
   such that Jacobi(D,N) = -1 (Selfridge's algorithm). Theory
   indicates that, if N is not a perfect square, D will "nearly
   always" be "small." Just in case, an overflow trap for D is
   included.
   */

   if ((err = mp_init_multi(&Dz, &gcd, &Np1, &Uz, &Vz, &U2mz, &V2mz, &Qmz, &Q2mz, &Qkdz, &T1z, &T2z, &T3z, &T4z, &Q2kdz,
                            NULL)) != MP_OKAY) {
      return err;
   }

   D = 5;
   sign = 1;

   for (;;) {
      Ds   = sign * D;
      sign = -sign;
      mp_set_u32(&Dz, (uint32_t)D);
      if ((err = mp_gcd(a, &Dz, &gcd)) != MP_OKAY)                goto LBL_LS_ERR;

      /* if 1 < GCD < N then N is composite with factor "D", and
         Jacobi(D,N) is technically undefined (but often returned
         as zero). */
      if ((mp_cmp_d(&gcd, 1uL) == MP_GT) && (mp_cmp(&gcd, a) == MP_LT)) {
         goto LBL_LS_ERR;
      }
      if (Ds < 0) {
         Dz.sign = MP_NEG;
      }
      if ((err = mp_kronecker(&Dz, a, &J)) != MP_OKAY)            goto LBL_LS_ERR;

      if (J == -1) {
         break;
      }
      D += 2;

      if (D > (INT_MAX - 2)) {
         err = MP_VAL;
         goto LBL_LS_ERR;
      }
   }



   P = 1;              /* Selfridge's choice */
   Q = (1 - Ds) / 4;   /* Required so D = P*P - 4*Q */

   /* NOTE: The conditions (a) N does not divide Q, and
      (b) D is square-free or not a perfect square, are included by
      some authors; e.g., "Prime numbers and computer methods for
      factorization," Hans Riesel (2nd ed., 1994, Birkhauser, Boston),
      p. 130. For this particular application of Lucas sequences,
      these conditions were found to be immaterial. */

   /* Now calculate N - Jacobi(D,N) = N + 1 (even), and calculate the
      odd positive integer d and positive integer s for which
      N + 1 = 2^s*d (similar to the step for N - 1 in Miller's test).
      The strong Lucas-Selfridge test then returns N as a strong
      Lucas probable prime (slprp) if any of the following
      conditions is met: U_d=0, V_d=0, V_2d=0, V_4d=0, V_8d=0,
      V_16d=0, ..., etc., ending with V_{2^(s-1)*d}=V_{(N+1)/2}=0
      (all equalities mod N). Thus d is the highest index of U that
      must be computed (since V_2m is independent of U), compared
      to U_{N+1} for the standard Lucas-Selfridge test; and no
      index of V beyond (N+1)/2 is required, just as in the
      standard Lucas-Selfridge test. However, the quantity Q^d must
      be computed for use (if necessary) in the latter stages of
      the test. The result is that the strong Lucas-Selfridge test
      has a running time only slightly greater (order of 10 %) than
      that of the standard Lucas-Selfridge test, while producing
      only (roughly) 30 % as many pseudoprimes (and every strong
      Lucas pseudoprime is also a standard Lucas pseudoprime). Thus
      the evidence indicates that the strong Lucas-Selfridge test is
      more effective than the standard Lucas-Selfridge test, and a
      Baillie-PSW test based on the strong Lucas-Selfridge test
      should be more reliable. */

   if ((err = mp_add_d(a, 1uL, &Np1)) != MP_OKAY)                 goto LBL_LS_ERR;
   s = mp_cnt_lsb(&Np1);

   /* CZ
    * This should round towards zero because
    * Thomas R. Nicely used GMP's mpz_tdiv_q_2exp()
    * and mp_div_2d() is equivalent. Additionally:
    * dividing an even number by two does not produce
    * any leftovers.
    */
   if ((err = mp_div_2d(&Np1, s, &Dz, NULL)) != MP_OKAY)          goto LBL_LS_ERR;
   /* We must now compute U_d and V_d. Since d is odd, the accumulated
      values U and V are initialized to U_1 and V_1 (if the target
      index were even, U and V would be initialized instead to U_0=0
      and V_0=2). The values of U_2m and V_2m are also initialized to
      U_1 and V_1; the FOR loop calculates in succession U_2 and V_2,
      U_4 and V_4, U_8 and V_8, etc. If the corresponding bits
      (1, 2, 3, ...) of t are on (the zero bit having been accounted
      for in the initialization of U and V), these values are then
      combined with the previous totals for U and V, using the
      composition formulas for addition of indices. */

   mp_set(&Uz, 1uL);    /* U=U_1 */
   mp_set(&Vz, (mp_digit)P);    /* V=V_1 */
   mp_set(&U2mz, 1uL);  /* U_1 */
   mp_set(&V2mz, (mp_digit)P);  /* V_1 */

   mp_set_i32(&Qmz, Q);
   if ((err = mp_mul_2(&Qmz, &Q2mz)) != MP_OKAY)                  goto LBL_LS_ERR;
   /* Initializes calculation of Q^d */
   mp_set_i32(&Qkdz, Q);

   Nbits = mp_count_bits(&Dz);

   for (u = 1; u < Nbits; u++) { /* zero bit off, already accounted for */
      /* Formulas for doubling of indices (carried out mod N). Note that
       * the indices denoted as "2m" are actually powers of 2, specifically
       * 2^(ul-1) beginning each loop and 2^ul ending each loop.
       *
       * U_2m = U_m*V_m
       * V_2m = V_m*V_m - 2*Q^m
       */

      if ((err = mp_mul(&U2mz, &V2mz, &U2mz)) != MP_OKAY)         goto LBL_LS_ERR;
      if ((err = mp_mod(&U2mz, a, &U2mz)) != MP_OKAY)             goto LBL_LS_ERR;
      if ((err = mp_sqr(&V2mz, &V2mz)) != MP_OKAY)                goto LBL_LS_ERR;
      if ((err = mp_sub(&V2mz, &Q2mz, &V2mz)) != MP_OKAY)         goto LBL_LS_ERR;
      if ((err = mp_mod(&V2mz, a, &V2mz)) != MP_OKAY)             goto LBL_LS_ERR;

      /* Must calculate powers of Q for use in V_2m, also for Q^d later */
      if ((err = mp_sqr(&Qmz, &Qmz)) != MP_OKAY)                  goto LBL_LS_ERR;

      /* prevents overflow */ /* CZ  still necessary without a fixed prealloc'd mem.? */
      if ((err = mp_mod(&Qmz, a, &Qmz)) != MP_OKAY)               goto LBL_LS_ERR;
      if ((err = mp_mul_2(&Qmz, &Q2mz)) != MP_OKAY)               goto LBL_LS_ERR;

      if (s_mp_get_bit(&Dz, (unsigned int)u) == MP_YES) {
         /* Formulas for addition of indices (carried out mod N);
          *
          * U_(m+n) = (U_m*V_n + U_n*V_m)/2
          * V_(m+n) = (V_m*V_n + D*U_m*U_n)/2
          *
          * Be careful with division by 2 (mod N)!
          */
         if ((err = mp_mul(&U2mz, &Vz, &T1z)) != MP_OKAY)         goto LBL_LS_ERR;
         if ((err = mp_mul(&Uz, &V2mz, &T2z)) != MP_OKAY)         goto LBL_LS_ERR;
         if ((err = mp_mul(&V2mz, &Vz, &T3z)) != MP_OKAY)         goto LBL_LS_ERR;
         if ((err = mp_mul(&U2mz, &Uz, &T4z)) != MP_OKAY)         goto LBL_LS_ERR;
         if ((err = s_mp_mul_si(&T4z, Ds, &T4z)) != MP_OKAY)      goto LBL_LS_ERR;
         if ((err = mp_add(&T1z, &T2z, &Uz)) != MP_OKAY)          goto LBL_LS_ERR;
         if (MP_IS_ODD(&Uz)) {
            if ((err = mp_add(&Uz, a, &Uz)) != MP_OKAY)           goto LBL_LS_ERR;
         }
         /* CZ
          * This should round towards negative infinity because
          * Thomas R. Nicely used GMP's mpz_fdiv_q_2exp().
          * But mp_div_2() does not do so, it is truncating instead.
          */
         oddness = MP_IS_ODD(&Uz) ? MP_YES : MP_NO;
         if ((err = mp_div_2(&Uz, &Uz)) != MP_OKAY)               goto LBL_LS_ERR;
         if ((Uz.sign == MP_NEG) && (oddness != MP_NO)) {
            if ((err = mp_sub_d(&Uz, 1uL, &Uz)) != MP_OKAY)       goto LBL_LS_ERR;
         }
         if ((err = mp_add(&T3z, &T4z, &Vz)) != MP_OKAY)          goto LBL_LS_ERR;
         if (MP_IS_ODD(&Vz)) {
            if ((err = mp_add(&Vz, a, &Vz)) != MP_OKAY)           goto LBL_LS_ERR;
         }
         oddness = MP_IS_ODD(&Vz) ? MP_YES : MP_NO;
         if ((err = mp_div_2(&Vz, &Vz)) != MP_OKAY)               goto LBL_LS_ERR;
         if ((Vz.sign == MP_NEG) && (oddness != MP_NO)) {
            if ((err = mp_sub_d(&Vz, 1uL, &Vz)) != MP_OKAY)       goto LBL_LS_ERR;
         }
         if ((err = mp_mod(&Uz, a, &Uz)) != MP_OKAY)              goto LBL_LS_ERR;
         if ((err = mp_mod(&Vz, a, &Vz)) != MP_OKAY)              goto LBL_LS_ERR;

         /* Calculating Q^d for later use */
         if ((err = mp_mul(&Qkdz, &Qmz, &Qkdz)) != MP_OKAY)       goto LBL_LS_ERR;
         if ((err = mp_mod(&Qkdz, a, &Qkdz)) != MP_OKAY)          goto LBL_LS_ERR;
      }
   }

   /* If U_d or V_d is congruent to 0 mod N, then N is a prime or a
      strong Lucas pseudoprime. */
   if (MP_IS_ZERO(&Uz) || MP_IS_ZERO(&Vz)) {
      *result = MP_YES;
      goto LBL_LS_ERR;
   }

   /* NOTE: Ribenboim ("The new book of prime number records," 3rd ed.,
      1995/6) omits the condition V0 on p.142, but includes it on
      p. 130. The condition is NECESSARY; otherwise the test will
      return false negatives---e.g., the primes 29 and 2000029 will be
      returned as composite. */

   /* Otherwise, we must compute V_2d, V_4d, V_8d, ..., V_{2^(s-1)*d}
      by repeated use of the formula V_2m = V_m*V_m - 2*Q^m. If any of
      these are congruent to 0 mod N, then N is a prime or a strong
      Lucas pseudoprime. */

   /* Initialize 2*Q^(d*2^r) for V_2m */
   if ((err = mp_mul_2(&Qkdz, &Q2kdz)) != MP_OKAY)                goto LBL_LS_ERR;

   for (r = 1; r < s; r++) {
      if ((err = mp_sqr(&Vz, &Vz)) != MP_OKAY)                    goto LBL_LS_ERR;
      if ((err = mp_sub(&Vz, &Q2kdz, &Vz)) != MP_OKAY)            goto LBL_LS_ERR;
      if ((err = mp_mod(&Vz, a, &Vz)) != MP_OKAY)                 goto LBL_LS_ERR;
      if (MP_IS_ZERO(&Vz)) {
         *result = MP_YES;
         goto LBL_LS_ERR;
      }
      /* Calculate Q^{d*2^r} for next r (final iteration irrelevant). */
      if (r < (s - 1)) {
         if ((err = mp_sqr(&Qkdz, &Qkdz)) != MP_OKAY)             goto LBL_LS_ERR;
         if ((err = mp_mod(&Qkdz, a, &Qkdz)) != MP_OKAY)          goto LBL_LS_ERR;
         if ((err = mp_mul_2(&Qkdz, &Q2kdz)) != MP_OKAY)          goto LBL_LS_ERR;
      }
   }
LBL_LS_ERR:
   mp_clear_multi(&Q2kdz, &T4z, &T3z, &T2z, &T1z, &Qkdz, &Q2mz, &Qmz, &V2mz, &U2mz, &Vz, &Uz, &Np1, &gcd, &Dz, NULL);
   return err;
}
#endif
#endif
#endif

/* End: bn_mp_prime_strong_lucas_selfridge.c */

/* Start: bn_mp_radix_size.c */
#include "tommath_private.h"
#ifdef BN_MP_RADIX_SIZE_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* returns size of ASCII representation */
mp_err mp_radix_size(const mp_int *a, int radix, int *size)
{
   mp_err  err;
   int digs;
   mp_int   t;
   mp_digit d;

   *size = 0;

   /* make sure the radix is in range */
   if ((radix < 2) || (radix > 64)) {
      return MP_VAL;
   }

   if (MP_IS_ZERO(a)) {
      *size = 2;
      return MP_OKAY;
   }

   /* special case for binary */
   if (radix == 2) {
      *size = (mp_count_bits(a) + ((a->sign == MP_NEG) ? 1 : 0) + 1);
      return MP_OKAY;
   }

   /* digs is the digit count */
   digs = 0;

   /* if it's negative add one for the sign */
   if (a->sign == MP_NEG) {
      ++digs;
   }

   /* init a copy of the input */
   if ((err = mp_init_copy(&t, a)) != MP_OKAY) {
      return err;
   }

   /* force temp to positive */
   t.sign = MP_ZPOS;

   /* fetch out all of the digits */
   while (!MP_IS_ZERO(&t)) {
      if ((err = mp_div_d(&t, (mp_digit)radix, &t, &d)) != MP_OKAY) {
         goto LBL_ERR;
      }
      ++digs;
   }

   /* return digs + 1, the 1 is for the NULL byte that would be required. */
   *size = digs + 1;
   err = MP_OKAY;

LBL_ERR:
   mp_clear(&t);
   return err;
}

#endif

/* End: bn_mp_radix_size.c */

/* Start: bn_mp_radix_smap.c */
#include "tommath_private.h"
#ifdef BN_MP_RADIX_SMAP_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* chars used in radix conversions */
const char *const mp_s_rmap = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/";
const uint8_t mp_s_rmap_reverse[] = {
   0xff, 0xff, 0xff, 0x3e, 0xff, 0xff, 0xff, 0x3f, /* ()*+,-./ */
   0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, /* 01234567 */
   0x08, 0x09, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, /* 89:;<=>? */
   0xff, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, /* @ABCDEFG */
   0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, /* HIJKLMNO */
   0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, /* PQRSTUVW */
   0x21, 0x22, 0x23, 0xff, 0xff, 0xff, 0xff, 0xff, /* XYZ[\]^_ */
   0xff, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, /* `abcdefg */
   0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, /* hijklmno */
   0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, /* pqrstuvw */
   0x3b, 0x3c, 0x3d, 0xff, 0xff, 0xff, 0xff, 0xff, /* xyz{|}~. */
};
const size_t mp_s_rmap_reverse_sz = sizeof(mp_s_rmap_reverse);
#endif

/* End: bn_mp_radix_smap.c */

/* Start: bn_mp_rand.c */
#include "tommath_private.h"
#ifdef BN_MP_RAND_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

mp_err(*s_mp_rand_source)(void *out, size_t size) = s_mp_rand_platform;

void mp_rand_source(mp_err(*source)(void *out, size_t size))
{
   s_mp_rand_source = (source == NULL) ? s_mp_rand_platform : source;
}

mp_err mp_rand(mp_int *a, int digits)
{
   int i;
   mp_err err;

   mp_zero(a);

   if (digits <= 0) {
      return MP_OKAY;
   }

   if ((err = mp_grow(a, digits)) != MP_OKAY) {
      return err;
   }

   if ((err = s_mp_rand_source(a->dp, (size_t)digits * sizeof(mp_digit))) != MP_OKAY) {
      return err;
   }

   /* TODO: We ensure that the highest digit is nonzero. Should this be removed? */
   while ((a->dp[digits - 1] & MP_MASK) == 0u) {
      if ((err = s_mp_rand_source(a->dp + digits - 1, sizeof(mp_digit))) != MP_OKAY) {
         return err;
      }
   }

   a->used = digits;
   for (i = 0; i < digits; ++i) {
      a->dp[i] &= MP_MASK;
   }

   return MP_OKAY;
}
#endif

/* End: bn_mp_rand.c */

/* Start: bn_mp_read_radix.c */
#include "tommath_private.h"
#ifdef BN_MP_READ_RADIX_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

#define MP_TOUPPER(c) ((((c) >= 'a') && ((c) <= 'z')) ? (((c) + 'A') - 'a') : (c))

/* read a string [ASCII] in a given radix */
mp_err mp_read_radix(mp_int *a, const char *str, int radix)
{
   mp_err   err;
   int      y;
   mp_sign  neg;
   unsigned pos;
   char     ch;

   /* zero the digit bignum */
   mp_zero(a);

   /* make sure the radix is ok */
   if ((radix < 2) || (radix > 64)) {
      return MP_VAL;
   }

   /* if the leading digit is a
    * minus set the sign to negative.
    */
   if (*str == '-') {
      ++str;
      neg = MP_NEG;
   } else {
      neg = MP_ZPOS;
   }

   /* set the integer to the default of zero */
   mp_zero(a);

   /* process each digit of the string */
   while (*str != '\0') {
      /* if the radix <= 36 the conversion is case insensitive
       * this allows numbers like 1AB and 1ab to represent the same  value
       * [e.g. in hex]
       */
      ch = (radix <= 36) ? (char)MP_TOUPPER((int)*str) : *str;
      pos = (unsigned)(ch - '(');
      if (mp_s_rmap_reverse_sz < pos) {
         break;
      }
      y = (int)mp_s_rmap_reverse[pos];

      /* if the char was found in the map
       * and is less than the given radix add it
       * to the number, otherwise exit the loop.
       */
      if ((y == 0xff) || (y >= radix)) {
         break;
      }
      if ((err = mp_mul_d(a, (mp_digit)radix, a)) != MP_OKAY) {
         return err;
      }
      if ((err = mp_add_d(a, (mp_digit)y, a)) != MP_OKAY) {
         return err;
      }
      ++str;
   }

   /* if an illegal character was found, fail. */
   if (!((*str == '\0') || (*str == '\r') || (*str == '\n'))) {
      mp_zero(a);
      return MP_VAL;
   }

   /* set the sign only if a != 0 */
   if (!MP_IS_ZERO(a)) {
      a->sign = neg;
   }
   return MP_OKAY;
}
#endif

/* End: bn_mp_read_radix.c */

/* Start: bn_mp_reduce.c */
#include "tommath_private.h"
#ifdef BN_MP_REDUCE_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* reduces x mod m, assumes 0 < x < m**2, mu is
 * precomputed via mp_reduce_setup.
 * From HAC pp.604 Algorithm 14.42
 */
mp_err mp_reduce(mp_int *x, const mp_int *m, const mp_int *mu)
{
   mp_int  q;
   mp_err  err;
   int     um = m->used;

   /* q = x */
   if ((err = mp_init_copy(&q, x)) != MP_OKAY) {
      return err;
   }

   /* q1 = x / b**(k-1)  */
   mp_rshd(&q, um - 1);

   /* according to HAC this optimization is ok */
   if ((mp_digit)um > ((mp_digit)1 << (MP_DIGIT_BIT - 1))) {
      if ((err = mp_mul(&q, mu, &q)) != MP_OKAY) {
         goto CLEANUP;
      }
   } else if (MP_HAS(S_MP_MUL_HIGH_DIGS)) {
      if ((err = s_mp_mul_high_digs(&q, mu, &q, um)) != MP_OKAY) {
         goto CLEANUP;
      }
   } else if (MP_HAS(S_MP_MUL_HIGH_DIGS_FAST)) {
      if ((err = s_mp_mul_high_digs_fast(&q, mu, &q, um)) != MP_OKAY) {
         goto CLEANUP;
      }
   } else {
      err = MP_VAL;
      goto CLEANUP;
   }

   /* q3 = q2 / b**(k+1) */
   mp_rshd(&q, um + 1);

   /* x = x mod b**(k+1), quick (no division) */
   if ((err = mp_mod_2d(x, MP_DIGIT_BIT * (um + 1), x)) != MP_OKAY) {
      goto CLEANUP;
   }

   /* q = q * m mod b**(k+1), quick (no division) */
   if ((err = s_mp_mul_digs(&q, m, &q, um + 1)) != MP_OKAY) {
      goto CLEANUP;
   }

   /* x = x - q */
   if ((err = mp_sub(x, &q, x)) != MP_OKAY) {
      goto CLEANUP;
   }

   /* If x < 0, add b**(k+1) to it */
   if (mp_cmp_d(x, 0uL) == MP_LT) {
      mp_set(&q, 1uL);
      if ((err = mp_lshd(&q, um + 1)) != MP_OKAY) {
         goto CLEANUP;
      }
      if ((err = mp_add(x, &q, x)) != MP_OKAY) {
         goto CLEANUP;
      }
   }

   /* Back off if it's too big */
   while (mp_cmp(x, m) != MP_LT) {
      if ((err = s_mp_sub(x, m, x)) != MP_OKAY) {
         goto CLEANUP;
      }
   }

CLEANUP:
   mp_clear(&q);

   return err;
}
#endif

/* End: bn_mp_reduce.c */

/* Start: bn_mp_reduce_2k.c */
#include "tommath_private.h"
#ifdef BN_MP_REDUCE_2K_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* reduces a modulo n where n is of the form 2**p - d */
mp_err mp_reduce_2k(mp_int *a, const mp_int *n, mp_digit d)
{
   mp_int q;
   mp_err err;
   int    p;

   if ((err = mp_init(&q)) != MP_OKAY) {
      return err;
   }

   p = mp_count_bits(n);
top:
   /* q = a/2**p, a = a mod 2**p */
   if ((err = mp_div_2d(a, p, &q, a)) != MP_OKAY) {
      goto LBL_ERR;
   }

   if (d != 1u) {
      /* q = q * d */
      if ((err = mp_mul_d(&q, d, &q)) != MP_OKAY) {
         goto LBL_ERR;
      }
   }

   /* a = a + q */
   if ((err = s_mp_add(a, &q, a)) != MP_OKAY) {
      goto LBL_ERR;
   }

   if (mp_cmp_mag(a, n) != MP_LT) {
      if ((err = s_mp_sub(a, n, a)) != MP_OKAY) {
         goto LBL_ERR;
      }
      goto top;
   }

LBL_ERR:
   mp_clear(&q);
   return err;
}

#endif

/* End: bn_mp_reduce_2k.c */

/* Start: bn_mp_reduce_2k_l.c */
#include "tommath_private.h"
#ifdef BN_MP_REDUCE_2K_L_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* reduces a modulo n where n is of the form 2**p - d
   This differs from reduce_2k since "d" can be larger
   than a single digit.
*/
mp_err mp_reduce_2k_l(mp_int *a, const mp_int *n, const mp_int *d)
{
   mp_int q;
   mp_err err;
   int    p;

   if ((err = mp_init(&q)) != MP_OKAY) {
      return err;
   }

   p = mp_count_bits(n);
top:
   /* q = a/2**p, a = a mod 2**p */
   if ((err = mp_div_2d(a, p, &q, a)) != MP_OKAY) {
      goto LBL_ERR;
   }

   /* q = q * d */
   if ((err = mp_mul(&q, d, &q)) != MP_OKAY) {
      goto LBL_ERR;
   }

   /* a = a + q */
   if ((err = s_mp_add(a, &q, a)) != MP_OKAY) {
      goto LBL_ERR;
   }

   if (mp_cmp_mag(a, n) != MP_LT) {
      if ((err = s_mp_sub(a, n, a)) != MP_OKAY) {
         goto LBL_ERR;
      }
      goto top;
   }

LBL_ERR:
   mp_clear(&q);
   return err;
}

#endif

/* End: bn_mp_reduce_2k_l.c */

/* Start: bn_mp_reduce_2k_setup.c */
#include "tommath_private.h"
#ifdef BN_MP_REDUCE_2K_SETUP_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* determines the setup value */
mp_err mp_reduce_2k_setup(const mp_int *a, mp_digit *d)
{
   mp_err err;
   mp_int tmp;
   int    p;

   if ((err = mp_init(&tmp)) != MP_OKAY) {
      return err;
   }

   p = mp_count_bits(a);
   if ((err = mp_2expt(&tmp, p)) != MP_OKAY) {
      mp_clear(&tmp);
      return err;
   }

   if ((err = s_mp_sub(&tmp, a, &tmp)) != MP_OKAY) {
      mp_clear(&tmp);
      return err;
   }

   *d = tmp.dp[0];
   mp_clear(&tmp);
   return MP_OKAY;
}
#endif

/* End: bn_mp_reduce_2k_setup.c */

/* Start: bn_mp_reduce_2k_setup_l.c */
#include "tommath_private.h"
#ifdef BN_MP_REDUCE_2K_SETUP_L_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* determines the setup value */
mp_err mp_reduce_2k_setup_l(const mp_int *a, mp_int *d)
{
   mp_err err;
   mp_int tmp;

   if ((err = mp_init(&tmp)) != MP_OKAY) {
      return err;
   }

   if ((err = mp_2expt(&tmp, mp_count_bits(a))) != MP_OKAY) {
      goto LBL_ERR;
   }

   if ((err = s_mp_sub(&tmp, a, d)) != MP_OKAY) {
      goto LBL_ERR;
   }

LBL_ERR:
   mp_clear(&tmp);
   return err;
}
#endif

/* End: bn_mp_reduce_2k_setup_l.c */

/* Start: bn_mp_reduce_is_2k.c */
#include "tommath_private.h"
#ifdef BN_MP_REDUCE_IS_2K_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* determines if mp_reduce_2k can be used */
mp_bool mp_reduce_is_2k(const mp_int *a)
{
   int ix, iy, iw;
   mp_digit iz;

   if (a->used == 0) {
      return MP_NO;
   } else if (a->used == 1) {
      return MP_YES;
   } else if (a->used > 1) {
      iy = mp_count_bits(a);
      iz = 1;
      iw = 1;

      /* Test every bit from the second digit up, must be 1 */
      for (ix = MP_DIGIT_BIT; ix < iy; ix++) {
         if ((a->dp[iw] & iz) == 0u) {
            return MP_NO;
         }
         iz <<= 1;
         if (iz > MP_DIGIT_MAX) {
            ++iw;
            iz = 1;
         }
      }
      return MP_YES;
   } else {
      return MP_YES;
   }
}

#endif

/* End: bn_mp_reduce_is_2k.c */

/* Start: bn_mp_reduce_is_2k_l.c */
#include "tommath_private.h"
#ifdef BN_MP_REDUCE_IS_2K_L_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* determines if reduce_2k_l can be used */
mp_bool mp_reduce_is_2k_l(const mp_int *a)
{
   int ix, iy;

   if (a->used == 0) {
      return MP_NO;
   } else if (a->used == 1) {
      return MP_YES;
   } else if (a->used > 1) {
      /* if more than half of the digits are -1 we're sold */
      for (iy = ix = 0; ix < a->used; ix++) {
         if (a->dp[ix] == MP_DIGIT_MAX) {
            ++iy;
         }
      }
      return (iy >= (a->used/2)) ? MP_YES : MP_NO;
   } else {
      return MP_NO;
   }
}

#endif

/* End: bn_mp_reduce_is_2k_l.c */

/* Start: bn_mp_reduce_setup.c */
#include "tommath_private.h"
#ifdef BN_MP_REDUCE_SETUP_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* pre-calculate the value required for Barrett reduction
 * For a given modulus "b" it calulates the value required in "a"
 */
mp_err mp_reduce_setup(mp_int *a, const mp_int *b)
{
   mp_err err;
   if ((err = mp_2expt(a, b->used * 2 * MP_DIGIT_BIT)) != MP_OKAY) {
      return err;
   }
   return mp_div(a, b, a, NULL);
}
#endif

/* End: bn_mp_reduce_setup.c */

/* Start: bn_mp_root_u32.c */
#include "tommath_private.h"
#ifdef BN_MP_ROOT_U32_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* find the n'th root of an integer
 *
 * Result found such that (c)**b <= a and (c+1)**b > a
 *
 * This algorithm uses Newton's approximation
 * x[i+1] = x[i] - f(x[i])/f'(x[i])
 * which will find the root in log(N) time where
 * each step involves a fair bit.
 */
mp_err mp_root_u32(const mp_int *a, uint32_t b, mp_int *c)
{
   mp_int t1, t2, t3, a_;
   mp_ord cmp;
   int    ilog2;
   mp_err err;

   /* input must be positive if b is even */
   if (((b & 1u) == 0u) && (a->sign == MP_NEG)) {
      return MP_VAL;
   }

   if ((err = mp_init_multi(&t1, &t2, &t3, NULL)) != MP_OKAY) {
      return err;
   }

   /* if a is negative fudge the sign but keep track */
   a_ = *a;
   a_.sign = MP_ZPOS;

   /* Compute seed: 2^(log_2(n)/b + 2)*/
   ilog2 = mp_count_bits(a);

   /*
     If "b" is larger than INT_MAX it is also larger than
     log_2(n) because the bit-length of the "n" is measured
     with an int and hence the root is always < 2 (two).
   */
   if (b > (uint32_t)(INT_MAX/2)) {
      mp_set(c, 1uL);
      c->sign = a->sign;
      err = MP_OKAY;
      goto LBL_ERR;
   }

   /* "b" is smaller than INT_MAX, we can cast safely */
   if (ilog2 < (int)b) {
      mp_set(c, 1uL);
      c->sign = a->sign;
      err = MP_OKAY;
      goto LBL_ERR;
   }
   ilog2 =  ilog2 / ((int)b);
   if (ilog2 == 0) {
      mp_set(c, 1uL);
      c->sign = a->sign;
      err = MP_OKAY;
      goto LBL_ERR;
   }
   /* Start value must be larger than root */
   ilog2 += 2;
   if ((err = mp_2expt(&t2,ilog2)) != MP_OKAY)                    goto LBL_ERR;
   do {
      /* t1 = t2 */
      if ((err = mp_copy(&t2, &t1)) != MP_OKAY)                   goto LBL_ERR;

      /* t2 = t1 - ((t1**b - a) / (b * t1**(b-1))) */

      /* t3 = t1**(b-1) */
      if ((err = mp_expt_u32(&t1, b - 1u, &t3)) != MP_OKAY)       goto LBL_ERR;

      /* numerator */
      /* t2 = t1**b */
      if ((err = mp_mul(&t3, &t1, &t2)) != MP_OKAY)               goto LBL_ERR;

      /* t2 = t1**b - a */
      if ((err = mp_sub(&t2, &a_, &t2)) != MP_OKAY)               goto LBL_ERR;

      /* denominator */
      /* t3 = t1**(b-1) * b  */
      if ((err = mp_mul_d(&t3, b, &t3)) != MP_OKAY)               goto LBL_ERR;

      /* t3 = (t1**b - a)/(b * t1**(b-1)) */
      if ((err = mp_div(&t2, &t3, &t3, NULL)) != MP_OKAY)         goto LBL_ERR;

      if ((err = mp_sub(&t1, &t3, &t2)) != MP_OKAY)               goto LBL_ERR;

      /*
          Number of rounds is at most log_2(root). If it is more it
          got stuck, so break out of the loop and do the rest manually.
       */
      if (ilog2-- == 0) {
         break;
      }
   }  while (mp_cmp(&t1, &t2) != MP_EQ);

   /* result can be off by a few so check */
   /* Loop beneath can overshoot by one if found root is smaller than actual root */
   for (;;) {
      if ((err = mp_expt_u32(&t1, b, &t2)) != MP_OKAY)            goto LBL_ERR;
      cmp = mp_cmp(&t2, &a_);
      if (cmp == MP_EQ) {
         err = MP_OKAY;
         goto LBL_ERR;
      }
      if (cmp == MP_LT) {
         if ((err = mp_add_d(&t1, 1uL, &t1)) != MP_OKAY)          goto LBL_ERR;
      } else {
         break;
      }
   }
   /* correct overshoot from above or from recurrence */
   for (;;) {
      if ((err = mp_expt_u32(&t1, b, &t2)) != MP_OKAY)            goto LBL_ERR;
      if (mp_cmp(&t2, &a_) == MP_GT) {
         if ((err = mp_sub_d(&t1, 1uL, &t1)) != MP_OKAY)          goto LBL_ERR;
      } else {
         break;
      }
   }

   /* set the result */
   mp_exch(&t1, c);

   /* set the sign of the result */
   c->sign = a->sign;

   err = MP_OKAY;

LBL_ERR:
   mp_clear_multi(&t1, &t2, &t3, NULL);
   return err;
}

#endif

/* End: bn_mp_root_u32.c */

/* Start: bn_mp_rshd.c */
#include "tommath_private.h"
#ifdef BN_MP_RSHD_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* shift right a certain amount of digits */
void mp_rshd(mp_int *a, int b)
{
   int     x;
   mp_digit *bottom, *top;

   /* if b <= 0 then ignore it */
   if (b <= 0) {
      return;
   }

   /* if b > used then simply zero it and return */
   if (a->used <= b) {
      mp_zero(a);
      return;
   }

   /* shift the digits down */

   /* bottom */
   bottom = a->dp;

   /* top [offset into digits] */
   top = a->dp + b;

   /* this is implemented as a sliding window where
    * the window is b-digits long and digits from
    * the top of the window are copied to the bottom
    *
    * e.g.

    b-2 | b-1 | b0 | b1 | b2 | ... | bb |   ---->
                /\                   |      ---->
                 \-------------------/      ---->
    */
   for (x = 0; x < (a->used - b); x++) {
      *bottom++ = *top++;
   }

   /* zero the top digits */
   MP_ZERO_DIGITS(bottom, a->used - x);

   /* remove excess digits */
   a->used -= b;
}
#endif

/* End: bn_mp_rshd.c */

/* Start: bn_mp_sbin_size.c */
#include "tommath_private.h"
#ifdef BN_MP_SBIN_SIZE_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* get the size for an signed equivalent */
size_t mp_sbin_size(const mp_int *a)
{
   return 1u + mp_ubin_size(a);
}
#endif

/* End: bn_mp_sbin_size.c */

/* Start: bn_mp_set.c */
#include "tommath_private.h"
#ifdef BN_MP_SET_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* set to a digit */
void mp_set(mp_int *a, mp_digit b)
{
   a->dp[0] = b & MP_MASK;
   a->sign  = MP_ZPOS;
   a->used  = (a->dp[0] != 0u) ? 1 : 0;
   MP_ZERO_DIGITS(a->dp + a->used, a->alloc - a->used);
}
#endif

/* End: bn_mp_set.c */

/* Start: bn_mp_set_double.c */
#include "tommath_private.h"
#ifdef BN_MP_SET_DOUBLE_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

#if defined(__STDC_IEC_559__) || defined(__GCC_IEC_559)
mp_err mp_set_double(mp_int *a, double b)
{
   uint64_t frac;
   int exp;
   mp_err err;
   union {
      double   dbl;
      uint64_t bits;
   } cast;
   cast.dbl = b;

   exp = (int)((unsigned)(cast.bits >> 52) & 0x7FFu);
   frac = (cast.bits & ((1uLL << 52) - 1uLL)) | (1uLL << 52);

   if (exp == 0x7FF) { /* +-inf, NaN */
      return MP_VAL;
   }
   exp -= 1023 + 52;

   mp_set_u64(a, frac);

   err = (exp < 0) ? mp_div_2d(a, -exp, a, NULL) : mp_mul_2d(a, exp, a);
   if (err != MP_OKAY) {
      return err;
   }

   if (((cast.bits >> 63) != 0uLL) && !MP_IS_ZERO(a)) {
      a->sign = MP_NEG;
   }

   return MP_OKAY;
}
#else
/* pragma message() not supported by several compilers (in mostly older but still used versions) */
#  ifdef _MSC_VER
#    pragma message("mp_set_double implementation is only available on platforms with IEEE754 floating point format")
#  else
#    warning "mp_set_double implementation is only available on platforms with IEEE754 floating point format"
#  endif
#endif
#endif

/* End: bn_mp_set_double.c */

/* Start: bn_mp_set_i32.c */
#include "tommath_private.h"
#ifdef BN_MP_SET_I32_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

MP_SET_SIGNED(mp_set_i32, mp_set_u32, int32_t, uint32_t)
#endif

/* End: bn_mp_set_i32.c */

/* Start: bn_mp_set_i64.c */
#include "tommath_private.h"
#ifdef BN_MP_SET_I64_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

MP_SET_SIGNED(mp_set_i64, mp_set_u64, int64_t, uint64_t)
#endif

/* End: bn_mp_set_i64.c */

/* Start: bn_mp_set_l.c */
#include "tommath_private.h"
#ifdef BN_MP_SET_L_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

MP_SET_SIGNED(mp_set_l, mp_set_ul, long, unsigned long)
#endif

/* End: bn_mp_set_l.c */

/* Start: bn_mp_set_ll.c */
#include "tommath_private.h"
#ifdef BN_MP_SET_LL_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

MP_SET_SIGNED(mp_set_ll, mp_set_ull, long long, unsigned long long)
#endif

/* End: bn_mp_set_ll.c */

/* Start: bn_mp_set_u32.c */
#include "tommath_private.h"
#ifdef BN_MP_SET_U32_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

MP_SET_UNSIGNED(mp_set_u32, uint32_t)
#endif

/* End: bn_mp_set_u32.c */

/* Start: bn_mp_set_u64.c */
#include "tommath_private.h"
#ifdef BN_MP_SET_U64_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

MP_SET_UNSIGNED(mp_set_u64, uint64_t)
#endif

/* End: bn_mp_set_u64.c */

/* Start: bn_mp_set_ul.c */
#include "tommath_private.h"
#ifdef BN_MP_SET_UL_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

MP_SET_UNSIGNED(mp_set_ul, unsigned long)
#endif

/* End: bn_mp_set_ul.c */

/* Start: bn_mp_set_ull.c */
#include "tommath_private.h"
#ifdef BN_MP_SET_ULL_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

MP_SET_UNSIGNED(mp_set_ull, unsigned long long)
#endif

/* End: bn_mp_set_ull.c */

/* Start: bn_mp_shrink.c */
#include "tommath_private.h"
#ifdef BN_MP_SHRINK_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* shrink a bignum */
mp_err mp_shrink(mp_int *a)
{
   mp_digit *tmp;
   int alloc = MP_MAX(MP_MIN_PREC, a->used);
   if (a->alloc != alloc) {
      if ((tmp = (mp_digit *) MP_REALLOC(a->dp,
                                         (size_t)a->alloc * sizeof(mp_digit),
                                         (size_t)alloc * sizeof(mp_digit))) == NULL) {
         return MP_MEM;
      }
      a->dp    = tmp;
      a->alloc = alloc;
   }
   return MP_OKAY;
}
#endif

/* End: bn_mp_shrink.c */

/* Start: bn_mp_signed_rsh.c */
#include "tommath_private.h"
#ifdef BN_MP_SIGNED_RSH_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* shift right by a certain bit count with sign extension */
mp_err mp_signed_rsh(const mp_int *a, int b, mp_int *c)
{
   mp_err res;
   if (a->sign == MP_ZPOS) {
      return mp_div_2d(a, b, c, NULL);
   }

   res = mp_add_d(a, 1uL, c);
   if (res != MP_OKAY) {
      return res;
   }

   res = mp_div_2d(c, b, c, NULL);
   return (res == MP_OKAY) ? mp_sub_d(c, 1uL, c) : res;
}
#endif

/* End: bn_mp_signed_rsh.c */

/* Start: bn_mp_sqr.c */
#include "tommath_private.h"
#ifdef BN_MP_SQR_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* computes b = a*a */
mp_err mp_sqr(const mp_int *a, mp_int *b)
{
   mp_err err;
   if (MP_HAS(S_MP_TOOM_SQR) && /* use Toom-Cook? */
       (a->used >= MP_TOOM_SQR_CUTOFF)) {
      err = s_mp_toom_sqr(a, b);
   } else if (MP_HAS(S_MP_KARATSUBA_SQR) &&  /* Karatsuba? */
              (a->used >= MP_KARATSUBA_SQR_CUTOFF)) {
      err = s_mp_karatsuba_sqr(a, b);
   } else if (MP_HAS(S_MP_SQR_FAST) && /* can we use the fast comba multiplier? */
              (((a->used * 2) + 1) < MP_WARRAY) &&
              (a->used < (MP_MAXFAST / 2))) {
      err = s_mp_sqr_fast(a, b);
   } else if (MP_HAS(S_MP_SQR)) {
      err = s_mp_sqr(a, b);
   } else {
      err = MP_VAL;
   }
   b->sign = MP_ZPOS;
   return err;
}
#endif

/* End: bn_mp_sqr.c */

/* Start: bn_mp_sqrmod.c */
#include "tommath_private.h"
#ifdef BN_MP_SQRMOD_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* c = a * a (mod b) */
mp_err mp_sqrmod(const mp_int *a, const mp_int *b, mp_int *c)
{
   mp_err  err;
   mp_int  t;

   if ((err = mp_init(&t)) != MP_OKAY) {
      return err;
   }

   if ((err = mp_sqr(a, &t)) != MP_OKAY) {
      goto LBL_ERR;
   }
   err = mp_mod(&t, b, c);

LBL_ERR:
   mp_clear(&t);
   return err;
}
#endif

/* End: bn_mp_sqrmod.c */

/* Start: bn_mp_sqrt.c */
#include "tommath_private.h"
#ifdef BN_MP_SQRT_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* this function is less generic than mp_n_root, simpler and faster */
mp_err mp_sqrt(const mp_int *arg, mp_int *ret)
{
   mp_err err;
   mp_int t1, t2;

   /* must be positive */
   if (arg->sign == MP_NEG) {
      return MP_VAL;
   }

   /* easy out */
   if (MP_IS_ZERO(arg)) {
      mp_zero(ret);
      return MP_OKAY;
   }

   if ((err = mp_init_copy(&t1, arg)) != MP_OKAY) {
      return err;
   }

   if ((err = mp_init(&t2)) != MP_OKAY) {
      goto E2;
   }

   /* First approx. (not very bad for large arg) */
   mp_rshd(&t1, t1.used/2);

   /* t1 > 0  */
   if ((err = mp_div(arg, &t1, &t2, NULL)) != MP_OKAY) {
      goto E1;
   }
   if ((err = mp_add(&t1, &t2, &t1)) != MP_OKAY) {
      goto E1;
   }
   if ((err = mp_div_2(&t1, &t1)) != MP_OKAY) {
      goto E1;
   }
   /* And now t1 > sqrt(arg) */
   do {
      if ((err = mp_div(arg, &t1, &t2, NULL)) != MP_OKAY) {
         goto E1;
      }
      if ((err = mp_add(&t1, &t2, &t1)) != MP_OKAY) {
         goto E1;
      }
      if ((err = mp_div_2(&t1, &t1)) != MP_OKAY) {
         goto E1;
      }
      /* t1 >= sqrt(arg) >= t2 at this point */
   } while (mp_cmp_mag(&t1, &t2) == MP_GT);

   mp_exch(&t1, ret);

E1:
   mp_clear(&t2);
E2:
   mp_clear(&t1);
   return err;
}

#endif

/* End: bn_mp_sqrt.c */

/* Start: bn_mp_sqrtmod_prime.c */
#include "tommath_private.h"
#ifdef BN_MP_SQRTMOD_PRIME_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* Tonelli-Shanks algorithm
 * https://en.wikipedia.org/wiki/Tonelli%E2%80%93Shanks_algorithm
 * https://gmplib.org/list-archives/gmp-discuss/2013-April/005300.html
 *
 */

mp_err mp_sqrtmod_prime(const mp_int *n, const mp_int *prime, mp_int *ret)
{
   mp_err err;
   int legendre;
   mp_int t1, C, Q, S, Z, M, T, R, two;
   mp_digit i;

   /* first handle the simple cases */
   if (mp_cmp_d(n, 0uL) == MP_EQ) {
      mp_zero(ret);
      return MP_OKAY;
   }
   if (mp_cmp_d(prime, 2uL) == MP_EQ)                            return MP_VAL; /* prime must be odd */
   if ((err = mp_kronecker(n, prime, &legendre)) != MP_OKAY)        return err;
   if (legendre == -1)                                           return MP_VAL; /* quadratic non-residue mod prime */

   if ((err = mp_init_multi(&t1, &C, &Q, &S, &Z, &M, &T, &R, &two, NULL)) != MP_OKAY) {
      return err;
   }

   /* SPECIAL CASE: if prime mod 4 == 3
    * compute directly: err = n^(prime+1)/4 mod prime
    * Handbook of Applied Cryptography algorithm 3.36
    */
   if ((err = mp_mod_d(prime, 4uL, &i)) != MP_OKAY)               goto cleanup;
   if (i == 3u) {
      if ((err = mp_add_d(prime, 1uL, &t1)) != MP_OKAY)           goto cleanup;
      if ((err = mp_div_2(&t1, &t1)) != MP_OKAY)                  goto cleanup;
      if ((err = mp_div_2(&t1, &t1)) != MP_OKAY)                  goto cleanup;
      if ((err = mp_exptmod(n, &t1, prime, ret)) != MP_OKAY)      goto cleanup;
      err = MP_OKAY;
      goto cleanup;
   }

   /* NOW: Tonelli-Shanks algorithm */

   /* factor out powers of 2 from prime-1, defining Q and S as: prime-1 = Q*2^S */
   if ((err = mp_copy(prime, &Q)) != MP_OKAY)                    goto cleanup;
   if ((err = mp_sub_d(&Q, 1uL, &Q)) != MP_OKAY)                 goto cleanup;
   /* Q = prime - 1 */
   mp_zero(&S);
   /* S = 0 */
   while (MP_IS_EVEN(&Q)) {
      if ((err = mp_div_2(&Q, &Q)) != MP_OKAY)                    goto cleanup;
      /* Q = Q / 2 */
      if ((err = mp_add_d(&S, 1uL, &S)) != MP_OKAY)               goto cleanup;
      /* S = S + 1 */
   }

   /* find a Z such that the Legendre symbol (Z|prime) == -1 */
   mp_set_u32(&Z, 2u);
   /* Z = 2 */
   for (;;) {
      if ((err = mp_kronecker(&Z, prime, &legendre)) != MP_OKAY)     goto cleanup;
      if (legendre == -1) break;
      if ((err = mp_add_d(&Z, 1uL, &Z)) != MP_OKAY)               goto cleanup;
      /* Z = Z + 1 */
   }

   if ((err = mp_exptmod(&Z, &Q, prime, &C)) != MP_OKAY)         goto cleanup;
   /* C = Z ^ Q mod prime */
   if ((err = mp_add_d(&Q, 1uL, &t1)) != MP_OKAY)                goto cleanup;
   if ((err = mp_div_2(&t1, &t1)) != MP_OKAY)                    goto cleanup;
   /* t1 = (Q + 1) / 2 */
   if ((err = mp_exptmod(n, &t1, prime, &R)) != MP_OKAY)         goto cleanup;
   /* R = n ^ ((Q + 1) / 2) mod prime */
   if ((err = mp_exptmod(n, &Q, prime, &T)) != MP_OKAY)          goto cleanup;
   /* T = n ^ Q mod prime */
   if ((err = mp_copy(&S, &M)) != MP_OKAY)                       goto cleanup;
   /* M = S */
   mp_set_u32(&two, 2u);

   for (;;) {
      if ((err = mp_copy(&T, &t1)) != MP_OKAY)                    goto cleanup;
      i = 0;
      for (;;) {
         if (mp_cmp_d(&t1, 1uL) == MP_EQ) break;
         if ((err = mp_exptmod(&t1, &two, prime, &t1)) != MP_OKAY) goto cleanup;
         i++;
      }
      if (i == 0u) {
         if ((err = mp_copy(&R, ret)) != MP_OKAY)                  goto cleanup;
         err = MP_OKAY;
         goto cleanup;
      }
      if ((err = mp_sub_d(&M, i, &t1)) != MP_OKAY)                goto cleanup;
      if ((err = mp_sub_d(&t1, 1uL, &t1)) != MP_OKAY)             goto cleanup;
      if ((err = mp_exptmod(&two, &t1, prime, &t1)) != MP_OKAY)   goto cleanup;
      /* t1 = 2 ^ (M - i - 1) */
      if ((err = mp_exptmod(&C, &t1, prime, &t1)) != MP_OKAY)     goto cleanup;
      /* t1 = C ^ (2 ^ (M - i - 1)) mod prime */
      if ((err = mp_sqrmod(&t1, prime, &C)) != MP_OKAY)           goto cleanup;
      /* C = (t1 * t1) mod prime */
      if ((err = mp_mulmod(&R, &t1, prime, &R)) != MP_OKAY)       goto cleanup;
      /* R = (R * t1) mod prime */
      if ((err = mp_mulmod(&T, &C, prime, &T)) != MP_OKAY)        goto cleanup;
      /* T = (T * C) mod prime */
      mp_set(&M, i);
      /* M = i */
   }

cleanup:
   mp_clear_multi(&t1, &C, &Q, &S, &Z, &M, &T, &R, &two, NULL);
   return err;
}

#endif

/* End: bn_mp_sqrtmod_prime.c */

/* Start: bn_mp_sub.c */
#include "tommath_private.h"
#ifdef BN_MP_SUB_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* high level subtraction (handles signs) */
mp_err mp_sub(const mp_int *a, const mp_int *b, mp_int *c)
{
   mp_sign sa = a->sign, sb = b->sign;
   mp_err err;

   if (sa != sb) {
      /* subtract a negative from a positive, OR */
      /* subtract a positive from a negative. */
      /* In either case, ADD their magnitudes, */
      /* and use the sign of the first number. */
      c->sign = sa;
      err = s_mp_add(a, b, c);
   } else {
      /* subtract a positive from a positive, OR */
      /* subtract a negative from a negative. */
      /* First, take the difference between their */
      /* magnitudes, then... */
      if (mp_cmp_mag(a, b) != MP_LT) {
         /* Copy the sign from the first */
         c->sign = sa;
         /* The first has a larger or equal magnitude */
         err = s_mp_sub(a, b, c);
      } else {
         /* The result has the *opposite* sign from */
         /* the first number. */
         c->sign = (sa == MP_ZPOS) ? MP_NEG : MP_ZPOS;
         /* The second has a larger magnitude */
         err = s_mp_sub(b, a, c);
      }
   }
   return err;
}

#endif

/* End: bn_mp_sub.c */

/* Start: bn_mp_sub_d.c */
#include "tommath_private.h"
#ifdef BN_MP_SUB_D_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* single digit subtraction */
mp_err mp_sub_d(const mp_int *a, mp_digit b, mp_int *c)
{
   mp_digit *tmpa, *tmpc;
   mp_err    err;
   int       ix, oldused;

   /* grow c as required */
   if (c->alloc < (a->used + 1)) {
      if ((err = mp_grow(c, a->used + 1)) != MP_OKAY) {
         return err;
      }
   }

   /* if a is negative just do an unsigned
    * addition [with fudged signs]
    */
   if (a->sign == MP_NEG) {
      mp_int a_ = *a;
      a_.sign = MP_ZPOS;
      err     = mp_add_d(&a_, b, c);
      c->sign = MP_NEG;

      /* clamp */
      mp_clamp(c);

      return err;
   }

   /* setup regs */
   oldused = c->used;
   tmpa    = a->dp;
   tmpc    = c->dp;

   /* if a <= b simply fix the single digit */
   if (((a->used == 1) && (a->dp[0] <= b)) || (a->used == 0)) {
      if (a->used == 1) {
         *tmpc++ = b - *tmpa;
      } else {
         *tmpc++ = b;
      }
      ix      = 1;

      /* negative/1digit */
      c->sign = MP_NEG;
      c->used = 1;
   } else {
      mp_digit mu = b;

      /* positive/size */
      c->sign = MP_ZPOS;
      c->used = a->used;

      /* subtract digits, mu is carry */
      for (ix = 0; ix < a->used; ix++) {
         *tmpc    = *tmpa++ - mu;
         mu       = *tmpc >> (MP_SIZEOF_BITS(mp_digit) - 1u);
         *tmpc++ &= MP_MASK;
      }
   }

   /* zero excess digits */
   MP_ZERO_DIGITS(tmpc, oldused - ix);

   mp_clamp(c);
   return MP_OKAY;
}

#endif

/* End: bn_mp_sub_d.c */

/* Start: bn_mp_submod.c */
#include "tommath_private.h"
#ifdef BN_MP_SUBMOD_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* d = a - b (mod c) */
mp_err mp_submod(const mp_int *a, const mp_int *b, const mp_int *c, mp_int *d)
{
   mp_err err;
   mp_int t;

   if ((err = mp_init(&t)) != MP_OKAY) {
      return err;
   }

   if ((err = mp_sub(a, b, &t)) != MP_OKAY) {
      goto LBL_ERR;
   }
   err = mp_mod(&t, c, d);

LBL_ERR:
   mp_clear(&t);
   return err;
}
#endif

/* End: bn_mp_submod.c */

/* Start: bn_mp_to_radix.c */
#include "tommath_private.h"
#ifdef BN_MP_TO_RADIX_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* stores a bignum as a ASCII string in a given radix (2..64)
 *
 * Stores upto "size - 1" chars and always a NULL byte, puts the number of characters
 * written, including the '\0', in "written".
 */
mp_err mp_to_radix(const mp_int *a, char *str, size_t maxlen, size_t *written, int radix)
{
   size_t  digs;
   mp_err  err;
   mp_int  t;
   mp_digit d;
   char   *_s = str;

   /* check range of radix and size*/
   if (maxlen < 2u) {
      return MP_BUF;
   }
   if ((radix < 2) || (radix > 64)) {
      return MP_VAL;
   }

   /* quick out if its zero */
   if (MP_IS_ZERO(a)) {
      *str++ = '0';
      *str = '\0';
      if (written != NULL) {
         *written = 2u;
      }
      return MP_OKAY;
   }

   if ((err = mp_init_copy(&t, a)) != MP_OKAY) {
      return err;
   }

   /* if it is negative output a - */
   if (t.sign == MP_NEG) {
      /* we have to reverse our digits later... but not the - sign!! */
      ++_s;

      /* store the flag and mark the number as positive */
      *str++ = '-';
      t.sign = MP_ZPOS;

      /* subtract a char */
      --maxlen;
   }
   digs = 0u;
   while (!MP_IS_ZERO(&t)) {
      if (--maxlen < 1u) {
         /* no more room */
         err = MP_BUF;
         goto LBL_ERR;
      }
      if ((err = mp_div_d(&t, (mp_digit)radix, &t, &d)) != MP_OKAY) {
         goto LBL_ERR;
      }
      *str++ = mp_s_rmap[d];
      ++digs;
   }
   /* reverse the digits of the string.  In this case _s points
    * to the first digit [exluding the sign] of the number
    */
   s_mp_reverse((unsigned char *)_s, digs);

   /* append a NULL so the string is properly terminated */
   *str = '\0';
   digs++;

   if (written != NULL) {
      *written = (a->sign == MP_NEG) ? (digs + 1u): digs;
   }

LBL_ERR:
   mp_clear(&t);
   return err;
}

#endif

/* End: bn_mp_to_radix.c */

/* Start: bn_mp_to_sbin.c */
#include "tommath_private.h"
#ifdef BN_MP_TO_SBIN_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* store in signed [big endian] format */
mp_err mp_to_sbin(const mp_int *a, unsigned char *buf, size_t maxlen, size_t *written)
{
   mp_err err;
   if (maxlen == 0u) {
      return MP_BUF;
   }
   if ((err = mp_to_ubin(a, buf + 1, maxlen - 1u, written)) != MP_OKAY) {
      return err;
   }
   if (written != NULL) {
      (*written)++;
   }
   buf[0] = (a->sign == MP_ZPOS) ? (unsigned char)0 : (unsigned char)1;
   return MP_OKAY;
}
#endif

/* End: bn_mp_to_sbin.c */

/* Start: bn_mp_to_ubin.c */
#include "tommath_private.h"
#ifdef BN_MP_TO_UBIN_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* store in unsigned [big endian] format */
mp_err mp_to_ubin(const mp_int *a, unsigned char *buf, size_t maxlen, size_t *written)
{
   size_t  x, count;
   mp_err  err;
   mp_int  t;

   count = mp_ubin_size(a);
   if (count > maxlen) {
      return MP_BUF;
   }

   if ((err = mp_init_copy(&t, a)) != MP_OKAY) {
      return err;
   }

   for (x = count; x --> 0u;) {
#ifndef MP_8BIT
      buf[x] = (unsigned char)(t.dp[0] & 255u);
#else
      buf[x] = (unsigned char)(t.dp[0] | ((t.dp[1] & 1u) << 7));
#endif
      if ((err = mp_div_2d(&t, 8, &t, NULL)) != MP_OKAY) {
         goto LBL_ERR;
      }
   }

   if (written != NULL) {
      *written = count;
   }

LBL_ERR:
   mp_clear(&t);
   return err;
}
#endif

/* End: bn_mp_to_ubin.c */

/* Start: bn_mp_ubin_size.c */
#include "tommath_private.h"
#ifdef BN_MP_UBIN_SIZE_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* get the size for an unsigned equivalent */
size_t mp_ubin_size(const mp_int *a)
{
   size_t size = (size_t)mp_count_bits(a);
   return (size / 8u) + (((size & 7u) != 0u) ? 1u : 0u);
}
#endif

/* End: bn_mp_ubin_size.c */

/* Start: bn_mp_unpack.c */
#include "tommath_private.h"
#ifdef BN_MP_UNPACK_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* based on gmp's mpz_import.
 * see http://gmplib.org/manual/Integer-Import-and-Export.html
 */
mp_err mp_unpack(mp_int *rop, size_t count, mp_order order, size_t size,
                 mp_endian endian, size_t nails, const void *op)
{
   mp_err err;
   size_t odd_nails, nail_bytes, i, j;
   unsigned char odd_nail_mask;

   mp_zero(rop);

   if (endian == MP_NATIVE_ENDIAN) {
      MP_GET_ENDIANNESS(endian);
   }

   odd_nails = (nails % 8u);
   odd_nail_mask = 0xff;
   for (i = 0; i < odd_nails; ++i) {
      odd_nail_mask ^= (unsigned char)(1u << (7u - i));
   }
   nail_bytes = nails / 8u;

   for (i = 0; i < count; ++i) {
      for (j = 0; j < (size - nail_bytes); ++j) {
         unsigned char byte = *((const unsigned char *)op +
                                (((order == MP_MSB_FIRST) ? i : ((count - 1u) - i)) * size) +
                                ((endian == MP_BIG_ENDIAN) ? (j + nail_bytes) : (((size - 1u) - j) - nail_bytes)));

         if ((err = mp_mul_2d(rop, (j == 0u) ? (int)(8u - odd_nails) : 8, rop)) != MP_OKAY) {
            return err;
         }

         rop->dp[0] |= (j == 0u) ? (mp_digit)(byte & odd_nail_mask) : (mp_digit)byte;
         rop->used  += 1;
      }
   }

   mp_clamp(rop);

   return MP_OKAY;
}

#endif

/* End: bn_mp_unpack.c */

/* Start: bn_mp_xor.c */
#include "tommath_private.h"
#ifdef BN_MP_XOR_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* two complement xor */
mp_err mp_xor(const mp_int *a, const mp_int *b, mp_int *c)
{
   int used = MP_MAX(a->used, b->used) + 1, i;
   mp_err err;
   mp_digit ac = 1, bc = 1, cc = 1;
   mp_sign csign = (a->sign != b->sign) ? MP_NEG : MP_ZPOS;

   if (c->alloc < used) {
      if ((err = mp_grow(c, used)) != MP_OKAY) {
         return err;
      }
   }

   for (i = 0; i < used; i++) {
      mp_digit x, y;

      /* convert to two complement if negative */
      if (a->sign == MP_NEG) {
         ac += (i >= a->used) ? MP_MASK : (~a->dp[i] & MP_MASK);
         x = ac & MP_MASK;
         ac >>= MP_DIGIT_BIT;
      } else {
         x = (i >= a->used) ? 0uL : a->dp[i];
      }

      /* convert to two complement if negative */
      if (b->sign == MP_NEG) {
         bc += (i >= b->used) ? MP_MASK : (~b->dp[i] & MP_MASK);
         y = bc & MP_MASK;
         bc >>= MP_DIGIT_BIT;
      } else {
         y = (i >= b->used) ? 0uL : b->dp[i];
      }

      c->dp[i] = x ^ y;

      /* convert to to sign-magnitude if negative */
      if (csign == MP_NEG) {
         cc += ~c->dp[i] & MP_MASK;
         c->dp[i] = cc & MP_MASK;
         cc >>= MP_DIGIT_BIT;
      }
   }

   c->used = used;
   c->sign = csign;
   mp_clamp(c);
   return MP_OKAY;
}
#endif

/* End: bn_mp_xor.c */

/* Start: bn_mp_zero.c */
#include "tommath_private.h"
#ifdef BN_MP_ZERO_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* set to zero */
void mp_zero(mp_int *a)
{
   a->sign = MP_ZPOS;
   a->used = 0;
   MP_ZERO_DIGITS(a->dp, a->alloc);
}
#endif

/* End: bn_mp_zero.c */

/* Start: bn_prime_tab.c */
#include "tommath_private.h"
#ifdef BN_PRIME_TAB_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

const mp_digit ltm_prime_tab[] = {
   0x0002, 0x0003, 0x0005, 0x0007, 0x000B, 0x000D, 0x0011, 0x0013,
   0x0017, 0x001D, 0x001F, 0x0025, 0x0029, 0x002B, 0x002F, 0x0035,
   0x003B, 0x003D, 0x0043, 0x0047, 0x0049, 0x004F, 0x0053, 0x0059,
   0x0061, 0x0065, 0x0067, 0x006B, 0x006D, 0x0071, 0x007F,
#ifndef MP_8BIT
   0x0083,
   0x0089, 0x008B, 0x0095, 0x0097, 0x009D, 0x00A3, 0x00A7, 0x00AD,
   0x00B3, 0x00B5, 0x00BF, 0x00C1, 0x00C5, 0x00C7, 0x00D3, 0x00DF,
   0x00E3, 0x00E5, 0x00E9, 0x00EF, 0x00F1, 0x00FB, 0x0101, 0x0107,
   0x010D, 0x010F, 0x0115, 0x0119, 0x011B, 0x0125, 0x0133, 0x0137,

   0x0139, 0x013D, 0x014B, 0x0151, 0x015B, 0x015D, 0x0161, 0x0167,
   0x016F, 0x0175, 0x017B, 0x017F, 0x0185, 0x018D, 0x0191, 0x0199,
   0x01A3, 0x01A5, 0x01AF, 0x01B1, 0x01B7, 0x01BB, 0x01C1, 0x01C9,
   0x01CD, 0x01CF, 0x01D3, 0x01DF, 0x01E7, 0x01EB, 0x01F3, 0x01F7,
   0x01FD, 0x0209, 0x020B, 0x021D, 0x0223, 0x022D, 0x0233, 0x0239,
   0x023B, 0x0241, 0x024B, 0x0251, 0x0257, 0x0259, 0x025F, 0x0265,
   0x0269, 0x026B, 0x0277, 0x0281, 0x0283, 0x0287, 0x028D, 0x0293,
   0x0295, 0x02A1, 0x02A5, 0x02AB, 0x02B3, 0x02BD, 0x02C5, 0x02CF,

   0x02D7, 0x02DD, 0x02E3, 0x02E7, 0x02EF, 0x02F5, 0x02F9, 0x0301,
   0x0305, 0x0313, 0x031D, 0x0329, 0x032B, 0x0335, 0x0337, 0x033B,
   0x033D, 0x0347, 0x0355, 0x0359, 0x035B, 0x035F, 0x036D, 0x0371,
   0x0373, 0x0377, 0x038B, 0x038F, 0x0397, 0x03A1, 0x03A9, 0x03AD,
   0x03B3, 0x03B9, 0x03C7, 0x03CB, 0x03D1, 0x03D7, 0x03DF, 0x03E5,
   0x03F1, 0x03F5, 0x03FB, 0x03FD, 0x0407, 0x0409, 0x040F, 0x0419,
   0x041B, 0x0425, 0x0427, 0x042D, 0x043F, 0x0443, 0x0445, 0x0449,
   0x044F, 0x0455, 0x045D, 0x0463, 0x0469, 0x047F, 0x0481, 0x048B,

   0x0493, 0x049D, 0x04A3, 0x04A9, 0x04B1, 0x04BD, 0x04C1, 0x04C7,
   0x04CD, 0x04CF, 0x04D5, 0x04E1, 0x04EB, 0x04FD, 0x04FF, 0x0503,
   0x0509, 0x050B, 0x0511, 0x0515, 0x0517, 0x051B, 0x0527, 0x0529,
   0x052F, 0x0551, 0x0557, 0x055D, 0x0565, 0x0577, 0x0581, 0x058F,
   0x0593, 0x0595, 0x0599, 0x059F, 0x05A7, 0x05AB, 0x05AD, 0x05B3,
   0x05BF, 0x05C9, 0x05CB, 0x05CF, 0x05D1, 0x05D5, 0x05DB, 0x05E7,
   0x05F3, 0x05FB, 0x0607, 0x060D, 0x0611, 0x0617, 0x061F, 0x0623,
   0x062B, 0x062F, 0x063D, 0x0641, 0x0647, 0x0649, 0x064D, 0x0653
#endif
};

#if defined(__GNUC__) && __GNUC__ >= 4
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
const mp_digit *s_mp_prime_tab = ltm_prime_tab;
#pragma GCC diagnostic pop
#elif defined(_MSC_VER) && _MSC_VER >= 1500
#pragma warning(push)
#pragma warning(disable: 4996)
const mp_digit *s_mp_prime_tab = ltm_prime_tab;
#pragma warning(pop)
#else
const mp_digit *s_mp_prime_tab = ltm_prime_tab;
#endif

#endif

/* End: bn_prime_tab.c */

/* Start: bn_s_mp_add.c */
#include "tommath_private.h"
#ifdef BN_S_MP_ADD_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* low level addition, based on HAC pp.594, Algorithm 14.7 */
mp_err s_mp_add(const mp_int *a, const mp_int *b, mp_int *c)
{
   const mp_int *x;
   mp_err err;
   int     olduse, min, max;

   /* find sizes, we let |a| <= |b| which means we have to sort
    * them.  "x" will point to the input with the most digits
    */
   if (a->used > b->used) {
      min = b->used;
      max = a->used;
      x = a;
   } else {
      min = a->used;
      max = b->used;
      x = b;
   }

   /* init result */
   if (c->alloc < (max + 1)) {
      if ((err = mp_grow(c, max + 1)) != MP_OKAY) {
         return err;
      }
   }

   /* get old used digit count and set new one */
   olduse = c->used;
   c->used = max + 1;

   {
      mp_digit u, *tmpa, *tmpb, *tmpc;
      int i;

      /* alias for digit pointers */

      /* first input */
      tmpa = a->dp;

      /* second input */
      tmpb = b->dp;

      /* destination */
      tmpc = c->dp;

      /* zero the carry */
      u = 0;
      for (i = 0; i < min; i++) {
         /* Compute the sum at one digit, T[i] = A[i] + B[i] + U */
         *tmpc = *tmpa++ + *tmpb++ + u;

         /* U = carry bit of T[i] */
         u = *tmpc >> (mp_digit)MP_DIGIT_BIT;

         /* take away carry bit from T[i] */
         *tmpc++ &= MP_MASK;
      }

      /* now copy higher words if any, that is in A+B
       * if A or B has more digits add those in
       */
      if (min != max) {
         for (; i < max; i++) {
            /* T[i] = X[i] + U */
            *tmpc = x->dp[i] + u;

            /* U = carry bit of T[i] */
            u = *tmpc >> (mp_digit)MP_DIGIT_BIT;

            /* take away carry bit from T[i] */
            *tmpc++ &= MP_MASK;
         }
      }

      /* add carry */
      *tmpc++ = u;

      /* clear digits above oldused */
      MP_ZERO_DIGITS(tmpc, olduse - c->used);
   }

   mp_clamp(c);
   return MP_OKAY;
}
#endif

/* End: bn_s_mp_add.c */

/* Start: bn_s_mp_balance_mul.c */
#include "tommath_private.h"
#ifdef BN_S_MP_BALANCE_MUL_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* single-digit multiplication with the smaller number as the single-digit */
mp_err s_mp_balance_mul(const mp_int *a, const mp_int *b, mp_int *c)
{
   int count, len_a, len_b, nblocks, i, j, bsize;
   mp_int a0, tmp, A, B, r;
   mp_err err;

   len_a = a->used;
   len_b = b->used;

   nblocks = MP_MAX(a->used, b->used) / MP_MIN(a->used, b->used);
   bsize = MP_MIN(a->used, b->used) ;

   if ((err = mp_init_size(&a0, bsize + 2)) != MP_OKAY) {
      return err;
   }
   if ((err = mp_init_multi(&tmp, &r, NULL)) != MP_OKAY) {
      mp_clear(&a0);
      return err;
   }

   /* Make sure that A is the larger one*/
   if (len_a < len_b) {
      B = *a;
      A = *b;
   } else {
      A = *a;
      B = *b;
   }

   for (i = 0, j=0; i < nblocks; i++) {
      /* Cut a slice off of a */
      a0.used = 0;
      for (count = 0; count < bsize; count++) {
         a0.dp[count] = A.dp[ j++ ];
         a0.used++;
      }
      mp_clamp(&a0);
      /* Multiply with b */
      if ((err = mp_mul(&a0, &B, &tmp)) != MP_OKAY) {
         goto LBL_ERR;
      }
      /* Shift tmp to the correct position */
      if ((err = mp_lshd(&tmp, bsize * i)) != MP_OKAY) {
         goto LBL_ERR;
      }
      /* Add to output. No carry needed */
      if ((err = mp_add(&r, &tmp, &r)) != MP_OKAY) {
         goto LBL_ERR;
      }
   }
   /* The left-overs; there are always left-overs */
   if (j < A.used) {
      a0.used = 0;
      for (count = 0; j < A.used; count++) {
         a0.dp[count] = A.dp[ j++ ];
         a0.used++;
      }
      mp_clamp(&a0);
      if ((err = mp_mul(&a0, &B, &tmp)) != MP_OKAY) {
         goto LBL_ERR;
      }
      if ((err = mp_lshd(&tmp, bsize * i)) != MP_OKAY) {
         goto LBL_ERR;
      }
      if ((err = mp_add(&r, &tmp, &r)) != MP_OKAY) {
         goto LBL_ERR;
      }
   }

   mp_exch(&r,c);
LBL_ERR:
   mp_clear_multi(&a0, &tmp, &r,NULL);
   return err;
}
#endif

/* End: bn_s_mp_balance_mul.c */

/* Start: bn_s_mp_exptmod.c */
#include "tommath_private.h"
#ifdef BN_S_MP_EXPTMOD_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

#ifdef MP_LOW_MEM
#   define TAB_SIZE 32
#   define MAX_WINSIZE 5
#else
#   define TAB_SIZE 256
#   define MAX_WINSIZE 0
#endif

mp_err s_mp_exptmod(const mp_int *G, const mp_int *X, const mp_int *P, mp_int *Y, int redmode)
{
   mp_int  M[TAB_SIZE], res, mu;
   mp_digit buf;
   mp_err   err;
   int      bitbuf, bitcpy, bitcnt, mode, digidx, x, y, winsize;
   mp_err(*redux)(mp_int *x, const mp_int *m, const mp_int *mu);

   /* find window size */
   x = mp_count_bits(X);
   if (x <= 7) {
      winsize = 2;
   } else if (x <= 36) {
      winsize = 3;
   } else if (x <= 140) {
      winsize = 4;
   } else if (x <= 450) {
      winsize = 5;
   } else if (x <= 1303) {
      winsize = 6;
   } else if (x <= 3529) {
      winsize = 7;
   } else {
      winsize = 8;
   }

   winsize = MAX_WINSIZE ? MP_MIN(MAX_WINSIZE, winsize) : winsize;

   /* init M array */
   /* init first cell */
   if ((err = mp_init(&M[1])) != MP_OKAY) {
      return err;
   }

   /* now init the second half of the array */
   for (x = 1<<(winsize-1); x < (1 << winsize); x++) {
      if ((err = mp_init(&M[x])) != MP_OKAY) {
         for (y = 1<<(winsize-1); y < x; y++) {
            mp_clear(&M[y]);
         }
         mp_clear(&M[1]);
         return err;
      }
   }

   /* create mu, used for Barrett reduction */
   if ((err = mp_init(&mu)) != MP_OKAY)                           goto LBL_M;

   if (redmode == 0) {
      if ((err = mp_reduce_setup(&mu, P)) != MP_OKAY)             goto LBL_MU;
      redux = mp_reduce;
   } else {
      if ((err = mp_reduce_2k_setup_l(P, &mu)) != MP_OKAY)        goto LBL_MU;
      redux = mp_reduce_2k_l;
   }

   /* create M table
    *
    * The M table contains powers of the base,
    * e.g. M[x] = G**x mod P
    *
    * The first half of the table is not
    * computed though accept for M[0] and M[1]
    */
   if ((err = mp_mod(G, P, &M[1])) != MP_OKAY)                    goto LBL_MU;

   /* compute the value at M[1<<(winsize-1)] by squaring
    * M[1] (winsize-1) times
    */
   if ((err = mp_copy(&M[1], &M[(size_t)1 << (winsize - 1)])) != MP_OKAY) goto LBL_MU;

   for (x = 0; x < (winsize - 1); x++) {
      /* square it */
      if ((err = mp_sqr(&M[(size_t)1 << (winsize - 1)],
                        &M[(size_t)1 << (winsize - 1)])) != MP_OKAY) goto LBL_MU;

      /* reduce modulo P */
      if ((err = redux(&M[(size_t)1 << (winsize - 1)], P, &mu)) != MP_OKAY) goto LBL_MU;
   }

   /* create upper table, that is M[x] = M[x-1] * M[1] (mod P)
    * for x = (2**(winsize - 1) + 1) to (2**winsize - 1)
    */
   for (x = (1 << (winsize - 1)) + 1; x < (1 << winsize); x++) {
      if ((err = mp_mul(&M[x - 1], &M[1], &M[x])) != MP_OKAY)     goto LBL_MU;
      if ((err = redux(&M[x], P, &mu)) != MP_OKAY)                goto LBL_MU;
   }

   /* setup result */
   if ((err = mp_init(&res)) != MP_OKAY)                          goto LBL_MU;
   mp_set(&res, 1uL);

   /* set initial mode and bit cnt */
   mode   = 0;
   bitcnt = 1;
   buf    = 0;
   digidx = X->used - 1;
   bitcpy = 0;
   bitbuf = 0;

   for (;;) {
      /* grab next digit as required */
      if (--bitcnt == 0) {
         /* if digidx == -1 we are out of digits */
         if (digidx == -1) {
            break;
         }
         /* read next digit and reset the bitcnt */
         buf    = X->dp[digidx--];
         bitcnt = (int)MP_DIGIT_BIT;
      }

      /* grab the next msb from the exponent */
      y     = (buf >> (mp_digit)(MP_DIGIT_BIT - 1)) & 1uL;
      buf <<= (mp_digit)1;

      /* if the bit is zero and mode == 0 then we ignore it
       * These represent the leading zero bits before the first 1 bit
       * in the exponent.  Technically this opt is not required but it
       * does lower the # of trivial squaring/reductions used
       */
      if ((mode == 0) && (y == 0)) {
         continue;
      }

      /* if the bit is zero and mode == 1 then we square */
      if ((mode == 1) && (y == 0)) {
         if ((err = mp_sqr(&res, &res)) != MP_OKAY)               goto LBL_RES;
         if ((err = redux(&res, P, &mu)) != MP_OKAY)              goto LBL_RES;
         continue;
      }

      /* else we add it to the window */
      bitbuf |= (y << (winsize - ++bitcpy));
      mode    = 2;

      if (bitcpy == winsize) {
         /* ok window is filled so square as required and multiply  */
         /* square first */
         for (x = 0; x < winsize; x++) {
            if ((err = mp_sqr(&res, &res)) != MP_OKAY)            goto LBL_RES;
            if ((err = redux(&res, P, &mu)) != MP_OKAY)           goto LBL_RES;
         }

         /* then multiply */
         if ((err = mp_mul(&res, &M[bitbuf], &res)) != MP_OKAY)  goto LBL_RES;
         if ((err = redux(&res, P, &mu)) != MP_OKAY)             goto LBL_RES;

         /* empty window and reset */
         bitcpy = 0;
         bitbuf = 0;
         mode   = 1;
      }
   }

   /* if bits remain then square/multiply */
   if ((mode == 2) && (bitcpy > 0)) {
      /* square then multiply if the bit is set */
      for (x = 0; x < bitcpy; x++) {
         if ((err = mp_sqr(&res, &res)) != MP_OKAY)               goto LBL_RES;
         if ((err = redux(&res, P, &mu)) != MP_OKAY)              goto LBL_RES;

         bitbuf <<= 1;
         if ((bitbuf & (1 << winsize)) != 0) {
            /* then multiply */
            if ((err = mp_mul(&res, &M[1], &res)) != MP_OKAY)     goto LBL_RES;
            if ((err = redux(&res, P, &mu)) != MP_OKAY)           goto LBL_RES;
         }
      }
   }

   mp_exch(&res, Y);
   err = MP_OKAY;
LBL_RES:
   mp_clear(&res);
LBL_MU:
   mp_clear(&mu);
LBL_M:
   mp_clear(&M[1]);
   for (x = 1<<(winsize-1); x < (1 << winsize); x++) {
      mp_clear(&M[x]);
   }
   return err;
}
#endif

/* End: bn_s_mp_exptmod.c */

/* Start: bn_s_mp_exptmod_fast.c */
#include "tommath_private.h"
#ifdef BN_S_MP_EXPTMOD_FAST_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* computes Y == G**X mod P, HAC pp.616, Algorithm 14.85
 *
 * Uses a left-to-right k-ary sliding window to compute the modular exponentiation.
 * The value of k changes based on the size of the exponent.
 *
 * Uses Montgomery or Diminished Radix reduction [whichever appropriate]
 */

#ifdef MP_LOW_MEM
#   define TAB_SIZE 32
#   define MAX_WINSIZE 5
#else
#   define TAB_SIZE 256
#   define MAX_WINSIZE 0
#endif

mp_err s_mp_exptmod_fast(const mp_int *G, const mp_int *X, const mp_int *P, mp_int *Y, int redmode)
{
   mp_int  M[TAB_SIZE], res;
   mp_digit buf, mp;
   int     bitbuf, bitcpy, bitcnt, mode, digidx, x, y, winsize;
   mp_err   err;

   /* use a pointer to the reduction algorithm.  This allows us to use
    * one of many reduction algorithms without modding the guts of
    * the code with if statements everywhere.
    */
   mp_err(*redux)(mp_int *x, const mp_int *n, mp_digit rho);

   /* find window size */
   x = mp_count_bits(X);
   if (x <= 7) {
      winsize = 2;
   } else if (x <= 36) {
      winsize = 3;
   } else if (x <= 140) {
      winsize = 4;
   } else if (x <= 450) {
      winsize = 5;
   } else if (x <= 1303) {
      winsize = 6;
   } else if (x <= 3529) {
      winsize = 7;
   } else {
      winsize = 8;
   }

   winsize = MAX_WINSIZE ? MP_MIN(MAX_WINSIZE, winsize) : winsize;

   /* init M array */
   /* init first cell */
   if ((err = mp_init_size(&M[1], P->alloc)) != MP_OKAY) {
      return err;
   }

   /* now init the second half of the array */
   for (x = 1<<(winsize-1); x < (1 << winsize); x++) {
      if ((err = mp_init_size(&M[x], P->alloc)) != MP_OKAY) {
         for (y = 1<<(winsize-1); y < x; y++) {
            mp_clear(&M[y]);
         }
         mp_clear(&M[1]);
         return err;
      }
   }

   /* determine and setup reduction code */
   if (redmode == 0) {
      if (MP_HAS(MP_MONTGOMERY_SETUP)) {
         /* now setup montgomery  */
         if ((err = mp_montgomery_setup(P, &mp)) != MP_OKAY)      goto LBL_M;
      } else {
         err = MP_VAL;
         goto LBL_M;
      }

      /* automatically pick the comba one if available (saves quite a few calls/ifs) */
      if (MP_HAS(S_MP_MONTGOMERY_REDUCE_FAST) &&
          (((P->used * 2) + 1) < MP_WARRAY) &&
          (P->used < MP_MAXFAST)) {
         redux = s_mp_montgomery_reduce_fast;
      } else if (MP_HAS(MP_MONTGOMERY_REDUCE)) {
         /* use slower baseline Montgomery method */
         redux = mp_montgomery_reduce;
      } else {
         err = MP_VAL;
         goto LBL_M;
      }
   } else if (redmode == 1) {
      if (MP_HAS(MP_DR_SETUP) && MP_HAS(MP_DR_REDUCE)) {
         /* setup DR reduction for moduli of the form B**k - b */
         mp_dr_setup(P, &mp);
         redux = mp_dr_reduce;
      } else {
         err = MP_VAL;
         goto LBL_M;
      }
   } else if (MP_HAS(MP_REDUCE_2K_SETUP) && MP_HAS(MP_REDUCE_2K)) {
      /* setup DR reduction for moduli of the form 2**k - b */
      if ((err = mp_reduce_2k_setup(P, &mp)) != MP_OKAY)          goto LBL_M;
      redux = mp_reduce_2k;
   } else {
      err = MP_VAL;
      goto LBL_M;
   }

   /* setup result */
   if ((err = mp_init_size(&res, P->alloc)) != MP_OKAY)           goto LBL_M;

   /* create M table
    *

    *
    * The first half of the table is not computed though accept for M[0] and M[1]
    */

   if (redmode == 0) {
      if (MP_HAS(MP_MONTGOMERY_CALC_NORMALIZATION)) {
         /* now we need R mod m */
         if ((err = mp_montgomery_calc_normalization(&res, P)) != MP_OKAY) goto LBL_RES;

         /* now set M[1] to G * R mod m */
         if ((err = mp_mulmod(G, &res, P, &M[1])) != MP_OKAY)     goto LBL_RES;
      } else {
         err = MP_VAL;
         goto LBL_RES;
      }
   } else {
      mp_set(&res, 1uL);
      if ((err = mp_mod(G, P, &M[1])) != MP_OKAY)                 goto LBL_RES;
   }

   /* compute the value at M[1<<(winsize-1)] by squaring M[1] (winsize-1) times */
   if ((err = mp_copy(&M[1], &M[(size_t)1 << (winsize - 1)])) != MP_OKAY) goto LBL_RES;

   for (x = 0; x < (winsize - 1); x++) {
      if ((err = mp_sqr(&M[(size_t)1 << (winsize - 1)], &M[(size_t)1 << (winsize - 1)])) != MP_OKAY) goto LBL_RES;
      if ((err = redux(&M[(size_t)1 << (winsize - 1)], P, mp)) != MP_OKAY) goto LBL_RES;
   }

   /* create upper table */
   for (x = (1 << (winsize - 1)) + 1; x < (1 << winsize); x++) {
      if ((err = mp_mul(&M[x - 1], &M[1], &M[x])) != MP_OKAY)     goto LBL_RES;
      if ((err = redux(&M[x], P, mp)) != MP_OKAY)                 goto LBL_RES;
   }

   /* set initial mode and bit cnt */
   mode   = 0;
   bitcnt = 1;
   buf    = 0;
   digidx = X->used - 1;
   bitcpy = 0;
   bitbuf = 0;

   for (;;) {
      /* grab next digit as required */
      if (--bitcnt == 0) {
         /* if digidx == -1 we are out of digits so break */
         if (digidx == -1) {
            break;
         }
         /* read next digit and reset bitcnt */
         buf    = X->dp[digidx--];
         bitcnt = (int)MP_DIGIT_BIT;
      }

      /* grab the next msb from the exponent */
      y     = (mp_digit)(buf >> (MP_DIGIT_BIT - 1)) & 1uL;
      buf <<= (mp_digit)1;

      /* if the bit is zero and mode == 0 then we ignore it
       * These represent the leading zero bits before the first 1 bit
       * in the exponent.  Technically this opt is not required but it
       * does lower the # of trivial squaring/reductions used
       */
      if ((mode == 0) && (y == 0)) {
         continue;
      }

      /* if the bit is zero and mode == 1 then we square */
      if ((mode == 1) && (y == 0)) {
         if ((err = mp_sqr(&res, &res)) != MP_OKAY)               goto LBL_RES;
         if ((err = redux(&res, P, mp)) != MP_OKAY)               goto LBL_RES;
         continue;
      }

      /* else we add it to the window */
      bitbuf |= (y << (winsize - ++bitcpy));
      mode    = 2;

      if (bitcpy == winsize) {
         /* ok window is filled so square as required and multiply  */
         /* square first */
         for (x = 0; x < winsize; x++) {
            if ((err = mp_sqr(&res, &res)) != MP_OKAY)            goto LBL_RES;
            if ((err = redux(&res, P, mp)) != MP_OKAY)            goto LBL_RES;
         }

         /* then multiply */
         if ((err = mp_mul(&res, &M[bitbuf], &res)) != MP_OKAY)   goto LBL_RES;
         if ((err = redux(&res, P, mp)) != MP_OKAY)               goto LBL_RES;

         /* empty window and reset */
         bitcpy = 0;
         bitbuf = 0;
         mode   = 1;
      }
   }

   /* if bits remain then square/multiply */
   if ((mode == 2) && (bitcpy > 0)) {
      /* square then multiply if the bit is set */
      for (x = 0; x < bitcpy; x++) {
         if ((err = mp_sqr(&res, &res)) != MP_OKAY)               goto LBL_RES;
         if ((err = redux(&res, P, mp)) != MP_OKAY)               goto LBL_RES;

         /* get next bit of the window */
         bitbuf <<= 1;
         if ((bitbuf & (1 << winsize)) != 0) {
            /* then multiply */
            if ((err = mp_mul(&res, &M[1], &res)) != MP_OKAY)     goto LBL_RES;
            if ((err = redux(&res, P, mp)) != MP_OKAY)            goto LBL_RES;
         }
      }
   }

   if (redmode == 0) {
      /* fixup result if Montgomery reduction is used
       * recall that any value in a Montgomery system is
       * actually multiplied by R mod n.  So we have
       * to reduce one more time to cancel out the factor
       * of R.
       */
      if ((err = redux(&res, P, mp)) != MP_OKAY)                  goto LBL_RES;
   }

   /* swap res with Y */
   mp_exch(&res, Y);
   err = MP_OKAY;
LBL_RES:
   mp_clear(&res);
LBL_M:
   mp_clear(&M[1]);
   for (x = 1<<(winsize-1); x < (1 << winsize); x++) {
      mp_clear(&M[x]);
   }
   return err;
}
#endif

/* End: bn_s_mp_exptmod_fast.c */

/* Start: bn_s_mp_get_bit.c */
#include "tommath_private.h"
#ifdef BN_S_MP_GET_BIT_C

/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* Get bit at position b and return MP_YES if the bit is 1, MP_NO if it is 0 */
mp_bool s_mp_get_bit(const mp_int *a, unsigned int b)
{
   mp_digit bit;
   int limb = (int)(b / MP_DIGIT_BIT);

   if (limb >= a->used) {
      return MP_NO;
   }

   bit = (mp_digit)1 << (b % MP_DIGIT_BIT);
   return ((a->dp[limb] & bit) != 0u) ? MP_YES : MP_NO;
}

#endif

/* End: bn_s_mp_get_bit.c */

/* Start: bn_s_mp_invmod_fast.c */
#include "tommath_private.h"
#ifdef BN_S_MP_INVMOD_FAST_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* computes the modular inverse via binary extended euclidean algorithm,
 * that is c = 1/a mod b
 *
 * Based on slow invmod except this is optimized for the case where b is
 * odd as per HAC Note 14.64 on pp. 610
 */
mp_err s_mp_invmod_fast(const mp_int *a, const mp_int *b, mp_int *c)
{
   mp_int  x, y, u, v, B, D;
   mp_sign neg;
   mp_err  err;

   /* 2. [modified] b must be odd   */
   if (MP_IS_EVEN(b)) {
      return MP_VAL;
   }

   /* init all our temps */
   if ((err = mp_init_multi(&x, &y, &u, &v, &B, &D, NULL)) != MP_OKAY) {
      return err;
   }

   /* x == modulus, y == value to invert */
   if ((err = mp_copy(b, &x)) != MP_OKAY)                         goto LBL_ERR;

   /* we need y = |a| */
   if ((err = mp_mod(a, b, &y)) != MP_OKAY)                       goto LBL_ERR;

   /* if one of x,y is zero return an error! */
   if (MP_IS_ZERO(&x) || MP_IS_ZERO(&y)) {
      err = MP_VAL;
      goto LBL_ERR;
   }

   /* 3. u=x, v=y, A=1, B=0, C=0,D=1 */
   if ((err = mp_copy(&x, &u)) != MP_OKAY)                        goto LBL_ERR;
   if ((err = mp_copy(&y, &v)) != MP_OKAY)                        goto LBL_ERR;
   mp_set(&D, 1uL);

top:
   /* 4.  while u is even do */
   while (MP_IS_EVEN(&u)) {
      /* 4.1 u = u/2 */
      if ((err = mp_div_2(&u, &u)) != MP_OKAY)                    goto LBL_ERR;

      /* 4.2 if B is odd then */
      if (MP_IS_ODD(&B)) {
         if ((err = mp_sub(&B, &x, &B)) != MP_OKAY)               goto LBL_ERR;
      }
      /* B = B/2 */
      if ((err = mp_div_2(&B, &B)) != MP_OKAY)                    goto LBL_ERR;
   }

   /* 5.  while v is even do */
   while (MP_IS_EVEN(&v)) {
      /* 5.1 v = v/2 */
      if ((err = mp_div_2(&v, &v)) != MP_OKAY)                    goto LBL_ERR;

      /* 5.2 if D is odd then */
      if (MP_IS_ODD(&D)) {
         /* D = (D-x)/2 */
         if ((err = mp_sub(&D, &x, &D)) != MP_OKAY)               goto LBL_ERR;
      }
      /* D = D/2 */
      if ((err = mp_div_2(&D, &D)) != MP_OKAY)                    goto LBL_ERR;
   }

   /* 6.  if u >= v then */
   if (mp_cmp(&u, &v) != MP_LT) {
      /* u = u - v, B = B - D */
      if ((err = mp_sub(&u, &v, &u)) != MP_OKAY)                  goto LBL_ERR;

      if ((err = mp_sub(&B, &D, &B)) != MP_OKAY)                  goto LBL_ERR;
   } else {
      /* v - v - u, D = D - B */
      if ((err = mp_sub(&v, &u, &v)) != MP_OKAY)                  goto LBL_ERR;

      if ((err = mp_sub(&D, &B, &D)) != MP_OKAY)                  goto LBL_ERR;
   }

   /* if not zero goto step 4 */
   if (!MP_IS_ZERO(&u)) {
      goto top;
   }

   /* now a = C, b = D, gcd == g*v */

   /* if v != 1 then there is no inverse */
   if (mp_cmp_d(&v, 1uL) != MP_EQ) {
      err = MP_VAL;
      goto LBL_ERR;
   }

   /* b is now the inverse */
   neg = a->sign;
   while (D.sign == MP_NEG) {
      if ((err = mp_add(&D, b, &D)) != MP_OKAY)                   goto LBL_ERR;
   }

   /* too big */
   while (mp_cmp_mag(&D, b) != MP_LT) {
      if ((err = mp_sub(&D, b, &D)) != MP_OKAY)                   goto LBL_ERR;
   }

   mp_exch(&D, c);
   c->sign = neg;
   err = MP_OKAY;

LBL_ERR:
   mp_clear_multi(&x, &y, &u, &v, &B, &D, NULL);
   return err;
}
#endif

/* End: bn_s_mp_invmod_fast.c */

/* Start: bn_s_mp_invmod_slow.c */
#include "tommath_private.h"
#ifdef BN_S_MP_INVMOD_SLOW_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* hac 14.61, pp608 */
mp_err s_mp_invmod_slow(const mp_int *a, const mp_int *b, mp_int *c)
{
   mp_int  x, y, u, v, A, B, C, D;
   mp_err  err;

   /* b cannot be negative */
   if ((b->sign == MP_NEG) || MP_IS_ZERO(b)) {
      return MP_VAL;
   }

   /* init temps */
   if ((err = mp_init_multi(&x, &y, &u, &v,
                            &A, &B, &C, &D, NULL)) != MP_OKAY) {
      return err;
   }

   /* x = a, y = b */
   if ((err = mp_mod(a, b, &x)) != MP_OKAY)                       goto LBL_ERR;
   if ((err = mp_copy(b, &y)) != MP_OKAY)                         goto LBL_ERR;

   /* 2. [modified] if x,y are both even then return an error! */
   if (MP_IS_EVEN(&x) && MP_IS_EVEN(&y)) {
      err = MP_VAL;
      goto LBL_ERR;
   }

   /* 3. u=x, v=y, A=1, B=0, C=0,D=1 */
   if ((err = mp_copy(&x, &u)) != MP_OKAY)                        goto LBL_ERR;
   if ((err = mp_copy(&y, &v)) != MP_OKAY)                        goto LBL_ERR;
   mp_set(&A, 1uL);
   mp_set(&D, 1uL);

top:
   /* 4.  while u is even do */
   while (MP_IS_EVEN(&u)) {
      /* 4.1 u = u/2 */
      if ((err = mp_div_2(&u, &u)) != MP_OKAY)                    goto LBL_ERR;

      /* 4.2 if A or B is odd then */
      if (MP_IS_ODD(&A) || MP_IS_ODD(&B)) {
         /* A = (A+y)/2, B = (B-x)/2 */
         if ((err = mp_add(&A, &y, &A)) != MP_OKAY)               goto LBL_ERR;
         if ((err = mp_sub(&B, &x, &B)) != MP_OKAY)               goto LBL_ERR;
      }
      /* A = A/2, B = B/2 */
      if ((err = mp_div_2(&A, &A)) != MP_OKAY)                    goto LBL_ERR;
      if ((err = mp_div_2(&B, &B)) != MP_OKAY)                    goto LBL_ERR;
   }

   /* 5.  while v is even do */
   while (MP_IS_EVEN(&v)) {
      /* 5.1 v = v/2 */
      if ((err = mp_div_2(&v, &v)) != MP_OKAY)                    goto LBL_ERR;

      /* 5.2 if C or D is odd then */
      if (MP_IS_ODD(&C) || MP_IS_ODD(&D)) {
         /* C = (C+y)/2, D = (D-x)/2 */
         if ((err = mp_add(&C, &y, &C)) != MP_OKAY)               goto LBL_ERR;
         if ((err = mp_sub(&D, &x, &D)) != MP_OKAY)               goto LBL_ERR;
      }
      /* C = C/2, D = D/2 */
      if ((err = mp_div_2(&C, &C)) != MP_OKAY)                    goto LBL_ERR;
      if ((err = mp_div_2(&D, &D)) != MP_OKAY)                    goto LBL_ERR;
   }

   /* 6.  if u >= v then */
   if (mp_cmp(&u, &v) != MP_LT) {
      /* u = u - v, A = A - C, B = B - D */
      if ((err = mp_sub(&u, &v, &u)) != MP_OKAY)                  goto LBL_ERR;

      if ((err = mp_sub(&A, &C, &A)) != MP_OKAY)                  goto LBL_ERR;

      if ((err = mp_sub(&B, &D, &B)) != MP_OKAY)                  goto LBL_ERR;
   } else {
      /* v - v - u, C = C - A, D = D - B */
      if ((err = mp_sub(&v, &u, &v)) != MP_OKAY)                  goto LBL_ERR;

      if ((err = mp_sub(&C, &A, &C)) != MP_OKAY)                  goto LBL_ERR;

      if ((err = mp_sub(&D, &B, &D)) != MP_OKAY)                  goto LBL_ERR;
   }

   /* if not zero goto step 4 */
   if (!MP_IS_ZERO(&u)) {
      goto top;
   }

   /* now a = C, b = D, gcd == g*v */

   /* if v != 1 then there is no inverse */
   if (mp_cmp_d(&v, 1uL) != MP_EQ) {
      err = MP_VAL;
      goto LBL_ERR;
   }

   /* if its too low */
   while (mp_cmp_d(&C, 0uL) == MP_LT) {
      if ((err = mp_add(&C, b, &C)) != MP_OKAY)                   goto LBL_ERR;
   }

   /* too big */
   while (mp_cmp_mag(&C, b) != MP_LT) {
      if ((err = mp_sub(&C, b, &C)) != MP_OKAY)                   goto LBL_ERR;
   }

   /* C is now the inverse */
   mp_exch(&C, c);
   err = MP_OKAY;
LBL_ERR:
   mp_clear_multi(&x, &y, &u, &v, &A, &B, &C, &D, NULL);
   return err;
}
#endif

/* End: bn_s_mp_invmod_slow.c */

/* Start: bn_s_mp_karatsuba_mul.c */
#include "tommath_private.h"
#ifdef BN_S_MP_KARATSUBA_MUL_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* c = |a| * |b| using Karatsuba Multiplication using
 * three half size multiplications
 *
 * Let B represent the radix [e.g. 2**MP_DIGIT_BIT] and
 * let n represent half of the number of digits in
 * the min(a,b)
 *
 * a = a1 * B**n + a0
 * b = b1 * B**n + b0
 *
 * Then, a * b =>
   a1b1 * B**2n + ((a1 + a0)(b1 + b0) - (a0b0 + a1b1)) * B + a0b0
 *
 * Note that a1b1 and a0b0 are used twice and only need to be
 * computed once.  So in total three half size (half # of
 * digit) multiplications are performed, a0b0, a1b1 and
 * (a1+b1)(a0+b0)
 *
 * Note that a multiplication of half the digits requires
 * 1/4th the number of single precision multiplications so in
 * total after one call 25% of the single precision multiplications
 * are saved.  Note also that the call to mp_mul can end up back
 * in this function if the a0, a1, b0, or b1 are above the threshold.
 * This is known as divide-and-conquer and leads to the famous
 * O(N**lg(3)) or O(N**1.584) work which is asymptopically lower than
 * the standard O(N**2) that the baseline/comba methods use.
 * Generally though the overhead of this method doesn't pay off
 * until a certain size (N ~ 80) is reached.
 */
mp_err s_mp_karatsuba_mul(const mp_int *a, const mp_int *b, mp_int *c)
{
   mp_int  x0, x1, y0, y1, t1, x0y0, x1y1;
   int     B;
   mp_err  err = MP_MEM; /* default the return code to an error */

   /* min # of digits */
   B = MP_MIN(a->used, b->used);

   /* now divide in two */
   B = B >> 1;

   /* init copy all the temps */
   if (mp_init_size(&x0, B) != MP_OKAY) {
      goto LBL_ERR;
   }
   if (mp_init_size(&x1, a->used - B) != MP_OKAY) {
      goto X0;
   }
   if (mp_init_size(&y0, B) != MP_OKAY) {
      goto X1;
   }
   if (mp_init_size(&y1, b->used - B) != MP_OKAY) {
      goto Y0;
   }

   /* init temps */
   if (mp_init_size(&t1, B * 2) != MP_OKAY) {
      goto Y1;
   }
   if (mp_init_size(&x0y0, B * 2) != MP_OKAY) {
      goto T1;
   }
   if (mp_init_size(&x1y1, B * 2) != MP_OKAY) {
      goto X0Y0;
   }

   /* now shift the digits */
   x0.used = y0.used = B;
   x1.used = a->used - B;
   y1.used = b->used - B;

   {
      int x;
      mp_digit *tmpa, *tmpb, *tmpx, *tmpy;

      /* we copy the digits directly instead of using higher level functions
       * since we also need to shift the digits
       */
      tmpa = a->dp;
      tmpb = b->dp;

      tmpx = x0.dp;
      tmpy = y0.dp;
      for (x = 0; x < B; x++) {
         *tmpx++ = *tmpa++;
         *tmpy++ = *tmpb++;
      }

      tmpx = x1.dp;
      for (x = B; x < a->used; x++) {
         *tmpx++ = *tmpa++;
      }

      tmpy = y1.dp;
      for (x = B; x < b->used; x++) {
         *tmpy++ = *tmpb++;
      }
   }

   /* only need to clamp the lower words since by definition the
    * upper words x1/y1 must have a known number of digits
    */
   mp_clamp(&x0);
   mp_clamp(&y0);

   /* now calc the products x0y0 and x1y1 */
   /* after this x0 is no longer required, free temp [x0==t2]! */
   if (mp_mul(&x0, &y0, &x0y0) != MP_OKAY) {
      goto X1Y1;          /* x0y0 = x0*y0 */
   }
   if (mp_mul(&x1, &y1, &x1y1) != MP_OKAY) {
      goto X1Y1;          /* x1y1 = x1*y1 */
   }

   /* now calc x1+x0 and y1+y0 */
   if (s_mp_add(&x1, &x0, &t1) != MP_OKAY) {
      goto X1Y1;          /* t1 = x1 - x0 */
   }
   if (s_mp_add(&y1, &y0, &x0) != MP_OKAY) {
      goto X1Y1;          /* t2 = y1 - y0 */
   }
   if (mp_mul(&t1, &x0, &t1) != MP_OKAY) {
      goto X1Y1;          /* t1 = (x1 + x0) * (y1 + y0) */
   }

   /* add x0y0 */
   if (mp_add(&x0y0, &x1y1, &x0) != MP_OKAY) {
      goto X1Y1;          /* t2 = x0y0 + x1y1 */
   }
   if (s_mp_sub(&t1, &x0, &t1) != MP_OKAY) {
      goto X1Y1;          /* t1 = (x1+x0)*(y1+y0) - (x1y1 + x0y0) */
   }

   /* shift by B */
   if (mp_lshd(&t1, B) != MP_OKAY) {
      goto X1Y1;          /* t1 = (x0y0 + x1y1 - (x1-x0)*(y1-y0))<<B */
   }
   if (mp_lshd(&x1y1, B * 2) != MP_OKAY) {
      goto X1Y1;          /* x1y1 = x1y1 << 2*B */
   }

   if (mp_add(&x0y0, &t1, &t1) != MP_OKAY) {
      goto X1Y1;          /* t1 = x0y0 + t1 */
   }
   if (mp_add(&t1, &x1y1, c) != MP_OKAY) {
      goto X1Y1;          /* t1 = x0y0 + t1 + x1y1 */
   }

   /* Algorithm succeeded set the return code to MP_OKAY */
   err = MP_OKAY;

X1Y1:
   mp_clear(&x1y1);
X0Y0:
   mp_clear(&x0y0);
T1:
   mp_clear(&t1);
Y1:
   mp_clear(&y1);
Y0:
   mp_clear(&y0);
X1:
   mp_clear(&x1);
X0:
   mp_clear(&x0);
LBL_ERR:
   return err;
}
#endif

/* End: bn_s_mp_karatsuba_mul.c */

/* Start: bn_s_mp_karatsuba_sqr.c */
#include "tommath_private.h"
#ifdef BN_S_MP_KARATSUBA_SQR_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* Karatsuba squaring, computes b = a*a using three
 * half size squarings
 *
 * See comments of karatsuba_mul for details.  It
 * is essentially the same algorithm but merely
 * tuned to perform recursive squarings.
 */
mp_err s_mp_karatsuba_sqr(const mp_int *a, mp_int *b)
{
   mp_int  x0, x1, t1, t2, x0x0, x1x1;
   int     B;
   mp_err  err = MP_MEM;

   /* min # of digits */
   B = a->used;

   /* now divide in two */
   B = B >> 1;

   /* init copy all the temps */
   if (mp_init_size(&x0, B) != MP_OKAY)
      goto LBL_ERR;
   if (mp_init_size(&x1, a->used - B) != MP_OKAY)
      goto X0;

   /* init temps */
   if (mp_init_size(&t1, a->used * 2) != MP_OKAY)
      goto X1;
   if (mp_init_size(&t2, a->used * 2) != MP_OKAY)
      goto T1;
   if (mp_init_size(&x0x0, B * 2) != MP_OKAY)
      goto T2;
   if (mp_init_size(&x1x1, (a->used - B) * 2) != MP_OKAY)
      goto X0X0;

   {
      int x;
      mp_digit *dst, *src;

      src = a->dp;

      /* now shift the digits */
      dst = x0.dp;
      for (x = 0; x < B; x++) {
         *dst++ = *src++;
      }

      dst = x1.dp;
      for (x = B; x < a->used; x++) {
         *dst++ = *src++;
      }
   }

   x0.used = B;
   x1.used = a->used - B;

   mp_clamp(&x0);

   /* now calc the products x0*x0 and x1*x1 */
   if (mp_sqr(&x0, &x0x0) != MP_OKAY)
      goto X1X1;           /* x0x0 = x0*x0 */
   if (mp_sqr(&x1, &x1x1) != MP_OKAY)
      goto X1X1;           /* x1x1 = x1*x1 */

   /* now calc (x1+x0)**2 */
   if (s_mp_add(&x1, &x0, &t1) != MP_OKAY)
      goto X1X1;           /* t1 = x1 - x0 */
   if (mp_sqr(&t1, &t1) != MP_OKAY)
      goto X1X1;           /* t1 = (x1 - x0) * (x1 - x0) */

   /* add x0y0 */
   if (s_mp_add(&x0x0, &x1x1, &t2) != MP_OKAY)
      goto X1X1;           /* t2 = x0x0 + x1x1 */
   if (s_mp_sub(&t1, &t2, &t1) != MP_OKAY)
      goto X1X1;           /* t1 = (x1+x0)**2 - (x0x0 + x1x1) */

   /* shift by B */
   if (mp_lshd(&t1, B) != MP_OKAY)
      goto X1X1;           /* t1 = (x0x0 + x1x1 - (x1-x0)*(x1-x0))<<B */
   if (mp_lshd(&x1x1, B * 2) != MP_OKAY)
      goto X1X1;           /* x1x1 = x1x1 << 2*B */

   if (mp_add(&x0x0, &t1, &t1) != MP_OKAY)
      goto X1X1;           /* t1 = x0x0 + t1 */
   if (mp_add(&t1, &x1x1, b) != MP_OKAY)
      goto X1X1;           /* t1 = x0x0 + t1 + x1x1 */

   err = MP_OKAY;

X1X1:
   mp_clear(&x1x1);
X0X0:
   mp_clear(&x0x0);
T2:
   mp_clear(&t2);
T1:
   mp_clear(&t1);
X1:
   mp_clear(&x1);
X0:
   mp_clear(&x0);
LBL_ERR:
   return err;
}
#endif

/* End: bn_s_mp_karatsuba_sqr.c */

/* Start: bn_s_mp_montgomery_reduce_fast.c */
#include "tommath_private.h"
#ifdef BN_S_MP_MONTGOMERY_REDUCE_FAST_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* computes xR**-1 == x (mod N) via Montgomery Reduction
 *
 * This is an optimized implementation of montgomery_reduce
 * which uses the comba method to quickly calculate the columns of the
 * reduction.
 *
 * Based on Algorithm 14.32 on pp.601 of HAC.
*/
mp_err s_mp_montgomery_reduce_fast(mp_int *x, const mp_int *n, mp_digit rho)
{
   int     ix, olduse;
   mp_err  err;
   mp_word W[MP_WARRAY];

   if (x->used > MP_WARRAY) {
      return MP_VAL;
   }

   /* get old used count */
   olduse = x->used;

   /* grow a as required */
   if (x->alloc < (n->used + 1)) {
      if ((err = mp_grow(x, n->used + 1)) != MP_OKAY) {
         return err;
      }
   }

   /* first we have to get the digits of the input into
    * an array of double precision words W[...]
    */
   {
      mp_word *_W;
      mp_digit *tmpx;

      /* alias for the W[] array */
      _W   = W;

      /* alias for the digits of  x*/
      tmpx = x->dp;

      /* copy the digits of a into W[0..a->used-1] */
      for (ix = 0; ix < x->used; ix++) {
         *_W++ = *tmpx++;
      }

      /* zero the high words of W[a->used..m->used*2] */
      if (ix < ((n->used * 2) + 1)) {
         MP_ZERO_BUFFER(_W, sizeof(mp_word) * (size_t)(((n->used * 2) + 1) - ix));
      }
   }

   /* now we proceed to zero successive digits
    * from the least significant upwards
    */
   for (ix = 0; ix < n->used; ix++) {
      /* mu = ai * m' mod b
       *
       * We avoid a double precision multiplication (which isn't required)
       * by casting the value down to a mp_digit.  Note this requires
       * that W[ix-1] have  the carry cleared (see after the inner loop)
       */
      mp_digit mu;
      mu = ((W[ix] & MP_MASK) * rho) & MP_MASK;

      /* a = a + mu * m * b**i
       *
       * This is computed in place and on the fly.  The multiplication
       * by b**i is handled by offseting which columns the results
       * are added to.
       *
       * Note the comba method normally doesn't handle carries in the
       * inner loop In this case we fix the carry from the previous
       * column since the Montgomery reduction requires digits of the
       * result (so far) [see above] to work.  This is
       * handled by fixing up one carry after the inner loop.  The
       * carry fixups are done in order so after these loops the
       * first m->used words of W[] have the carries fixed
       */
      {
         int iy;
         mp_digit *tmpn;
         mp_word *_W;

         /* alias for the digits of the modulus */
         tmpn = n->dp;

         /* Alias for the columns set by an offset of ix */
         _W = W + ix;

         /* inner loop */
         for (iy = 0; iy < n->used; iy++) {
            *_W++ += (mp_word)mu * (mp_word)*tmpn++;
         }
      }

      /* now fix carry for next digit, W[ix+1] */
      W[ix + 1] += W[ix] >> (mp_word)MP_DIGIT_BIT;
   }

   /* now we have to propagate the carries and
    * shift the words downward [all those least
    * significant digits we zeroed].
    */
   {
      mp_digit *tmpx;
      mp_word *_W, *_W1;

      /* nox fix rest of carries */

      /* alias for current word */
      _W1 = W + ix;

      /* alias for next word, where the carry goes */
      _W = W + ++ix;

      for (; ix < ((n->used * 2) + 1); ix++) {
         *_W++ += *_W1++ >> (mp_word)MP_DIGIT_BIT;
      }

      /* copy out, A = A/b**n
       *
       * The result is A/b**n but instead of converting from an
       * array of mp_word to mp_digit than calling mp_rshd
       * we just copy them in the right order
       */

      /* alias for destination word */
      tmpx = x->dp;

      /* alias for shifted double precision result */
      _W = W + n->used;

      for (ix = 0; ix < (n->used + 1); ix++) {
         *tmpx++ = *_W++ & (mp_word)MP_MASK;
      }

      /* zero oldused digits, if the input a was larger than
       * m->used+1 we'll have to clear the digits
       */
      MP_ZERO_DIGITS(tmpx, olduse - ix);
   }

   /* set the max used and clamp */
   x->used = n->used + 1;
   mp_clamp(x);

   /* if A >= m then A = A - m */
   if (mp_cmp_mag(x, n) != MP_LT) {
      return s_mp_sub(x, n, x);
   }
   return MP_OKAY;
}
#endif

/* End: bn_s_mp_montgomery_reduce_fast.c */

/* Start: bn_s_mp_mul_digs.c */
#include "tommath_private.h"
#ifdef BN_S_MP_MUL_DIGS_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* multiplies |a| * |b| and only computes upto digs digits of result
 * HAC pp. 595, Algorithm 14.12  Modified so you can control how
 * many digits of output are created.
 */
mp_err s_mp_mul_digs(const mp_int *a, const mp_int *b, mp_int *c, int digs)
{
   mp_int  t;
   mp_err  err;
   int     pa, pb, ix, iy;
   mp_digit u;
   mp_word r;
   mp_digit tmpx, *tmpt, *tmpy;

   /* can we use the fast multiplier? */
   if ((digs < MP_WARRAY) &&
       (MP_MIN(a->used, b->used) < MP_MAXFAST)) {
      return s_mp_mul_digs_fast(a, b, c, digs);
   }

   if ((err = mp_init_size(&t, digs)) != MP_OKAY) {
      return err;
   }
   t.used = digs;

   /* compute the digits of the product directly */
   pa = a->used;
   for (ix = 0; ix < pa; ix++) {
      /* set the carry to zero */
      u = 0;

      /* limit ourselves to making digs digits of output */
      pb = MP_MIN(b->used, digs - ix);

      /* setup some aliases */
      /* copy of the digit from a used within the nested loop */
      tmpx = a->dp[ix];

      /* an alias for the destination shifted ix places */
      tmpt = t.dp + ix;

      /* an alias for the digits of b */
      tmpy = b->dp;

      /* compute the columns of the output and propagate the carry */
      for (iy = 0; iy < pb; iy++) {
         /* compute the column as a mp_word */
         r       = (mp_word)*tmpt +
                   ((mp_word)tmpx * (mp_word)*tmpy++) +
                   (mp_word)u;

         /* the new column is the lower part of the result */
         *tmpt++ = (mp_digit)(r & (mp_word)MP_MASK);

         /* get the carry word from the result */
         u       = (mp_digit)(r >> (mp_word)MP_DIGIT_BIT);
      }
      /* set carry if it is placed below digs */
      if ((ix + iy) < digs) {
         *tmpt = u;
      }
   }

   mp_clamp(&t);
   mp_exch(&t, c);

   mp_clear(&t);
   return MP_OKAY;
}
#endif

/* End: bn_s_mp_mul_digs.c */

/* Start: bn_s_mp_mul_digs_fast.c */
#include "tommath_private.h"
#ifdef BN_S_MP_MUL_DIGS_FAST_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* Fast (comba) multiplier
 *
 * This is the fast column-array [comba] multiplier.  It is
 * designed to compute the columns of the product first
 * then handle the carries afterwards.  This has the effect
 * of making the nested loops that compute the columns very
 * simple and schedulable on super-scalar processors.
 *
 * This has been modified to produce a variable number of
 * digits of output so if say only a half-product is required
 * you don't have to compute the upper half (a feature
 * required for fast Barrett reduction).
 *
 * Based on Algorithm 14.12 on pp.595 of HAC.
 *
 */
mp_err s_mp_mul_digs_fast(const mp_int *a, const mp_int *b, mp_int *c, int digs)
{
   int      olduse, pa, ix, iz;
   mp_err   err;
   mp_digit W[MP_WARRAY];
   mp_word  _W;

   /* grow the destination as required */
   if (c->alloc < digs) {
      if ((err = mp_grow(c, digs)) != MP_OKAY) {
         return err;
      }
   }

   /* number of output digits to produce */
   pa = MP_MIN(digs, a->used + b->used);

   /* clear the carry */
   _W = 0;
   for (ix = 0; ix < pa; ix++) {
      int      tx, ty;
      int      iy;
      mp_digit *tmpx, *tmpy;

      /* get offsets into the two bignums */
      ty = MP_MIN(b->used-1, ix);
      tx = ix - ty;

      /* setup temp aliases */
      tmpx = a->dp + tx;
      tmpy = b->dp + ty;

      /* this is the number of times the loop will iterrate, essentially
         while (tx++ < a->used && ty-- >= 0) { ... }
       */
      iy = MP_MIN(a->used-tx, ty+1);

      /* execute loop */
      for (iz = 0; iz < iy; ++iz) {
         _W += (mp_word)*tmpx++ * (mp_word)*tmpy--;

      }

      /* store term */
      W[ix] = (mp_digit)_W & MP_MASK;

      /* make next carry */
      _W = _W >> (mp_word)MP_DIGIT_BIT;
   }

   /* setup dest */
   olduse  = c->used;
   c->used = pa;

   {
      mp_digit *tmpc;
      tmpc = c->dp;
      for (ix = 0; ix < pa; ix++) {
         /* now extract the previous digit [below the carry] */
         *tmpc++ = W[ix];
      }

      /* clear unused digits [that existed in the old copy of c] */
      MP_ZERO_DIGITS(tmpc, olduse - ix);
   }
   mp_clamp(c);
   return MP_OKAY;
}
#endif

/* End: bn_s_mp_mul_digs_fast.c */

/* Start: bn_s_mp_mul_high_digs.c */
#include "tommath_private.h"
#ifdef BN_S_MP_MUL_HIGH_DIGS_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* multiplies |a| * |b| and does not compute the lower digs digits
 * [meant to get the higher part of the product]
 */
mp_err s_mp_mul_high_digs(const mp_int *a, const mp_int *b, mp_int *c, int digs)
{
   mp_int   t;
   int      pa, pb, ix, iy;
   mp_err   err;
   mp_digit u;
   mp_word  r;
   mp_digit tmpx, *tmpt, *tmpy;

   /* can we use the fast multiplier? */
   if (MP_HAS(S_MP_MUL_HIGH_DIGS_FAST)
       && ((a->used + b->used + 1) < MP_WARRAY)
       && (MP_MIN(a->used, b->used) < MP_MAXFAST)) {
      return s_mp_mul_high_digs_fast(a, b, c, digs);
   }

   if ((err = mp_init_size(&t, a->used + b->used + 1)) != MP_OKAY) {
      return err;
   }
   t.used = a->used + b->used + 1;

   pa = a->used;
   pb = b->used;
   for (ix = 0; ix < pa; ix++) {
      /* clear the carry */
      u = 0;

      /* left hand side of A[ix] * B[iy] */
      tmpx = a->dp[ix];

      /* alias to the address of where the digits will be stored */
      tmpt = &(t.dp[digs]);

      /* alias for where to read the right hand side from */
      tmpy = b->dp + (digs - ix);

      for (iy = digs - ix; iy < pb; iy++) {
         /* calculate the double precision result */
         r       = (mp_word)*tmpt +
                   ((mp_word)tmpx * (mp_word)*tmpy++) +
                   (mp_word)u;

         /* get the lower part */
         *tmpt++ = (mp_digit)(r & (mp_word)MP_MASK);

         /* carry the carry */
         u       = (mp_digit)(r >> (mp_word)MP_DIGIT_BIT);
      }
      *tmpt = u;
   }
   mp_clamp(&t);
   mp_exch(&t, c);
   mp_clear(&t);
   return MP_OKAY;
}
#endif

/* End: bn_s_mp_mul_high_digs.c */

/* Start: bn_s_mp_mul_high_digs_fast.c */
#include "tommath_private.h"
#ifdef BN_S_MP_MUL_HIGH_DIGS_FAST_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* this is a modified version of fast_s_mul_digs that only produces
 * output digits *above* digs.  See the comments for fast_s_mul_digs
 * to see how it works.
 *
 * This is used in the Barrett reduction since for one of the multiplications
 * only the higher digits were needed.  This essentially halves the work.
 *
 * Based on Algorithm 14.12 on pp.595 of HAC.
 */
mp_err s_mp_mul_high_digs_fast(const mp_int *a, const mp_int *b, mp_int *c, int digs)
{
   int     olduse, pa, ix, iz;
   mp_err   err;
   mp_digit W[MP_WARRAY];
   mp_word  _W;

   /* grow the destination as required */
   pa = a->used + b->used;
   if (c->alloc < pa) {
      if ((err = mp_grow(c, pa)) != MP_OKAY) {
         return err;
      }
   }

   /* number of output digits to produce */
   pa = a->used + b->used;
   _W = 0;
   for (ix = digs; ix < pa; ix++) {
      int      tx, ty, iy;
      mp_digit *tmpx, *tmpy;

      /* get offsets into the two bignums */
      ty = MP_MIN(b->used-1, ix);
      tx = ix - ty;

      /* setup temp aliases */
      tmpx = a->dp + tx;
      tmpy = b->dp + ty;

      /* this is the number of times the loop will iterrate, essentially its
         while (tx++ < a->used && ty-- >= 0) { ... }
       */
      iy = MP_MIN(a->used-tx, ty+1);

      /* execute loop */
      for (iz = 0; iz < iy; iz++) {
         _W += (mp_word)*tmpx++ * (mp_word)*tmpy--;
      }

      /* store term */
      W[ix] = (mp_digit)_W & MP_MASK;

      /* make next carry */
      _W = _W >> (mp_word)MP_DIGIT_BIT;
   }

   /* setup dest */
   olduse  = c->used;
   c->used = pa;

   {
      mp_digit *tmpc;

      tmpc = c->dp + digs;
      for (ix = digs; ix < pa; ix++) {
         /* now extract the previous digit [below the carry] */
         *tmpc++ = W[ix];
      }

      /* clear unused digits [that existed in the old copy of c] */
      MP_ZERO_DIGITS(tmpc, olduse - ix);
   }
   mp_clamp(c);
   return MP_OKAY;
}
#endif

/* End: bn_s_mp_mul_high_digs_fast.c */

/* Start: bn_s_mp_prime_is_divisible.c */
#include "tommath_private.h"
#ifdef BN_S_MP_PRIME_IS_DIVISIBLE_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* determines if an integers is divisible by one
 * of the first PRIME_SIZE primes or not
 *
 * sets result to 0 if not, 1 if yes
 */
mp_err s_mp_prime_is_divisible(const mp_int *a, mp_bool *result)
{
   int      ix;
   mp_err   err;
   mp_digit res;

   /* default to not */
   *result = MP_NO;

   for (ix = 0; ix < PRIVATE_MP_PRIME_TAB_SIZE; ix++) {
      /* what is a mod LBL_prime_tab[ix] */
      if ((err = mp_mod_d(a, s_mp_prime_tab[ix], &res)) != MP_OKAY) {
         return err;
      }

      /* is the residue zero? */
      if (res == 0u) {
         *result = MP_YES;
         return MP_OKAY;
      }
   }

   return MP_OKAY;
}
#endif

/* End: bn_s_mp_prime_is_divisible.c */

/* Start: bn_s_mp_rand_jenkins.c */
#include "tommath_private.h"
#ifdef BN_S_MP_RAND_JENKINS_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* Bob Jenkins' http://burtleburtle.net/bob/rand/smallprng.html */
/* Chosen for speed and a good "mix" */
typedef struct {
   uint64_t a;
   uint64_t b;
   uint64_t c;
   uint64_t d;
} ranctx;

static ranctx jenkins_x;

#define rot(x,k) (((x)<<(k))|((x)>>(64-(k))))
static uint64_t s_rand_jenkins_val(void)
{
   uint64_t e = jenkins_x.a - rot(jenkins_x.b, 7);
   jenkins_x.a = jenkins_x.b ^ rot(jenkins_x.c, 13);
   jenkins_x.b = jenkins_x.c + rot(jenkins_x.d, 37);
   jenkins_x.c = jenkins_x.d + e;
   jenkins_x.d = e + jenkins_x.a;
   return jenkins_x.d;
}

void s_mp_rand_jenkins_init(uint64_t seed)
{
   uint64_t i;
   jenkins_x.a = 0xf1ea5eedULL;
   jenkins_x.b = jenkins_x.c = jenkins_x.d = seed;
   for (i = 0uLL; i < 20uLL; ++i) {
      (void)s_rand_jenkins_val();
   }
}

mp_err s_mp_rand_jenkins(void *p, size_t n)
{
   char *q = (char *)p;
   while (n > 0u) {
      int i;
      uint64_t x = s_rand_jenkins_val();
      for (i = 0; (i < 8) && (n > 0u); ++i, --n) {
         *q++ = (char)(x & 0xFFuLL);
         x >>= 8;
      }
   }
   return MP_OKAY;
}

#endif

/* End: bn_s_mp_rand_jenkins.c */

/* Start: bn_s_mp_rand_platform.c */
#include "tommath_private.h"
#ifdef BN_S_MP_RAND_PLATFORM_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* First the OS-specific special cases
 * - *BSD
 * - Windows
 */
#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || defined(__DragonFly__)
#define BN_S_READ_ARC4RANDOM_C
static mp_err s_read_arc4random(void *p, size_t n)
{
   arc4random_buf(p, n);
   return MP_OKAY;
}
#endif

#if defined(_WIN32) || defined(_WIN32_WCE)
#define BN_S_READ_WINCSP_C

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0400
#endif
#ifdef _WIN32_WCE
#define UNDER_CE
#define ARM
#endif

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>

static mp_err s_read_wincsp(void *p, size_t n)
{
   static HCRYPTPROV hProv = 0;
   if (hProv == 0) {
      HCRYPTPROV h = 0;
      if (!CryptAcquireContext(&h, NULL, MS_DEF_PROV, PROV_RSA_FULL,
                               (CRYPT_VERIFYCONTEXT | CRYPT_MACHINE_KEYSET)) &&
          !CryptAcquireContext(&h, NULL, MS_DEF_PROV, PROV_RSA_FULL,
                               CRYPT_VERIFYCONTEXT | CRYPT_MACHINE_KEYSET | CRYPT_NEWKEYSET)) {
         return MP_ERR;
      }
      hProv = h;
   }
   return CryptGenRandom(hProv, (DWORD)n, (BYTE *)p) == TRUE ? MP_OKAY : MP_ERR;
}
#endif /* WIN32 */

#if !defined(BN_S_READ_WINCSP_C) && defined(__linux__) && defined(__GLIBC_PREREQ)
#if __GLIBC_PREREQ(2, 25)
#define BN_S_READ_GETRANDOM_C
#include <sys/random.h>
#include <errno.h>

static mp_err s_read_getrandom(void *p, size_t n)
{
   char *q = (char *)p;
   while (n > 0u) {
      ssize_t ret = getrandom(q, n, 0);
      if (ret < 0) {
         if (errno == EINTR) {
            continue;
         }
         return MP_ERR;
      }
      q += ret;
      n -= (size_t)ret;
   }
   return MP_OKAY;
}
#endif
#endif

/* We assume all platforms besides windows provide "/dev/urandom".
 * In case yours doesn't, define MP_NO_DEV_URANDOM at compile-time.
 */
#if !defined(BN_S_READ_WINCSP_C) && !defined(MP_NO_DEV_URANDOM)
#define BN_S_READ_URANDOM_C
#ifndef MP_DEV_URANDOM
#define MP_DEV_URANDOM "/dev/urandom"
#endif
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>

static mp_err s_read_urandom(void *p, size_t n)
{
   int fd;
   char *q = (char *)p;

   do {
      fd = open(MP_DEV_URANDOM, O_RDONLY);
   } while ((fd == -1) && (errno == EINTR));
   if (fd == -1) return MP_ERR;

   while (n > 0u) {
      ssize_t ret = read(fd, p, n);
      if (ret < 0) {
         if (errno == EINTR) {
            continue;
         }
         close(fd);
         return MP_ERR;
      }
      q += ret;
      n -= (size_t)ret;
   }

   close(fd);
   return MP_OKAY;
}
#endif

#if defined(MP_PRNG_ENABLE_LTM_RNG)
#define BN_S_READ_LTM_RNG
unsigned long (*ltm_rng)(unsigned char *out, unsigned long outlen, void (*callback)(void));
void (*ltm_rng_callback)(void);

static mp_err s_read_ltm_rng(void *p, size_t n)
{
   unsigned long res;
   if (ltm_rng == NULL) return MP_ERR;
   res = ltm_rng(p, n, ltm_rng_callback);
   if (res != n) return MP_ERR;
   return MP_OKAY;
}
#endif

mp_err s_read_arc4random(void *p, size_t n);
mp_err s_read_wincsp(void *p, size_t n);
mp_err s_read_getrandom(void *p, size_t n);
mp_err s_read_urandom(void *p, size_t n);
mp_err s_read_ltm_rng(void *p, size_t n);

mp_err s_mp_rand_platform(void *p, size_t n)
{
   mp_err err = MP_ERR;
   if ((err != MP_OKAY) && MP_HAS(S_READ_ARC4RANDOM)) err = s_read_arc4random(p, n);
   if ((err != MP_OKAY) && MP_HAS(S_READ_WINCSP))     err = s_read_wincsp(p, n);
   if ((err != MP_OKAY) && MP_HAS(S_READ_GETRANDOM))  err = s_read_getrandom(p, n);
   if ((err != MP_OKAY) && MP_HAS(S_READ_URANDOM))    err = s_read_urandom(p, n);
   if ((err != MP_OKAY) && MP_HAS(S_READ_LTM_RNG))    err = s_read_ltm_rng(p, n);
   return err;
}

#endif

/* End: bn_s_mp_rand_platform.c */

/* Start: bn_s_mp_reverse.c */
#include "tommath_private.h"
#ifdef BN_S_MP_REVERSE_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* reverse an array, used for radix code */
void s_mp_reverse(unsigned char *s, size_t len)
{
   size_t   ix, iy;
   unsigned char t;

   ix = 0u;
   iy = len - 1u;
   while (ix < iy) {
      t     = s[ix];
      s[ix] = s[iy];
      s[iy] = t;
      ++ix;
      --iy;
   }
}
#endif

/* End: bn_s_mp_reverse.c */

/* Start: bn_s_mp_sqr.c */
#include "tommath_private.h"
#ifdef BN_S_MP_SQR_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* low level squaring, b = a*a, HAC pp.596-597, Algorithm 14.16 */
mp_err s_mp_sqr(const mp_int *a, mp_int *b)
{
   mp_int   t;
   int      ix, iy, pa;
   mp_err   err;
   mp_word  r;
   mp_digit u, tmpx, *tmpt;

   pa = a->used;
   if ((err = mp_init_size(&t, (2 * pa) + 1)) != MP_OKAY) {
      return err;
   }

   /* default used is maximum possible size */
   t.used = (2 * pa) + 1;

   for (ix = 0; ix < pa; ix++) {
      /* first calculate the digit at 2*ix */
      /* calculate double precision result */
      r = (mp_word)t.dp[2*ix] +
          ((mp_word)a->dp[ix] * (mp_word)a->dp[ix]);

      /* store lower part in result */
      t.dp[ix+ix] = (mp_digit)(r & (mp_word)MP_MASK);

      /* get the carry */
      u           = (mp_digit)(r >> (mp_word)MP_DIGIT_BIT);

      /* left hand side of A[ix] * A[iy] */
      tmpx        = a->dp[ix];

      /* alias for where to store the results */
      tmpt        = t.dp + ((2 * ix) + 1);

      for (iy = ix + 1; iy < pa; iy++) {
         /* first calculate the product */
         r       = (mp_word)tmpx * (mp_word)a->dp[iy];

         /* now calculate the double precision result, note we use
          * addition instead of *2 since it's easier to optimize
          */
         r       = (mp_word)*tmpt + r + r + (mp_word)u;

         /* store lower part */
         *tmpt++ = (mp_digit)(r & (mp_word)MP_MASK);

         /* get carry */
         u       = (mp_digit)(r >> (mp_word)MP_DIGIT_BIT);
      }
      /* propagate upwards */
      while (u != 0uL) {
         r       = (mp_word)*tmpt + (mp_word)u;
         *tmpt++ = (mp_digit)(r & (mp_word)MP_MASK);
         u       = (mp_digit)(r >> (mp_word)MP_DIGIT_BIT);
      }
   }

   mp_clamp(&t);
   mp_exch(&t, b);
   mp_clear(&t);
   return MP_OKAY;
}
#endif

/* End: bn_s_mp_sqr.c */

/* Start: bn_s_mp_sqr_fast.c */
#include "tommath_private.h"
#ifdef BN_S_MP_SQR_FAST_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* the jist of squaring...
 * you do like mult except the offset of the tmpx [one that
 * starts closer to zero] can't equal the offset of tmpy.
 * So basically you set up iy like before then you min it with
 * (ty-tx) so that it never happens.  You double all those
 * you add in the inner loop

After that loop you do the squares and add them in.
*/

mp_err s_mp_sqr_fast(const mp_int *a, mp_int *b)
{
   int       olduse, pa, ix, iz;
   mp_digit  W[MP_WARRAY], *tmpx;
   mp_word   W1;
   mp_err    err;

   /* grow the destination as required */
   pa = a->used + a->used;
   if (b->alloc < pa) {
      if ((err = mp_grow(b, pa)) != MP_OKAY) {
         return err;
      }
   }

   /* number of output digits to produce */
   W1 = 0;
   for (ix = 0; ix < pa; ix++) {
      int      tx, ty, iy;
      mp_word  _W;
      mp_digit *tmpy;

      /* clear counter */
      _W = 0;

      /* get offsets into the two bignums */
      ty = MP_MIN(a->used-1, ix);
      tx = ix - ty;

      /* setup temp aliases */
      tmpx = a->dp + tx;
      tmpy = a->dp + ty;

      /* this is the number of times the loop will iterrate, essentially
         while (tx++ < a->used && ty-- >= 0) { ... }
       */
      iy = MP_MIN(a->used-tx, ty+1);

      /* now for squaring tx can never equal ty
       * we halve the distance since they approach at a rate of 2x
       * and we have to round because odd cases need to be executed
       */
      iy = MP_MIN(iy, ((ty-tx)+1)>>1);

      /* execute loop */
      for (iz = 0; iz < iy; iz++) {
         _W += (mp_word)*tmpx++ * (mp_word)*tmpy--;
      }

      /* double the inner product and add carry */
      _W = _W + _W + W1;

      /* even columns have the square term in them */
      if (((unsigned)ix & 1u) == 0u) {
         _W += (mp_word)a->dp[ix>>1] * (mp_word)a->dp[ix>>1];
      }

      /* store it */
      W[ix] = (mp_digit)_W & MP_MASK;

      /* make next carry */
      W1 = _W >> (mp_word)MP_DIGIT_BIT;
   }

   /* setup dest */
   olduse  = b->used;
   b->used = a->used+a->used;

   {
      mp_digit *tmpb;
      tmpb = b->dp;
      for (ix = 0; ix < pa; ix++) {
         *tmpb++ = W[ix] & MP_MASK;
      }

      /* clear unused digits [that existed in the old copy of c] */
      MP_ZERO_DIGITS(tmpb, olduse - ix);
   }
   mp_clamp(b);
   return MP_OKAY;
}
#endif

/* End: bn_s_mp_sqr_fast.c */

/* Start: bn_s_mp_sub.c */
#include "tommath_private.h"
#ifdef BN_S_MP_SUB_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* low level subtraction (assumes |a| > |b|), HAC pp.595 Algorithm 14.9 */
mp_err s_mp_sub(const mp_int *a, const mp_int *b, mp_int *c)
{
   int    olduse, min, max;
   mp_err err;

   /* find sizes */
   min = b->used;
   max = a->used;

   /* init result */
   if (c->alloc < max) {
      if ((err = mp_grow(c, max)) != MP_OKAY) {
         return err;
      }
   }
   olduse = c->used;
   c->used = max;

   {
      mp_digit u, *tmpa, *tmpb, *tmpc;
      int i;

      /* alias for digit pointers */
      tmpa = a->dp;
      tmpb = b->dp;
      tmpc = c->dp;

      /* set carry to zero */
      u = 0;
      for (i = 0; i < min; i++) {
         /* T[i] = A[i] - B[i] - U */
         *tmpc = (*tmpa++ - *tmpb++) - u;

         /* U = carry bit of T[i]
          * Note this saves performing an AND operation since
          * if a carry does occur it will propagate all the way to the
          * MSB.  As a result a single shift is enough to get the carry
          */
         u = *tmpc >> (MP_SIZEOF_BITS(mp_digit) - 1u);

         /* Clear carry from T[i] */
         *tmpc++ &= MP_MASK;
      }

      /* now copy higher words if any, e.g. if A has more digits than B  */
      for (; i < max; i++) {
         /* T[i] = A[i] - U */
         *tmpc = *tmpa++ - u;

         /* U = carry bit of T[i] */
         u = *tmpc >> (MP_SIZEOF_BITS(mp_digit) - 1u);

         /* Clear carry from T[i] */
         *tmpc++ &= MP_MASK;
      }

      /* clear digits above used (since we may not have grown result above) */
      MP_ZERO_DIGITS(tmpc, olduse - c->used);
   }

   mp_clamp(c);
   return MP_OKAY;
}

#endif

/* End: bn_s_mp_sub.c */

/* Start: bn_s_mp_toom_mul.c */
#include "tommath_private.h"
#ifdef BN_S_MP_TOOM_MUL_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* multiplication using the Toom-Cook 3-way algorithm
 *
 * Much more complicated than Karatsuba but has a lower
 * asymptotic running time of O(N**1.464).  This algorithm is
 * only particularly useful on VERY large inputs
 * (we're talking 1000s of digits here...).
*/

/*
   This file contains code from J. Arndt's book  "Matters Computational"
   and the accompanying FXT-library with permission of the author.
*/

/*
   Setup from

     Chung, Jaewook, and M. Anwar Hasan. "Asymmetric squaring formulae."
     18th IEEE Symposium on Computer Arithmetic (ARITH'07). IEEE, 2007.

   The interpolation from above needed one temporary variable more
   than the interpolation here:

     Bodrato, Marco, and Alberto Zanoni. "What about Toom-Cook matrices optimality."
     Centro Vito Volterra Universita di Roma Tor Vergata (2006)
*/

mp_err s_mp_toom_mul(const mp_int *a, const mp_int *b, mp_int *c)
{
   mp_int S1, S2, T1, a0, a1, a2, b0, b1, b2;
   int B, count;
   mp_err err;

   /* init temps */
   if ((err = mp_init_multi(&S1, &S2, &T1, NULL)) != MP_OKAY) {
      return err;
   }

   /* B */
   B = MP_MIN(a->used, b->used) / 3;

   /** a = a2 * x^2 + a1 * x + a0; */
   if ((err = mp_init_size(&a0, B)) != MP_OKAY)                   goto LBL_ERRa0;

   for (count = 0; count < B; count++) {
      a0.dp[count] = a->dp[count];
      a0.used++;
   }
   mp_clamp(&a0);
   if ((err = mp_init_size(&a1, B)) != MP_OKAY)                   goto LBL_ERRa1;
   for (; count < (2 * B); count++) {
      a1.dp[count - B] = a->dp[count];
      a1.used++;
   }
   mp_clamp(&a1);
   if ((err = mp_init_size(&a2, B + (a->used - (3 * B)))) != MP_OKAY) goto LBL_ERRa2;
   for (; count < a->used; count++) {
      a2.dp[count - (2 * B)] = a->dp[count];
      a2.used++;
   }
   mp_clamp(&a2);

   /** b = b2 * x^2 + b1 * x + b0; */
   if ((err = mp_init_size(&b0, B)) != MP_OKAY)                   goto LBL_ERRb0;
   for (count = 0; count < B; count++) {
      b0.dp[count] = b->dp[count];
      b0.used++;
   }
   mp_clamp(&b0);
   if ((err = mp_init_size(&b1, B)) != MP_OKAY)                   goto LBL_ERRb1;
   for (; count < (2 * B); count++) {
      b1.dp[count - B] = b->dp[count];
      b1.used++;
   }
   mp_clamp(&b1);
   if ((err = mp_init_size(&b2, B + (b->used - (3 * B)))) != MP_OKAY) goto LBL_ERRb2;
   for (; count < b->used; count++) {
      b2.dp[count - (2 * B)] = b->dp[count];
      b2.used++;
   }
   mp_clamp(&b2);

   /** \\ S1 = (a2+a1+a0) * (b2+b1+b0); */
   /** T1 = a2 + a1; */
   if ((err = mp_add(&a2, &a1, &T1)) != MP_OKAY)                  goto LBL_ERR;

   /** S2 = T1 + a0; */
   if ((err = mp_add(&T1, &a0, &S2)) != MP_OKAY)                  goto LBL_ERR;

   /** c = b2 + b1; */
   if ((err = mp_add(&b2, &b1, c)) != MP_OKAY)                    goto LBL_ERR;

   /** S1 = c + b0; */
   if ((err = mp_add(c, &b0, &S1)) != MP_OKAY)                    goto LBL_ERR;

   /** S1 = S1 * S2; */
   if ((err = mp_mul(&S1, &S2, &S1)) != MP_OKAY)                  goto LBL_ERR;

   /** \\S2 = (4*a2+2*a1+a0) * (4*b2+2*b1+b0); */
   /** T1 = T1 + a2; */
   if ((err = mp_add(&T1, &a2, &T1)) != MP_OKAY)                  goto LBL_ERR;

   /** T1 = T1 << 1; */
   if ((err = mp_mul_2(&T1, &T1)) != MP_OKAY)                     goto LBL_ERR;

   /** T1 = T1 + a0; */
   if ((err = mp_add(&T1, &a0, &T1)) != MP_OKAY)                  goto LBL_ERR;

   /** c = c + b2; */
   if ((err = mp_add(c, &b2, c)) != MP_OKAY)                      goto LBL_ERR;

   /** c = c << 1; */
   if ((err = mp_mul_2(c, c)) != MP_OKAY)                         goto LBL_ERR;

   /** c = c + b0; */
   if ((err = mp_add(c, &b0, c)) != MP_OKAY)                      goto LBL_ERR;

   /** S2 = T1 * c; */
   if ((err = mp_mul(&T1, c, &S2)) != MP_OKAY)                    goto LBL_ERR;

   /** \\S3 = (a2-a1+a0) * (b2-b1+b0); */
   /** a1 = a2 - a1; */
   if ((err = mp_sub(&a2, &a1, &a1)) != MP_OKAY)                  goto LBL_ERR;

   /** a1 = a1 + a0; */
   if ((err = mp_add(&a1, &a0, &a1)) != MP_OKAY)                  goto LBL_ERR;

   /** b1 = b2 - b1; */
   if ((err = mp_sub(&b2, &b1, &b1)) != MP_OKAY)                  goto LBL_ERR;

   /** b1 = b1 + b0; */
   if ((err = mp_add(&b1, &b0, &b1)) != MP_OKAY)                  goto LBL_ERR;

   /** a1 = a1 * b1; */
   if ((err = mp_mul(&a1, &b1, &a1)) != MP_OKAY)                  goto LBL_ERR;

   /** b1 = a2 * b2; */
   if ((err = mp_mul(&a2, &b2, &b1)) != MP_OKAY)                  goto LBL_ERR;

   /** \\S2 = (S2 - S3)/3; */
   /** S2 = S2 - a1; */
   if ((err = mp_sub(&S2, &a1, &S2)) != MP_OKAY)                  goto LBL_ERR;

   /** S2 = S2 / 3; \\ this is an exact division  */
   if ((err = mp_div_3(&S2, &S2, NULL)) != MP_OKAY)               goto LBL_ERR;

   /** a1 = S1 - a1; */
   if ((err = mp_sub(&S1, &a1, &a1)) != MP_OKAY)                  goto LBL_ERR;

   /** a1 = a1 >> 1; */
   if ((err = mp_div_2(&a1, &a1)) != MP_OKAY)                     goto LBL_ERR;

   /** a0 = a0 * b0; */
   if ((err = mp_mul(&a0, &b0, &a0)) != MP_OKAY)                  goto LBL_ERR;

   /** S1 = S1 - a0; */
   if ((err = mp_sub(&S1, &a0, &S1)) != MP_OKAY)                  goto LBL_ERR;

   /** S2 = S2 - S1; */
   if ((err = mp_sub(&S2, &S1, &S2)) != MP_OKAY)                  goto LBL_ERR;

   /** S2 = S2 >> 1; */
   if ((err = mp_div_2(&S2, &S2)) != MP_OKAY)                     goto LBL_ERR;

   /** S1 = S1 - a1; */
   if ((err = mp_sub(&S1, &a1, &S1)) != MP_OKAY)                  goto LBL_ERR;

   /** S1 = S1 - b1; */
   if ((err = mp_sub(&S1, &b1, &S1)) != MP_OKAY)                  goto LBL_ERR;

   /** T1 = b1 << 1; */
   if ((err = mp_mul_2(&b1, &T1)) != MP_OKAY)                     goto LBL_ERR;

   /** S2 = S2 - T1; */
   if ((err = mp_sub(&S2, &T1, &S2)) != MP_OKAY)                  goto LBL_ERR;

   /** a1 = a1 - S2; */
   if ((err = mp_sub(&a1, &S2, &a1)) != MP_OKAY)                  goto LBL_ERR;


   /** P = b1*x^4+ S2*x^3+ S1*x^2+ a1*x + a0; */
   if ((err = mp_lshd(&b1, 4 * B)) != MP_OKAY)                    goto LBL_ERR;
   if ((err = mp_lshd(&S2, 3 * B)) != MP_OKAY)                    goto LBL_ERR;
   if ((err = mp_add(&b1, &S2, &b1)) != MP_OKAY)                  goto LBL_ERR;
   if ((err = mp_lshd(&S1, 2 * B)) != MP_OKAY)                    goto LBL_ERR;
   if ((err = mp_add(&b1, &S1, &b1)) != MP_OKAY)                  goto LBL_ERR;
   if ((err = mp_lshd(&a1, 1 * B)) != MP_OKAY)                    goto LBL_ERR;
   if ((err = mp_add(&b1, &a1, &b1)) != MP_OKAY)                  goto LBL_ERR;
   if ((err = mp_add(&b1, &a0, c)) != MP_OKAY)                    goto LBL_ERR;

   /** a * b - P */


LBL_ERR:
   mp_clear(&b2);
LBL_ERRb2:
   mp_clear(&b1);
LBL_ERRb1:
   mp_clear(&b0);
LBL_ERRb0:
   mp_clear(&a2);
LBL_ERRa2:
   mp_clear(&a1);
LBL_ERRa1:
   mp_clear(&a0);
LBL_ERRa0:
   mp_clear_multi(&S1, &S2, &T1, NULL);
   return err;
}

#endif

/* End: bn_s_mp_toom_mul.c */

/* Start: bn_s_mp_toom_sqr.c */
#include "tommath_private.h"
#ifdef BN_S_MP_TOOM_SQR_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* squaring using Toom-Cook 3-way algorithm */

/*
   This file contains code from J. Arndt's book  "Matters Computational"
   and the accompanying FXT-library with permission of the author.
*/

/* squaring using Toom-Cook 3-way algorithm */
/*
   Setup and interpolation from algorithm SQR_3 in

     Chung, Jaewook, and M. Anwar Hasan. "Asymmetric squaring formulae."
     18th IEEE Symposium on Computer Arithmetic (ARITH'07). IEEE, 2007.

*/
mp_err s_mp_toom_sqr(const mp_int *a, mp_int *b)
{
   mp_int S0, a0, a1, a2;
   mp_digit *tmpa, *tmpc;
   int B, count;
   mp_err err;


   /* init temps */
   if ((err = mp_init(&S0)) != MP_OKAY) {
      return err;
   }

   /* B */
   B = a->used / 3;

   /** a = a2 * x^2 + a1 * x + a0; */
   if ((err = mp_init_size(&a0, B)) != MP_OKAY)                   goto LBL_ERRa0;

   a0.used = B;
   if ((err = mp_init_size(&a1, B)) != MP_OKAY)                   goto LBL_ERRa1;
   a1.used = B;
   if ((err = mp_init_size(&a2, B + (a->used - (3 * B)))) != MP_OKAY) goto LBL_ERRa2;

   tmpa = a->dp;
   tmpc = a0.dp;
   for (count = 0; count < B; count++) {
      *tmpc++ = *tmpa++;
   }
   tmpc = a1.dp;
   for (; count < (2 * B); count++) {
      *tmpc++ = *tmpa++;
   }
   tmpc = a2.dp;
   for (; count < a->used; count++) {
      *tmpc++ = *tmpa++;
      a2.used++;
   }
   mp_clamp(&a0);
   mp_clamp(&a1);
   mp_clamp(&a2);

   /** S0 = a0^2;  */
   if ((err = mp_sqr(&a0, &S0)) != MP_OKAY)                       goto LBL_ERR;

   /** \\S1 = (a2 + a1 + a0)^2 */
   /** \\S2 = (a2 - a1 + a0)^2  */
   /** \\S1 = a0 + a2; */
   /** a0 = a0 + a2; */
   if ((err = mp_add(&a0, &a2, &a0)) != MP_OKAY)                  goto LBL_ERR;
   /** \\S2 = S1 - a1; */
   /** b = a0 - a1; */
   if ((err = mp_sub(&a0, &a1, b)) != MP_OKAY)                    goto LBL_ERR;
   /** \\S1 = S1 + a1; */
   /** a0 = a0 + a1; */
   if ((err = mp_add(&a0, &a1, &a0)) != MP_OKAY)                  goto LBL_ERR;
   /** \\S1 = S1^2;  */
   /** a0 = a0^2; */
   if ((err = mp_sqr(&a0, &a0)) != MP_OKAY)                       goto LBL_ERR;
   /** \\S2 = S2^2;  */
   /** b = b^2; */
   if ((err = mp_sqr(b, b)) != MP_OKAY)                           goto LBL_ERR;

   /** \\ S3 = 2 * a1 * a2  */
   /** \\S3 = a1 * a2;  */
   /** a1 = a1 * a2; */
   if ((err = mp_mul(&a1, &a2, &a1)) != MP_OKAY)                  goto LBL_ERR;
   /** \\S3 = S3 << 1;  */
   /** a1 = a1 << 1; */
   if ((err = mp_mul_2(&a1, &a1)) != MP_OKAY)                     goto LBL_ERR;

   /** \\S4 = a2^2;  */
   /** a2 = a2^2; */
   if ((err = mp_sqr(&a2, &a2)) != MP_OKAY)                       goto LBL_ERR;

   /** \\ tmp = (S1 + S2)/2  */
   /** \\tmp = S1 + S2; */
   /** b = a0 + b; */
   if ((err = mp_add(&a0, b, b)) != MP_OKAY)                      goto LBL_ERR;
   /** \\tmp = tmp >> 1; */
   /** b = b >> 1; */
   if ((err = mp_div_2(b, b)) != MP_OKAY)                         goto LBL_ERR;

   /** \\ S1 = S1 - tmp - S3  */
   /** \\S1 = S1 - tmp; */
   /** a0 = a0 - b; */
   if ((err = mp_sub(&a0, b, &a0)) != MP_OKAY)                    goto LBL_ERR;
   /** \\S1 = S1 - S3;  */
   /** a0 = a0 - a1; */
   if ((err = mp_sub(&a0, &a1, &a0)) != MP_OKAY)                  goto LBL_ERR;

   /** \\S2 = tmp - S4 -S0  */
   /** \\S2 = tmp - S4;  */
   /** b = b - a2; */
   if ((err = mp_sub(b, &a2, b)) != MP_OKAY)                      goto LBL_ERR;
   /** \\S2 = S2 - S0;  */
   /** b = b - S0; */
   if ((err = mp_sub(b, &S0, b)) != MP_OKAY)                      goto LBL_ERR;


   /** \\P = S4*x^4 + S3*x^3 + S2*x^2 + S1*x + S0; */
   /** P = a2*x^4 + a1*x^3 + b*x^2 + a0*x + S0; */

   if ((err = mp_lshd(&a2, 4 * B)) != MP_OKAY)                    goto LBL_ERR;
   if ((err = mp_lshd(&a1, 3 * B)) != MP_OKAY)                    goto LBL_ERR;
   if ((err = mp_lshd(b, 2 * B)) != MP_OKAY)                      goto LBL_ERR;
   if ((err = mp_lshd(&a0, 1 * B)) != MP_OKAY)                    goto LBL_ERR;
   if ((err = mp_add(&a2, &a1, &a2)) != MP_OKAY)                  goto LBL_ERR;
   if ((err = mp_add(&a2, b, b)) != MP_OKAY)                      goto LBL_ERR;
   if ((err = mp_add(b, &a0, b)) != MP_OKAY)                      goto LBL_ERR;
   if ((err = mp_add(b, &S0, b)) != MP_OKAY)                      goto LBL_ERR;
   /** a^2 - P  */


LBL_ERR:
   mp_clear(&a2);
LBL_ERRa2:
   mp_clear(&a1);
LBL_ERRa1:
   mp_clear(&a0);
LBL_ERRa0:
   mp_clear(&S0);

   return err;
}

#endif

/* End: bn_s_mp_toom_sqr.c */


/* EOF */
