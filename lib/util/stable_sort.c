/*
   Stable sort routines

   Copyright © Douglas Bagnall <douglas.bagnall@catalyst.net.nz>

     ** NOTE! The following LGPL license applies to this file which is used by
     ** the ldb library. This does NOT imply that all of Samba is released
     ** under the LGPL.

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see <http://www.gnu.org/licenses/>.
*/

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <talloc.h>
#include "replace.h"
#include "stable_sort.h"

static void sort_few(char *array, char *aux,
		     size_t n,
		     size_t s,
		     samba_compare_with_context_fn_t cmpfn,
		     void *opaque)
{
	/* a kind of insertion sort for small n. */
	int i, j, dist;
	int cmp;
	char *a, *b;

	for (i = 1; i < n; i++) {
		a = &array[i * s];
		/* leftwards is sorted. look until we find this one's place */
		for (j = i - 1; j >= 0; j--) {
			b = &array[j * s];
			cmp = cmpfn(a, b, opaque);
			if (cmp >= 0) {
				break;
			}
		}
		dist = i - 1 - j;
		if (dist == 0) {
			/* a is already in the right place */
			continue;
		}

		b = &array[(i - dist) * s];
		memcpy(aux, a, s);
		memmove(b + s, b, s * dist);
		memcpy(b, aux, s);
	}
}


static void merge(char *dest,
		  char *a, size_t alen,
		  char *b, size_t blen,
		  size_t s,
		  samba_compare_with_context_fn_t cmpfn,
		  void *opaque)
{
	size_t ai = 0;
	size_t bi = 0;
	size_t di = 0;
	while (ai < alen && bi < blen) {
		int cmp = cmpfn(&a[ai * s], &b[bi * s], opaque);
		if (cmp <= 0) {
			memcpy(&dest[di * s], &a[ai * s], s);
			ai++;
		} else {
			memcpy(&dest[di * s], &b[bi * s], s);
			bi++;
		}
		di++;
	}
	if (ai < alen) {
		memcpy(&dest[di * s], &a[ai * s], s * (alen - ai));
	} else if (bi < blen) {
		memcpy(&dest[di * s], &b[bi * s], s * (blen - bi));
	}
}


bool stable_sort_r(void *array, void *aux,
		   size_t n,
		   size_t s,
		   samba_compare_with_context_fn_t cmpfn,
		   void * opaque)
{
	char *src = array, *dest = aux, *tmp = NULL;
	size_t i, j, k;
	size_t runsize;
	if (array == NULL || aux == NULL) {
		return false;
	}

	if (n < 20) {
		sort_few(array, aux, n, s, cmpfn, opaque);
		return true;
	}

	if (n > SIZE_MAX / s) {
		/*
		 * We will have an integer overflow if we continue.
		 *
		 * This means that the *supposed* size of the allocated buffer
		 * is greater than SIZE_MAX, which is not possible in theory
		 * or practice, and is a sign the caller has got very
		 * confused.
		 */
		return false;
	}

	/*
	 * This is kind of a bottom-up merge sort.
	 *
	 * We start but sorting into a whole lot of little runs, using an
	 * insertion sort which is efficient for small numbers. Empirically,
	 * on 2 machines, a run size of around 8 seems optimal, but the peak
	 * is wide, and it seems worth adapting the size to avoid an
	 * unbalanced final merge at the top. That is, if we pick the right
	 * runsize now, we will finish with a merge of roughly n/2:n/2, and
	 * not have to follow that with an merge of roughly n:[a few], which
	 * we would sometimes do with a fixed size at the lowest level.
	 *
	 * The aim is a runsize of n / (a power of 2) rounded up, in the
	 * target range.
	 */

	runsize = n;
	while (runsize > 10) {
		runsize++;
		runsize >>= 1;
	}

	for (i = 0; i < n; i += runsize) {
		size_t nn = MIN(n - i, runsize);
		sort_few(&src[i * s], aux, nn, s, cmpfn, opaque);
	}

	while (runsize < n) {
		for (i = 0; i < n; i += runsize * 2) {
			j = i + runsize;
			if (j >= n) {
				/*
				 * first run doesn't fit, meaning this chunk
				 * is already sorted. We just need to copy
				 * it.
				 */
				size_t nn = n - i;
				memcpy(&dest[i * s], &src[i * s], nn * s);
				break;
			}
			k = j + runsize;
			if (k > n) {
				merge(&dest[i * s],
				      &src[i * s], runsize,
				      &src[j * s], n - j,
				      s,
				      cmpfn, opaque);
			} else {
				merge(&dest[i * s],
				      &src[i * s], runsize,
				      &src[j * s], runsize,
				      s,
				      cmpfn, opaque);
			}
		}

		tmp = src;
		src = dest;
		dest = tmp;
		runsize *= 2;
	}
	/*
	 * We have sorted the array into src, which is either array or aux.
	 */
	if (src != array) {
		memcpy(array, src, n * s);
	}
	return true;
}



/*
 * A wrapper that allocates (and frees) the temporary buffer if necessary.
 *
 * returns false on allocation error, true otherwise.
 */

bool stable_sort_talloc_r(TALLOC_CTX *mem_ctx,
			  void *array,
			  size_t n,
			  size_t s,
			  samba_compare_with_context_fn_t cmpfn,
			  void *opaque)
{
	bool ok;
	char *mem = talloc_array_size(mem_ctx, s, n);
	if (mem == NULL) {
		return false;
	}
	ok = stable_sort_r(array, mem, n, s, cmpfn, opaque);
	talloc_free(mem);
	return ok;
}


bool stable_sort(void *array, void *aux,
		 size_t n,
		 size_t s,
		 samba_compare_fn_t cmpfn)
{
	/*
	 * What is this magic, casting cmpfn into a different type that takes
	 * an extra parameter? Is that allowed?
	 *
	 * A: Yes. It's fine. The extra argument will be passed on the stack
	 * or (more likely) a register, and the cmpfn will remain blissfully
	 * unaware.
	 */
	return stable_sort_r(array, aux, n, s,
			     (samba_compare_with_context_fn_t)cmpfn,
			     NULL);
}


bool stable_sort_talloc(TALLOC_CTX *mem_ctx,
			void *array,
			size_t n,
			size_t s,
			samba_compare_fn_t cmpfn)
{
	return stable_sort_talloc_r(mem_ctx, array, n, s,
				    (samba_compare_with_context_fn_t)cmpfn,
				    NULL);
}
