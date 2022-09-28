#ifndef HAVE_STABLE_SORT_H
#define HAVE_STABLE_SORT_H 1

#ifdef __COMPAR_FN_T
typedef __compar_fn_t samba_compare_fn_t;

#ifdef __USE_GNU
/* glibc defines __compar_d_fn_t for qsort_r */
typedef __compar_d_fn_t samba_compare_with_context_fn_t;
#endif

#else
typedef int (*samba_compare_fn_t) (const void *, const void *);
typedef int (*samba_compare_with_context_fn_t) (const void *, const void *, void *);
#endif



bool stable_sort_r(void *array, void *aux,
		   size_t n,
		   size_t s,
		   samba_compare_with_context_fn_t cmpfn,
		   void *opaque);

bool stable_sort(void *array, void *aux,
		 size_t n,
		 size_t s,
		 samba_compare_fn_t cmpfn);


bool stable_sort_talloc_r(TALLOC_CTX *mem_ctx,
			  void *array,
			  size_t n,
			  size_t s,
			  samba_compare_with_context_fn_t cmpfn,
			  void *opaque);


bool stable_sort_talloc(TALLOC_CTX *mem_ctx,
			void *array,
			size_t n,
			size_t s,
			samba_compare_fn_t cmpfn);


#endif /* HAVE_STABLE_SORT_H */
