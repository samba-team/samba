#ifndef _MANGLE_H_
#define _MANGLE_H_
/*
  header for 8.3 name mangling interface 
*/

struct mangle_fns {
	void (*reset)(void);
	BOOL (*is_mangled)(const char *s, const struct share_params *p);
	BOOL (*must_mangle)(const char *s, const struct share_params *p);
	BOOL (*is_8_3)(const char *fname, BOOL check_case, BOOL allow_wildcards,
		       const struct share_params *p);
	BOOL (*lookup_name_from_8_3)(TALLOC_CTX *ctx,
				const char *in,
				char **out, /* talloced on the given context. */
				const struct share_params *p);
	BOOL (*name_to_8_3)(const char *in,
			char out[13],
			BOOL cache83,
			int default_case,
			const struct share_params *p);
};
#endif /* _MANGLE_H_ */
