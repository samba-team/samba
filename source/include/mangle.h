#ifndef _MANGLE_H_
#define _MANGLE_H_
/*
  header for 8.3 name mangling interface 
*/

struct mangle_fns {
	BOOL (*is_mangled)(const char *s);
	BOOL (*is_8_3)(const char *fname, BOOL check_case, BOOL allow_wildcards);
	void (*reset)(void);
	BOOL (*check_cache)(char *s, size_t maxlen);
	void (*name_map)(char *OutName, BOOL need83, BOOL cache83);
};
#endif /* _MANGLE_H_ */
