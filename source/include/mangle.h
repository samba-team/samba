/*
  header for 8.3 name mangling interface 
*/

struct mangle_fns {
	BOOL (*is_mangled)(const char *s);
	BOOL (*is_8_3)(const char *fname, BOOL check_case);
	void (*reset)(void);
	BOOL (*check_cache)(char *s);
	BOOL (*name_map)(char *OutName, BOOL need83, BOOL cache83);
};
