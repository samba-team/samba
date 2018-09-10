#include <talloc.h>

enum tftw_flags_e {
	/* Regular file.  */
	TFTW_FLAG_FILE,
	/* Directory.  */
	TFTW_FLAG_DIR,
	/* Unreadable directory.  */
	TFTW_FLAG_DNR,
	/* Unstatable file.  */
	TFTW_FLAG_NSTAT,
	/* Symbolic link.  */
	TFTW_FLAG_SLINK,
	/* Special file (fifo, ...).  */
	TFTW_FLAG_SPEC,

	/* Directory, all subdirs have been visited. */
	TFTW_FLAG_DP,
	/* Symbolic link naming non-existing file.  */
	TFTW_FLAG_SLN
};

/* Maximum number of subdirectories to descend into */
#define TFTW_MAX_DEPTH 50

typedef int (*tftw_walker_fn)(TALLOC_CTX *mem_ctx,
			      const char *fpath,
			      const struct stat *sb,
			      enum tftw_flags_e flag,
			      void *userdata);

int tftw(TALLOC_CTX *mem_ctx, const char *fpath, tftw_walker_fn fn, size_t depth, void *userdata);
