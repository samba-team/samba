
struct rvfs_private {
	/* the meta-data database */
	TDB_CONTEXT *tdb;

	/* the base directory */
	char *connectpath;

	/* a linked list of open searches */
	struct search_state *search;

	/* next available search handle */
	uint16_t next_search_handle;
};

struct rvfs_dir {
	uint_t count;
	char *unix_dir;
	struct {
		char *name;
	} *files;
};

struct search_state {
	struct search_state *next, *prev;
	TALLOC_CTX *mem_ctx;
	uint16_t handle;
	uint_t current_index;
	struct rvfs_dir *dir;
};


struct ref_struct {
	NTTIME mtime, ctime, atime, wtime;
	char *;
};
