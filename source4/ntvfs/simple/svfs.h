
struct svfs_private {
	/* the base directory */
	char *connectpath;

	/* a linked list of open searches */
	struct search_state *search;

	/* next available search handle */
	uint16_t next_search_handle;

	struct svfs_file *open_files;
};

struct svfs_dir {
	uint_t count;
	char *unix_dir;
	struct {
		char *name;
		struct stat st;
	} *files;
};

struct svfs_file {
	struct svfs_file *next, *prev;
	int fd;
	char *name;
};

struct search_state {
	struct search_state *next, *prev;
	TALLOC_CTX *mem_ctx;
	uint16_t handle;
	uint_t current_index;
	struct svfs_dir *dir;
};
