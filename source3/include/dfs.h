
typedef struct _referal_trans_param
{
	uint16 level;
	char   directory[255];
	uint16 type;
} referal_trans_param;
 
typedef struct _referal_ver_2
{
	uint16 version;
	uint16 size;
	uint16 server_type;
	uint16 flags;
	uint32 proximity;
	uint32 ttl;
	uint16 filename_offset;
	uint16 mangledname_offset;
	uint16 sharename_offset;
	char sharename[255];
} referal_ver_2;

typedef struct _dfs_response
{
	uint16 path_consumed;
	uint16 number_of_referal;
	uint32 server_function;
	referal_ver_2 *referal;
	char filename[255];
	char mangledname[255];
	struct _dfs_response *next;
} dfs_response;
 

typedef struct _dfs_internal_table
{
	pstring localpath;
	pstring mangledpath;
	pstring sharename;
	unsigned int proximity;
	unsigned int type;
	int localpath_length;
	int mangledpath_length;
	int sharename_length;
} dfs_internal_table; 

typedef struct _dfs_internal
{

	dfs_internal_table *table;
	int size;
	BOOL ready;
} dfs_internal;
