/* this private structure is used by the ltdb backend in the
   ldb_context */
struct ltdb_private {
	TDB_CONTEXT *tdb;
	unsigned int connect_flags;
	
	/* a double is used for portability and ease of string
	   handling. It has plenty of digits of precision */
	double sequence_number;

	struct {
		struct ldb_message baseinfo;
		struct ldb_message indexlist;
		struct ldb_message attributes;
		struct ldb_message subclasses;

		struct {
			char *name;
			int flags;
		} last_attribute;
	} cache;

	/* error if an internal ldb+tdb error */
	const char *last_err_string;
};

/* special record types */
#define LTDB_INDEX      "@INDEX"
#define LTDB_INDEXLIST  "@INDEXLIST"
#define LTDB_IDX        "@IDX"
#define LTDB_IDXATTR    "@IDXATTR"
#define LTDB_BASEINFO   "@BASEINFO"
#define LTDB_ATTRIBUTES "@ATTRIBUTES"
#define LTDB_SUBCLASSES "@SUBCLASSES"

/* special attribute types */
#define LTDB_SEQUENCE_NUMBER "sequenceNumber"
#define LTDB_OBJECTCLASS "objectClass"

/* well known attribute flags */
#define LTDB_FLAG_CASE_INSENSITIVE (1<<0)
#define LTDB_FLAG_INTEGER          (1<<1)
#define LTDB_FLAG_WILDCARD         (1<<2)
#define LTDB_FLAG_OBJECTCLASS      (1<<3)
#define LTDB_FLAG_HIDDEN           (1<<4)


#ifndef IVAL
#define IVAL(p, ofs) (((unsigned *)((char *)(p) + (ofs)))[0])
#endif
#ifndef SIVAL
#define SIVAL(p, ofs, v) do { IVAL(p, ofs) = (v); } while (0)
#endif
