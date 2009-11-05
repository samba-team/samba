enum dsdb_dn_format {
	DSDB_NORMAL_DN,
	DSDB_BINARY_DN,
	DSDB_STRING_DN,
	DSDB_INVALID_DN
};

struct dsdb_dn {
	struct ldb_dn *dn;
	DATA_BLOB extra_part;
	enum dsdb_dn_format dn_format;
	const char *oid;
};

#define DSDB_SYNTAX_BINARY_DN "1.2.840.113556.1.4.903"
#define DSDB_SYNTAX_STRING_DN  "1.2.840.113556.1.4.904"
