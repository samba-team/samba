/* this private structure is used by the ltdb backend in the
   ldb_context */
struct ltdb_private {
	TDB_CONTEXT *tdb;
	unsigned int connect_flags;
};

#ifndef IVAL
#define IVAL(p, ofs) (((unsigned *)((char *)(p) + (ofs)))[0])
#endif
#ifndef SIVAL
#define SIVAL(p, ofs, v) do { IVAL(p, ofs) = (v); } while (0)
#endif
