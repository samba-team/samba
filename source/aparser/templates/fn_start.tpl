/*******************************************************************
parse a @STRUCTNAME@ structure
********************************************************************/
BOOL @FUNCNAME@(char *desc, io_struct *ps, int depth,
		@STRUCTNAME@ *il, unsigned flags)
{
	io_debug(ps, depth, desc, "@FUNCNAME@");
	depth++;
	
	if (!(flags & PARSE_SCALARS)) goto buffers;

#if 0
	if (UNMARSHALLING(ps)) {
		ZERO_STRUCTP(il);
	}
#endif
	/* parse the scalars */
