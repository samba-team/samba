/*******************************************************************
parse a @STRUCTNAME@ structure
********************************************************************/
BOOL @FUNCNAME@(char *desc, prs_struct *ps, int depth,
		@STRUCTNAME@ *il, unsigned flags)
{
	prs_debug(ps, depth, desc, "@FUNCNAME@");
	depth++;
	
	if (!(flags & PARSE_SCALARS)) goto buffers;

	ZERO_STRUCTP(il);
	/* parse the scalars */
