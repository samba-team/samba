
	return True;

fail:
        ZERO_STRUCTP(il);
	return False;
} /* @FUNCNAME@ */

/*******************************************************************
parse a @STRUCTNAME@ structure
********************************************************************/
BOOL @FUNCNAME@_alloc(char *desc, @STRUCTNAME@ **q_u,
             prs_struct *ps, int depth)
{
	@STRUCTNAME@ *il;
	BOOL ret;
	
	if (!UNMARSHALLING(ps)) return False;

	il=(@STRUCTNAME@ *)malloc(sizeof(@STRUCTNAME@));
	if (il == NULL) return False;
	ZERO_STRUCTP(il);

	ret = @FUNCNAME@(desc, il, ps, depth);
	if (!ret) {
	   free(il);
	   return False;
	}
	*q_u = il;
	return True;
}


