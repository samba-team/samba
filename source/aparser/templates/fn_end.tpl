
end:
	/* the parse is OK, just align and end */
	if (!prs_align(ps)) goto fail;

	return True;

fail:
        ZERO_STRUCTP(il);
	return False;
} /* @FUNCNAME@ */


