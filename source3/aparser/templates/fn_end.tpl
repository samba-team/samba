
end:
	/* the parse is OK */
	return True;

fail:
	if (UNMARSHALLING(ps)) {
		ZERO_STRUCTP(il);
	}
	return False;
} /* @FUNCNAME@ */


