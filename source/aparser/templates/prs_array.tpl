	if (il->@ARRAYLEN@ > 0) {
		il->@ELEM@ = (@TYPE@ *)malloc(sizeof(@TYPE@)*il->@ARRAYLEN@);
		if (!il->@ELEM@) goto fail;
		if (!prs_@TYPE@s(True, "@ELEM@", ps, depth+1, il->@ELEM@, il->@ARRAYLEN@)) goto fail;
	} else {
	        il->@ELEM@ = NULL; 
	}
