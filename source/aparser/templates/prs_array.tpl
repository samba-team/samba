	if ((@FLAGS@ & PARSE_SCALARS) &&
            !io_alloc("@ELEM@", ps, (void **)&il->@ELEM@, sizeof(*(il->@ELEM@))*(il->@ARRAY_LEN@))) goto fail;
	{
		int i;
		for (i=0;i<il->@ARRAY_LEN@;i++) {
		if (!io_@TYPE@("@ELEM@...", ps, depth+1, &il->@ELEM@[i], @FLAGS@)) goto fail;
		}
	}
