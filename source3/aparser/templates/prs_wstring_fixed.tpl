	if (!io_alloc("@ELEM@", ps, (void **)&il->@ELEM@, sizeof(*(il->@ELEM@))*(@ARRAY_LEN@))) goto fail;
	if (!io_wstring("@ELEM@", ps, depth+1, il->@ELEM@,	@ARRAY_LEN@, @FLAGS@)) goto fail;
