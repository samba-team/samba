	if (!io_alloc("@ELEM@", ps, (void **)&il->@ELEM@, sizeof(*(il->@ELEM@))*@ARRAY_LEN@)) goto fail;
	if (!io_uint8s("@ELEM@", ps, depth+1, &il->@ELEM@, @ARRAY_LEN@, @FLAGS@)) goto fail;
