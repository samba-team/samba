	if ((MARSHALLING(ps) && il->@ELEM@) ||
	     ps->data_offset < ps->buffer_size) {
	if (!io_alloc("@ELEM@", ps, (void **)&il->@ELEM@, sizeof(*(il->@ELEM@)))) goto fail;
	if (!io_@TYPE@("@ELEM@...", ps, depth+1, il->@ELEM@, @FLAGS@)) goto fail;
	}
