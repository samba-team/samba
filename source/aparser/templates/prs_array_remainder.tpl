	if (UNMARSHALLING(ps))
	{
		int i;
		for (i=0;ps->data_offset < ps->buffer_size;i++) {
		if (!io_alloc("@ELEM@", ps, (void **)&il->@ELEM@, sizeof(*(il->@ELEM@))*(i+1))) goto fail;
		if (!io_@TYPE@("@ELEM@...", ps, depth+1, &il->@ELEM@[i], @FLAGS@)) goto fail;
		}
	}
	else
	{
		int i = -1;
		/* HACK ALERT! */
		do {
		i++;
		if (!io_@TYPE@("@ELEM@...", ps, depth+1, &il->@ELEM@[i], @FLAGS@)) goto fail;
		} while (il->@ELEM@[i].tag2 != 0);
	}
