function uint32_parser(elem) {
	printf("\
	if(!prs_uint32(\"%s\", ps, depth, &il->%s))\n\
		return False;\n\
", elem, elem);
}

function unistr2_parser(elem) {
	printf("\
	if(!prs_uint32(\"%s_ptr\", ps, depth, &il->%s_ptr))\n\
		return False;\n\
", elem, elem);
}

function buffer5_parser(elem) {
	printf("\
	if(!prs_uint32(\"%s_len\", ps, depth, &il->%s_len))\n\
		return False;\n\
	if(!prs_uint32(\"%s_ptr\", ps, depth, &il->%s_ptr))\n\
		return False;\n\
", elem, elem, elem, elem);
}

function nttime_parser(elem) {
	printf("\
	if(!smb_io_time(\"%s\", &il->%s, ps, depth))\n\
		return False;\n\
", elem, elem);
}

function uint64_parser(elem) {
	printf("\
	if(!prs_uint64(\"%s\", ps, depth, &il->%s))\n\
		return False;\n\
", elem, elem);
}

function generic_parser(type, elem) {
	printf("\
	if(!%s(\"%s\", &il->%s, ps, depth))\n\
		return False;\n\
", "io_"tolower(type), elem, elem);
}
