function add_elem(type, elem)
{
   types[num_elems] = type;
   elems[num_elems] = elem;
   num_elems++;
}

function produce_preamble() {
	printf("#define TEST_STRUCT %s\n", struct_name);
	printf("#define TEST_FUNC %s\n", func_name);
	printf("#define TEST_NAME \"%s\"\n", func_name);
	printf("\n\n");
}

function produce_header() {
        printf("\n/* %s structure */\n", struct_name);
	printf("typedef struct {\n");
	for (i=0;i<num_elems;i++) {
		if (types[i] == "UNISTR2") {
			printf("\tuint32 %s_ptr;\n", elems[i]);
		} else if (types[i] == "BUFFER5") {
			printf("\tuint32 %s_len;\n", elems[i]);
			printf("\tuint32 %s_ptr;\n", elems[i]);
		} else {
			printf("\t%s\t%s;\n", types[i], elems[i]);
		}
	}
	for (i=0;i<num_elems;i++) {
		if (types[i] == "UNISTR2" || 
		    types[i] == "BUFFER5") {
			printf("\t%s\t%s;\n", types[i], elems[i]);
		}
	}
	printf("} %s;\n\n", struct_name);
}


function parse_structs() {
        printf("\n\t/* parse the structures in the packet */\n\n");
	for (i=0;i<num_elems;i++) {
		if (types[i] == "UNISTR2") {
			io_unistr2(elems[i]);
		}
		if (types[i] == "BUFFER5") {
			io_buffer5(elems[i]);
		}
	}
}

function io_unistr2(elem) {
	printf("\
	if(!smb_io_unistr2(\"%s\", &il->%s, il->%s_ptr, ps, depth))\n\
		return False;\n\
	if(!prs_align(ps))\n\
		return False;\n\
", elem, elem, elem);
}

function io_buffer5(elem) {
	printf("\
        if (il->%s_ptr) {\n\
	if(!smb_io_buffer5(\"%s\", &il->%s, ps, depth))\n\
		return False;\n\
	if(!prs_align(ps))\n\
		return False;\n\
        }\n\
", elem, elem, elem);
}

function start_struct(name) {
	num_elems=0;
	struct_name=toupper(module"_"name);
	func_name=tolower(module"_io_"name);
}

function parse_elems() {
        printf("\n\t/* parse the main elements the packet */\n\n");
	for (i=0;i<num_elems;i++) {
		if (types[i] == "uint32") {
			uint32_parser(elems[i]);
		} 
		if (types[i] == "UINT64_S") {
			uint64_parser(elems[i]);
		} 
		if (types[i] == "UNISTR2") {
			unistr2_parser(elems[i]);
		} 
		if (types[i] == "BUFFER5") {
			buffer5_parser(elems[i]);
		} 
		if (types[i] == "NTTIME") {
			nttime_parser(elems[i]);
		} 
	}
}

function end_struct() {
	produce_preamble();
	produce_header();
	func_header(func_name, struct_name);
	parse_elems();
	parse_structs();
	func_footer();
}



function func_footer() {
	printf("\n\
\n\
	return True;\n\
}\n");
}

function func_header(func_name, struct_name)
{
	printf("\
/*******************************************************************\n\
parse a %s structure\n\
********************************************************************/  \n\
BOOL %s(char *desc, %s **q_u, \n\
                                          prs_struct *ps, int depth)\n\
{	\n\
	%s *il;\n\
	\n\
	prs_debug(ps, depth, desc, \"%s\");\n\
	depth++;\n\
		\n\
	/* reading */\n\
	if (UNMARSHALLING(ps)) {\n\
		il=(%s *)malloc(sizeof(%s));\n\
		if(il == NULL)\n\
			return False;\n\
		ZERO_STRUCTP(il);\n\
		*q_u=il;\n\
	}\n\
	else {\n\
		il=*q_u;\n\
	}\n\
	\n\
	if(!prs_align(ps))\n\
		return False;\n\
\n\
", struct_name, func_name, struct_name, struct_name, func_name, struct_name, struct_name);
}

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

/^module/ {
	module=$2;
}

/^struct/ {
	start_struct($2);
}


/^\}/ {
	end_struct();
}

/uint32|UINT64_S|UNISTR2|BUFFER5|NTTIME/ {
	split($0,a,"[ ;]*");
	add_elem(a[2], a[3]);
}
