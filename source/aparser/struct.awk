function isaptr(elem) {
	if (substr(elem, 1, 1) == "*") {
		return 1;
	}
	return 0;
}


function header_elem1(type, elem, ref) {
	if (type == "BUFFER5") {
		printf("\tuint32 %s_len;\n", elem);
	}
	if (ref == 1) {
		printf("\tuint32 %s_ptr;\n", elem);
	} else {
		printf("\t%s\t%s;\n", type, elem);
	}
}

function header_elem2(type, elem, ref) {
	if (ref) {
		printf("\t%s\t%s;\n", type, elem);
	}
}

function produce_header1() {
        printf("\n/* %s structure */\n", struct_name);
	printf("typedef struct {\n");
	for (i=0;i<num_elems;i++) {
		if (unions[i] != unions[i-1]) {
			if (unions[i] != "") {
				printf("\tunion {\n");
			} else {
				printf("\t} %s;\n", unions[i-1]);
			}
		}
		if (isptr[i]) {
			header_elem1(types[i], "*"elems[i], isref[i]);
		} else {
			header_elem1(types[i], elems[i], isref[i]);
		}
	}
	if (unions[i-1] != "") {
		printf("\t} %s;\n", unions[i-1]);
	}
}

function produce_header2() {
	for (i=0;i<num_elems;i++) {
		if (isptr[i]) {
			header_elem2(types[i], "*"elems[i], isref[i]);
		} else {
			header_elem2(types[i], elems[i], isref[i]);
		}
	}
	printf("} %s;\n\n", struct_name);
}

function produce_header() {
	produce_header1();
	produce_header2();
}

function parse_structs() {
        printf("\n\t/* parse the structures in the packet */\n\n");
	for (i=0;i<num_elems;i++) {
		if (types[i] == "UNISTR2") {
			io_unistr2(elems[i]);
		} else if (types[i] == "BUFFER5") {
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
	union="";
	case="";
	struct_name=toupper(name);
	func_name=tolower("io_"name);
	if (name == test) {
		produce_preamble();
	}
}

function parse_one(type, elem) {
	if (type == "uint32") {
		uint32_parser(elem);
	} else if (type == "UINT64_S") {
		uint64_parser(elem);
	} else if (type == "UNISTR2") {
		unistr2_parser(elem);
	} else if (type == "BUFFER5") {
		buffer5_parser(elem);
	} else if (type == "NTTIME") {
		nttime_parser(elem);
	} else {
		generic_parser(type, elem);
	}
}

function parse_elems() {
        printf("\n\t/* parse the main elements of the packet */\n\n");
	for (i=0;i<num_elems;i++) {
		if (cases[i] != "") {
			printf("\tif (il->%s == %s) {\n", 
			       switches[i], cases[i]);
			parse_one(types[i], unions[i]"."elems[i]);
			printf("\t}\n");
		} else {
			parse_one(types[i], elems[i]);
		}
	}
}

function end_struct() {
	produce_header();
	func_header(func_name, struct_name);
	parse_elems();
	parse_structs();
	func_footer();
}

function add_elem(type, elem, ref)
{
	types[num_elems] = type;
	elems[num_elems] = elem;
	switches[num_elems] = switch;
	cases[num_elems] = case;
	unions[num_elems] = union;
	isref[num_elems] = ref;
	isptr[num_elems] = isaptr(elem);
	if (isptr[num_elems] == 1) {
		elems[num_elems] = substr(elems[num_elems], 2);
	}
	num_elems++;
}

