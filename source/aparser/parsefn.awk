# build parse functions for a parsed struct file

function parse_elem(f, v, struct_num, elem_num,
		    LOCAL, type, elem)
{
	type = structs[struct_num, elem_num, "type"];
	elem = structs[struct_num, elem_num, "elem"];
	v["ELEM"] = noptr(elem);
	v["TYPE"] = type;
	if (structs[type] != "") {
		if (isaptr(elem)) {
			print_template(f, "prs_struct_alloc.tpl", v);
		} else {
			print_template(f, "prs_struct.tpl", v);
		}
	} else {
		print_template(f, "prs_"type".tpl", v);
	}
}


function parse_array(f, v, struct_num, elem_num,
		     LOCAL, elem, type)
{
	elem = structs[struct_num, elem_num, "elem"];
	type = structs[struct_num, elem_num, "type"];
	v["ARRAYLEN"] = structs[struct_num, elem_num, "array_len"]
	v["ELEM"] = elem;
	v["TYPE"] = type;
	print_template(f, "prs_array.tpl", v);
}

function parse_union(f, v, struct_num, elem_num,
		     LOCAL, union, type, i, elem, value)
{
	union = structs[struct_num, elem_num, "elem"];
	v["UNION"] = noptr(union);
	v["SWITCH"] = structs[struct_num, "unions", union, "switch"];

	print_template(f, "union_start.tpl", v);
	for (i=0;i<structs[struct_num, "unions", union, "num_elems"];i++) {
		elem = structs[struct_num, "unions", union, i, "elem"];
		type = structs[struct_num, "unions", union, i, "type"];
		value = structs[struct_num, "unions", union, i, "value"];
		v["ELEM"] = v["UNION"]"->"noptr(elem);
		v["TYPE"] = type;
		v["VALUE"] = value;
		print_template(f, "prs_case.tpl", v);
		if (structs[type] != "") {
			print_template(f, "prs_struct.tpl", v);
		} else {
			print_template(f, "prs_"type".tpl", v);
		}
		print_template(f, "prs_case_end.tpl", v);
	}

	print_template(f, "union_end.tpl", v);
}

function parse_ptr_elem(f, v, struct_num, elem_num,
			LOCAL, elem, type)
{
	elem = structs[struct_num, elem_num, "elem"];
	type = structs[struct_num, elem_num, "type"];
	v["ELEM"] = noptr(elem);
	print_template(f, "ifptr_start.tpl", v);
	if (type == "union") {
		parse_union(f, v, struct_num, elem_num);
	} else {
		parse_elem(f, v, struct_num, elem_num);
	}
	print_template(f, "ifptr_end.tpl", v);
}

function parse_scalar(f, v, elnum,
		      LOCAL, elem, type)
{
	if (elements[elnum, "type"] == "union") {
		parse_union(f, v, elnum);
	} else if (elements[elnum, "array_len"]!="") {
		parse_array(f, v, elnum);
	} else {
		
	}
	elem = elements[elnum, "elem"];
	v["ELEM"] = elem;
	print_template(f, "prs_pointer.tpl", v);
}

function parse_pointer(f, v, elnum,
		       LOCAL, elem)
{
	elem = elements[elnum, "elem"];
	v["ELEM"] = elem;
	print_template(f, "prs_pointer.tpl", v);
}

function parse_scalars(f, v, elnum)
{
	if (elements[elnum, "ptr"] == "1") {
		parse_pointer(f, v, elnum);
	} else {
		parse_scalar(f, v, elnum);
	}
}

function struct_parser(f, v, struct_num,
		       LOCAL, i) 
{
	v["STRUCTNAME"] = structs[struct_num, "name"];
	v["FUNCNAME"] = "prs_" v["STRUCTNAME"];
	print_template(f, "fn_start.tpl", v);

        # first all the structure pointers, scalars and arrays
	for (i=0;i<structs[struct_num, "num_elems"];i++) {
		parse_scalars(f, v, structs[struct_num, i]);
	}

	# now the buffers
	for (i=0;i<structs[struct_num, "num_elems"];i++) {
		parse_buffers(f, v, structs[struct_num, i]);
	}

	print_template(f, "fn_end.tpl", v);
}

function produce_parsers(f,
			 LOCAL, v)
{
	v["MODULE"]=module;

	print_template(f, "module_start.tpl", v);

	for (i=0;i < num_structs;i++) {
		struct_parser(f, v, i);
	}

	print_template(f, "module_end.tpl", v);
}
