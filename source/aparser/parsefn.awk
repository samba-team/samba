# build parse functions for a parsed struct file

function elem_name(v, elem)
{
	return v["UNION"]elem;
}

function parse_array(f, v, elnum, flags,
		     LOCAL, type, elem)
{
	type = elements[elnum, "type"];
	elem = elements[elnum, "elem"];
	v["ELEM"] = elem_name(v, elem);
	v["TYPE"] = type;
	v["FLAGS"] = flags;
	v["ARRAY_LEN"] = elements[elnum, "array_len"];

	if (type == "uint16") {
		print_template(f, "prs_wstring.tpl", v);
	} else {
		print_template(f, "prs_array.tpl", v);
	}
}
	      

function parse_element(f, v, elnum, flags,
		       LOCAL, type, elem)
{
	type = elements[elnum, "type"];
	if (substr(type,1,1) == ".") return;
	elem = elements[elnum, "elem"];
	if (elements[elnum,"ptr"] == "") {
		v["PTR"] = "\\&";
	} else {
		v["PTR"] = " ";
	}
	v["ELEM"] = elem_name(v, elem);
	v["TYPE"] = type;
	v["FLAGS"] = flags;
	print_template(f, "prs_element.tpl", v);
}

function parse_union(f, v, elnum, flags,
		     LOCAL, i)
{
	v["UNION"] = elements[elnum, "elem"];
	v["SWITCH"] = elements[elnum, "switch"];

	if (elements[elnum, "ptr"] == "1") {
		v["UNION"] = v["UNION"]"->";
	} else {
		v["UNION"] = v["UNION"]".";
	}

	print_template(f, "union_start.tpl", v);
	for (i=0;i<unions[elnum, "num_elems"];i++) {
		v["CASE"] = elements[unions[elnum, i], "case"];
		print_template(f, "prs_case.tpl", v);
		if (elements[elnum, "ptr"] == "1") {
			parse_scalars(f, v, unions[elnum, i], "PARSE_SCALARS");
			parse_buffers(f, v, unions[elnum, i], "PARSE_BUFFERS");
		} else {
			if (flags == "PARSE_SCALARS") {
				parse_scalars(f, v, unions[elnum, i], flags);
			} else {
				parse_buffers(f, v, unions[elnum, i], flags);
			}
		}
		print_template(f, "prs_break.tpl", v);
	}
	v["UNION"] = "";

	print_template(f, "union_end.tpl", v);
}

function parse_scalar(f, v, elnum, flags)
{
	if (elements[elnum, "type"] == "union") {
		parse_union(f, v, elnum, flags);
	} else if (elements[elnum, "array_len"]!="") {
		parse_array(f, v, elnum, flags);
	} else {
		parse_element(f, v, elnum, flags);
	}
}

function parse_pointer(f, v, elnum, flags,
		       LOCAL, elem)
{
	elem = elements[elnum, "elem"];
	v["ELEM"] = elem_name(v, elem);
	v["FLAGS"] = flags;
	print_template(f, "prs_pointer.tpl", v);
}

function parse_scalars(f, v, elnum, flags)
{
	if (elements[elnum, "ptr"] == "1") {
		parse_pointer(f, v, elnum, flags);
	} else {
		parse_scalar(f, v, elnum, flags);
	}
}

function parse_buffers(f, v, elnum, flags,
		      LOCAL, elem, type)
{
	elem = elements[elnum, "elem"];
	type = elements[elnum, "type"];
	v["ELEM"] = elem_name(v, elem);
	if (elements[elnum, "ptr"] == "1") {
		print_template(f, "ifptr_start.tpl", v);
		parse_scalar(f, v, elnum, "PARSE_SCALARS|PARSE_BUFFERS");
		print_template(f, "ifptr_end.tpl", v);
	} else {
		parse_scalar(f, v, elnum, flags);
	}
}

function struct_parser(f, v, struct_num,
		       LOCAL, i, n1) 
{
	v["STRUCTNAME"] = structs[struct_num, "name"];
	v["FUNCNAME"] = "io_" v["STRUCTNAME"];
	print_template(f, "fn_start.tpl", v);

	for (n1=0;n1<structs[struct_num, "num_elems"];n1++) {
		if (elements[structs[struct_num, n1], "type"] == ".trailer") break;
	}

        # first all the structure pointers, scalars and arrays
	for (i=0;i<n1;i++) {
		parse_scalars(f, v, structs[struct_num, i], "PARSE_SCALARS");
	}

	print_template(f, "fn_mid.tpl", v);

	# now the buffers
	for (i=0;i<n1;i++) {
		parse_buffers(f, v, structs[struct_num, i], "PARSE_BUFFERS");
	}

	# and any trailers
	for (i=n1;i<structs[struct_num, "num_elems"];i++) {
		parse_scalars(f, v, structs[struct_num, i], "PARSE_SCALARS");
		parse_buffers(f, v, structs[struct_num, i], "PARSE_BUFFERS");
	}

	print_template(f, "fn_end.tpl", v);
}

function produce_parsers(f,
			 LOCAL, v, i)
{
	v["MODULE"]=module;

	print_template(f, "module_start.tpl", v);

	for (i=0;i < num_structs;i++) {
		struct_parser(f, v, i);
	}

	print_template(f, "module_end.tpl", v);
}
