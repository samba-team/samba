# build parse functions for a parsed struct file

function elem_name(v, elem)
{
	return v["UNION"]elem;
}

function parse_array(f, v, elnum, flags,
		     LOCAL, type, elem, array_len)
{
	type = elements[elnum, "type"];
	elem = elements[elnum, "elem"];
	array_len = elements[elnum, "array_len"];
	v["ELEM"] = elem_name(v, elem);
	v["TYPE"] = type;
	v["FLAGS"] = flags;
	v["ARRAY_LEN"] = array_len;

	if (array_len=="+") {
	  print_template(f,"prs_array_optional.tpl", v);
	  return;
	}

	if (array_len=="*") {
	  print_template(f,"prs_array_remainder.tpl", v);
	  return;
	}

	if (type == "wchar" || type == "uint16") {
		if (match(array_len,"[0-9]") == 1) {
			print_template(f, "prs_wstring_fixed.tpl", v);
		} else {
			print_template(f, "prs_wstring.tpl", v);
		}
	} else if (type == "uint8") {
		if (match(array_len,"[0-9]") == 1) {
			print_template(f, "prs_uint8s_fixed.tpl", v);
		} else {
			print_template(f, "prs_uint8s.tpl", v);
		}
	} else {
		print_template(f, "prs_array.tpl", v);
	}
}
	      

function parse_element(f, v, elnum, flags,
		       LOCAL, type, elem)
{
	if (elements[elnum,"nowire"] != "") {
		return;
	}
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

function parse_align2(f, v, elnum, flags,
		       LOCAL, elem)
{
	elem = elements[elnum, "elem"];
	v["OFFSET"] = elem_name(v, elem);
	print_template(f, "prs_align2.tpl", v);
}

function parse_align4(f, v, elnum, flags,
		       LOCAL, elem)
{
	elem = elements[elnum, "elem"];
	v["OFFSET"] = elem_name(v, elem);
	print_template(f, "prs_align4.tpl", v);
}

function parse_pointer(f, v, elnum, flags,
		       LOCAL, elem)
{
	elem = elements[elnum, "elem"];
	v["ELEM"] = elem_name(v, elem);
	v["FLAGS"] = flags;
	print_template(f, "prs_pointer.tpl", v);
}

function parse_scalar_fn(m, v, elnum,
			LOCAL, elem, type)
{
	elem = elements[elnum, "elem"];
	type = elements[elnum, "type"]
	xprintf(m, "%s %s", type, elem_name(v, elem));
	if (type == "union") {
	} else if (elements[elnum, "array_len"]!="") {
	} else {
	}
}

function parse_pointer_fn(f, v, elnum, flags,
		       LOCAL, elem)
{
	elem = elements[elnum, "elem"];
	v["ELEM"] = elem_name(v, elem);
	v["FLAGS"] = flags;
	xprintf(m, "%s\n", v["ELEM"]);
}

function parse_scalars_fn(m, v, elnum, flags)
{
	if (elements[elnum, "type"] == ".align2") {
	}
	else if (elements[elnum, "type"] == ".align4") {
	}
	else if (elements[elnum, "ptr"] == "1") {
		parse_pointer_fn(m, v, elnum, flags);
	} else {
		parse_scalar_fn(m, v, elnum, flags);
	}
}

function parse_scalars(f, v, elnum, flags)
{
	if (elements[elnum, "type"] == ".align2") {
		parse_align2(f, v, elnum, flags);
	}
	else if (elements[elnum, "type"] == ".align4") {
		parse_align4(f, v, elnum, flags);
	}
	else if (elements[elnum, "ptr"] == "1") {
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
	if (elements[elnum, "type"] == ".align2") {
	}
	else if (elements[elnum, "type"] == ".align4") {
	} else if (elements[elnum, "ptr"] == "1") {
		print_template(f, "ifptr_start.tpl", v);
		parse_scalar(f, v, elnum, "PARSE_SCALARS|PARSE_BUFFERS");
		print_template(f, "ifptr_end.tpl", v);
	} else {
		parse_scalar(f, v, elnum, flags);
	}
}

function struct_parser(f, m, v, struct_num,
		       LOCAL, i, n1, f1, num_elems) 
{
	f1 = -1;
	num_elems = structs[struct_num, "num_elems"];
	v["STRUCTNAME"] = structs[struct_num, "name"];
	v["FUNCNAME"] = "io_" v["STRUCTNAME"];
	print_template(f, "fn_start.tpl", v);

	for (n1=0;n1<num_elems;n1++) {
		if (elements[structs[struct_num, n1], "type"] == ".trailer") {
			f1 = n1;
			break;
		}
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
	for (i=n1;i<num_elems;i++) {
		parse_scalars(f, v, structs[struct_num, i], "PARSE_SCALARS");
		parse_buffers(f, v, structs[struct_num, i], "PARSE_BUFFERS");
	}

	if (i > 0) {
		print_template(f, "fn_end.tpl", v);
	}
	else {
		print_template(f, "fn_end0.tpl", v);
	}

	if (f1 == -1)
		return;

	xprintf(m, "void fn_%s(\n", v["STRUCTNAME"]);

	for (i=f1+1;i<num_elems;i++) {
		parse_scalars_fn(m, v, structs[struct_num, i]);
		if (i != num_elems-1)
			xprintf(m, ", \n");
			
	}

	xprintf(m, ")\n{\n}\n");
}

function produce_parsers(f, m,
			 LOCAL, v, i)
{
	v["MODULE"]=module;

	print_template(f, "module_start.tpl", v);

	for (i=0;i < num_structs;i++) {
		struct_parser(f, m, v, i);
	}

	print_template(f, "module_end.tpl", v);
}
