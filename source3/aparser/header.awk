# produce a header file for a parsed struct file

function header_union(f, struct_num, union,
		      LOCAL, i) 
{
	xprintf(f,"\tunion {\n");
	for (i=0;i<structs[struct_num, "unions", union, "num_elems"];i++) {
		xprintf(f,"\t\t%s %s;\n", 
		       structs[struct_num, "unions", union, i, "type"],
		       structs[struct_num, "unions", union, i, "elem"]);
	}
	xprintf(f,"\t} %s;\n", union);
}

function header_array(f, struct_num, elem_num)
{
	xprintf(f,"\t%s *%s; /* array of length %s */ \n", 
	       structs[struct_num, elem_num, "type"],
	       structs[struct_num, elem_num, "elem"],
	       structs[struct_num, elem_num, "array_len"]);
}

function header_elem(f, struct_num, elem_num) 
{
	if (structs[struct_num, elem_num, "type"] == ".align") return;

	if (structs[struct_num, elem_num, "type"] == "union") {
		header_union(f, struct_num, structs[struct_num, elem_num, "elem"]);
	} else if (structs[struct_num, elem_num, "array_len"]) {
		header_array(f, struct_num, elem_num);
	} else {
		xprintf(f,"\t%s %s;\n", 
		       structs[struct_num, elem_num, "type"],
		       structs[struct_num, elem_num, "elem"]);
	}
}

function header_struct(f, struct_num,
		       LOCAL, i) 
{
	xprintf(f,"/* structure %s */\n", 
	       structs[struct_num, "name"]);
	xprintf(f,"typedef struct {\n");
	for (i=0;i < structs[struct_num, "num_elems"];i++) {
		header_elem(f, struct_num, i);
	}
	xprintf(f,"} %s;\n\n\n", structs[struct_num, "name"]);
}


function produce_headers(f, NIL,
			 LOCAL, i) 
{
	xprintf(f,"/* auto-generated headers for %s */\n\n\n", module);
	for (i=0;i < num_structs;i++) {
		header_struct(f, i);
	}
	xprintf(f,"/* end auto-generated headers */\n\n");
}

