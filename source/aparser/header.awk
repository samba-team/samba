# produce a header file for a parsed struct file

function header_elstring(elnum,
			 LOCAL, elem)
{
	elem=elements[elnum, "elem"];
	if (elements[elnum, "ptr"]=="1") elem="*"elem;
	if (elements[elnum, "array_len"]!="") elem="*"elem;
	return elem;
}

function header_element(f, elnum,
			LOCAL, type)
{
	type=elements[elnum, "type"];
	xprintf(f,"\t%s %s;\n", type, header_elstring(elnum));
}

function header_union(f, elnum,
		      LOCAL, i) 
{
	xprintf(f,"\tunion {\n");
	for (i=0;i<unions[elnum, "num_elems"];i++) {
		header_element(f, unions[elnum, i]);
	}
	xprintf(f,"\t} %s;\n", header_elstring(elnum));
}

function header_elem(f, elnum) 
{
	
	if (elements[elnum, "type"] == "union") {
		header_union(f, elnum);
	} else {
		header_element(f, elnum);
	}
}

function header_struct(f, struct_num,
		       LOCAL, i) 
{
	xprintf(f,"/* structure %s */\n", 
	       structs[struct_num, "name"]);
	xprintf(f,"typedef struct {\n");
	for (i=0;i < structs[struct_num, "num_elems"];i++) {
		header_elem(f, structs[struct_num, i]);
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

