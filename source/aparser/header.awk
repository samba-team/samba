# produce a header file for a parsed struct file

function header_elstring(elnum,
			 LOCAL, elem)
{
	array_len = elements[elnum, "array_len"];
	elem=elements[elnum, "elem"];
	if (elements[elnum, "ptr"]=="1") elem="*"elem;
	if (array_len!="") {
		if (is_constant(array_len) == 1) {
			elem=elem"["array_len"]";
		} else {
			elem="*"elem;
		}
	}
	return elem;
}

function header_element(f, elnum,
			LOCAL, type)
{
	type=elements[elnum, "type"];
	if (substr(type,1,1) == ".") return;
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
	xprintf(f,"#ifndef _%s_\n", module);
	xprintf(f,"#define _%s_\n", module);

	xprintf(f,"\n\n");
	for (i=0;i < num_options;i++) {
		xprintf(f,"#define OPTION_%s %s\n", 
			options[i, "name"], options[i, "value"]);
	}
	xprintf(f,"\n\n");

	for (i=0;i < num_structs;i++) {
		header_struct(f, i);
	}
	xprintf(f,"/* end auto-generated headers */\n\n");
	xprintf(f,"#endif /* _%s_ */\n", module);
}

