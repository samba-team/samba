# dump the current parse tree


function element_string(elnum,
			LOCAL, elem)
{
	elem = elements[elnum, "elem"];
	if (elements[elnum, "ptr"]=="1") elem="*"elem;
	if (elements[elnum, "array_len"]!="") 
		elem=elem"["elements[elnum, "array_len"]"]";
	if (elements[elnum, "switch"]!="") 
		elem=elem"["elements[elnum, "switch"]"]";
	return elem;
}

function dump_element(f, elnum,
		      LOCAL, elem, type)
{
	type = elements[elnum, "type"];
	case = elements[elnum, "case"];
	elem = element_string(elnum);
	if (case != "") {
		xprintf(f,"\t\tcase %d %s %s;\n", case, type, elem);
	} else {
		xprintf(f,"\t%s %s;\n", type, elem);
	}
}

function dump_union(f, elnum,
		    LOCAL, i) 
{
	xprintf(f,"\tunion %s {\n", element_string(elnum));
	for (i=0;i<unions[elnum, "num_elems"];i++) {
		dump_element(f, unions[elnum, i]);
	}
	xprintf(f,"\t}\n");
}

function dump_elem(f, struct_num, elem_num,
		   LOCAL, enum) 
{
	elnum = structs[struct_num, elem_num];

	if (elements[elnum, "type"] == "union") {
		dump_union(f, elnum);
	} else {
		dump_element(f, elnum);
	}
}

function dump_structs(f, NIL,
		      LOCAL, i, j) 
{
	xprintf(f,"/* dump of parsed structures */\n\n\n");

	for (i=0;i < num_options;i++) {
		xprintf(f,"option %s %s\n", options[i, "name"], options[i, "value"]);
	}
	xprintf(f,"\n\n");

	for (i=0;i < num_structs;i++) {
		xprintf(f,"/* structure %d */\n", i);
		xprintf(f,"struct %s {\n", structs[i, "name"]);
		for (j=0;j<structs[i, "num_elems"];j++) {
			dump_elem(f, i, j);
		}
		xprintf(f,"};\n\n");
	}
	xprintf(f,"/* end dump */\n\n");
}
