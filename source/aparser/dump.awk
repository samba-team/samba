# dump the current parse tree

function dump_union(f, struct_num, union,
		    LOCAL, i) 
{
	xprintf(f,"\tunion %s %s {\n", 
	       structs[struct_num, "unions", union, "switch"],
	       union);
	for (i=0;i<structs[struct_num, "unions", union, "num_elems"];i++) {
		xprintf(f,"\t\tcase %d %s %s;\n", 
		       structs[struct_num, "unions", union, i, "value"],
		       structs[struct_num, "unions", union, i, "type"],
		       structs[struct_num, "unions", union, i, "elem"]);
	}
	xprintf(f,"\t}\n");
}

function dump_array(f, struct_num, elem_num,
		    LOCAL, i) 
{
	xprintf(f,"\t{%s} %s %s;\n", 
	       structs[struct_num, elem_num, "array_len"],
	       structs[struct_num, elem_num, "type"],
	       structs[struct_num, elem_num, "elem"]);
}

function dump_elem(f, struct_num, elem_num) 
{
	if (structs[struct_num, elem_num, "type"] == "union") {
		dump_union(f, struct_num, structs[struct_num, elem_num, "elem"]);
	} else if (structs[struct_num, elem_num, "array_len"]) {
		dump_array(f, struct_num, elem_num);
	} else {
		xprintf(f,"\t%s %s;\n", 
		       structs[struct_num, elem_num, "type"],
		       structs[struct_num, elem_num, "elem"]);
	}
}

function dump_structs(f, NIL,
		      LOCAL, i, j) 
{
	xprintf(f,"/* dump of parsed structures */\n\n\n");
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


