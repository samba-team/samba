# build the parse tree for a struct file

function start_module(name) 
{
	module=name;
	num_structs=0;
}

function start_struct(name) 
{
	current_struct=num_structs;
	structs[name]=current_struct;
	structs[current_struct, "name"]=name;
	structs[current_struct, "num_elems"]=0;
	structs[current_struct, "num_unions"]=0;
}

function end_struct() 
{
	num_structs++;
	current_struct="";
}

function add_elem(type, elem,
		  LOCAL, elem_num)
{
	elem_num=structs[current_struct, "num_elems"];
	structs[current_struct, elem_num, "type"] = type;
	structs[current_struct, elem_num, "elem"] = elem;
	structs[current_struct, elem_num, "array_len"] = "";
	structs[current_struct, "num_elems"]++;
	return elem_num;
}

function add_array(array_len, type, elem,
		   LOCAL, elem_num)
{
	elem_num=add_elem(type, elem);
	structs[current_struct, elem_num, "array_len"] = array_len;
}

function start_union(switch, elem) 
{
	current_union=elem;
	add_elem("union", elem);
	structs[current_struct, "unions", current_union, "switch"] = switch;
	structs[current_struct, "unions", current_union, "num_elems"] = 0;
}

function parse_case(value, type, elem,
		    LOCAL, elem_num) 
{
	elem_num =structs[current_struct, "unions", current_union, "num_elems"];
	structs[current_struct, "unions", current_union, elem_num, "type"] = type;
	structs[current_struct, "unions", current_union, elem_num, "elem"] = elem;
	structs[current_struct, "unions", current_union, elem_num, "value"] = value;
	structs[current_struct, "unions", current_union, "num_elems"]++;
}

function end_union() 
{
	current_union="";
}

