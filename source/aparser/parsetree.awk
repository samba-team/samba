# build the parse tree for a struct file

function start_module(name) 
{
	module=name;
	num_structs=0;
	num_elements=0;
	num_unions=0;
	num_tests=0;
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

function add_element(type, elem, case,
		     LOCAL, elem_num, i, v)
{
	elem_num=num_elements;

	if (substr(elem, 1, 1) == "*") {
		elem=substr(elem, 2);
		elements[elem_num, "ptr"]=1;
	}

	i=match(elem,"[[]");
	if (i != 0) {
		v = substr(elem, i+1, length(elem)-i-1);
		elem=substr(elem, 1, i-1);
		if (type=="union") {
			elements[elem_num, "switch"] = v;
		} else {
			elements[elem_num, "array_len"] = v;
		}
	}

	elements[elem_num, "type"] = type;
	elements[elem_num, "elem"] = elem;
	elements[elem_num, "case"] = case;

	num_elements++;
	return elem_num;
}

function add_struct_elem(type, elem, case,
			 LOCAL, elem_num)
{
	elem_num=structs[current_struct, "num_elems"];
	structs[current_struct, elem_num] = add_element(type, elem, case);
	structs[current_struct, "num_elems"]++;
	return structs[current_struct, elem_num];
}

function start_union(elem)
{
	current_union = add_struct_elem("union", elem);
	unions[current_union, "num_elems"] = 0;
}

function parse_case(case, type, elem,
		    LOCAL, elem_num) 
{
	elem_num = unions[current_union, "num_elems"];
	unions[current_union, elem_num] = add_element(type, elem, case);
	unions[current_union, "num_elems"]++;
}

function end_union() 
{
	current_union="";
}
