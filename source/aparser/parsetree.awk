# build the parse tree for a struct file

function find_structure(name, 
			LOCAL, i)
{
  for (i=0;i<num_structs;i++) {
    if (structs[i, "name"] == name) return i;
  }
  return "-1";
}

function start_module(name) 
{
	module=name;
	num_structs=0;
	num_elements=0;
	num_unions=0;
	num_tests=0;
	num_options=0;
}

function set_option(name, value) 
{
	options[name] = value;
	options[num_options, "name"] = name;
	options[num_options, "value"] = value;
	num_options++;
}

function parse_define(def1, def2,
		      LOCAL, type, i)
{
	defines[def1]=def2;
}

function start_struct(name) 
{
	current_struct=num_structs;
	structs[name]=current_struct;
	structs[current_struct, "name"]=name;
	structs[current_struct, "num_elems"]=0;
	structs[current_struct, "num_unions"]=0;
	structs[current_struct, "recurse"] = options["recurse"];
}

function end_struct(name) 
{
	if (name!="") structs[num_structs, "name"]=name;
	printf("struct %s with %d elements\n", 
	       structs[num_structs, "name"],
	       structs[num_structs, "num_elems"]);
	num_structs++;
	current_struct="";
}

function add_element(type, elem, case,
		     LOCAL, elem_num, i, v)
{
	while (defines[type]!="") {
		type=defines[type];
	}
	elem_num=num_elements;

	if (substr(elem, 1, 1) == ".") {
		elem=substr(elem, 2);
		elements[elem_num, "nowire"]=1;
	}

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

function start_union_notencap(switch)
{
	add_struct_elem("uint32", "switch_"switch);
	start_union("UNKNOWN[switch_"switch"]");
}

function start_union_encap(struct, type, switch, union)
{
	start_struct(struct);
	add_struct_elem(type, switch);
	add_struct_elem(type, "switch_"switch);
	start_union(union"[switch_"switch"]");
	encap_union="1";
}

function parse_case(case, type, elem,
		    LOCAL, elem_num) 
{
	split(case, a, "[:]");
	case = a[1];
	elem_num = unions[current_union, "num_elems"];
	unions[current_union, elem_num] = add_element(type, elem, case);
	unions[current_union, "num_elems"]++;
}

function end_union(name) 
{
	if (name!="") {
		elements[current_union, "elem"] = name;
	}
	current_union="";
	if (encap_union=="1") {
		end_struct(name);
		encap_union="0";
	}
}

function delete_element(struct, elnum,
			LOCAL, i)
{
	for (i=elnum;i<structs[struct,"num_elems"]-1;i++) {
		structs[struct, i] = structs[struct, i+1];
	}
	structs[struct, "num_elems"]--;
}

function copy_struct(from, to,
		     LOCAL, i)
{
	for (i=0;i<structs[from,"num_elems"];i++) {
		structs[to, i] = structs[from, i];
	}
	structs[to, "name"] = structs[from, "name"];
	structs[to, "num_elems"] = structs[from, "num_elems"];
	structs[to, "num_unions"] = structs[from, "num_unions"];
}

function add_sizeis_array(count, type, elem)
{
	copy_struct(current_struct, current_struct+1);
	elem=substr(elem,2);
	start_struct("array_"current_struct"_"elem);
	add_struct_elem("uint32", count);
	add_struct_elem(type, elem"["count"]");
	end_struct("");
	current_struct=num_structs;
	add_struct_elem("array_"current_struct-1"_"elem, "*"elem"_ptr");
}


function start_function(type, fname)
{
        start_struct(fname);
	structs[current_struct, "recurse"] = "False";
}

function end_function(LOCAL, i)
{
  copy_struct(num_structs, num_structs+1);
  structs[num_structs, "name"] = "Q_"structs[num_structs, "name"];
  for (i=0;i<structs[num_structs, "num_elems"];i++) {
    if (match(elements[structs[num_structs, i], "properties"], "in") == 0) {
      delete_element(num_structs, i);
      i--;
    }
  }
  end_struct();
  current_struct=num_structs;
  structs[num_structs, "name"] = "R_"structs[num_structs, "name"];
  for (i=0;i<structs[num_structs, "num_elems"];i++) {
    if (match(elements[structs[num_structs, i], "properties"], "out") == 0) {
      delete_element(num_structs, i);
      i--;
    }
  }
  if (return_result!="void")
    add_function_param("[out]", return_result, "status");
  end_struct();
}

function add_function_param(properties, type, elem,
			    LOCAL, elnum, len)
{
  len=length(type);
  if (substr(type, len) == "*") {
    type=substr(type, 1, len-1);
    elem="*"elem;
  }
  if (substr(elem,1,1) == "*" &&
      (match(properties,"in") == 0 || 
       find_structure(type) != "-1")) {
    elem=substr(elem, 2);
  }
  elnum = add_struct_elem(type, elem);
  elements[elnum, "properties"] = properties;
}

