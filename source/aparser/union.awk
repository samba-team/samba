function start_union(elem, name) {
	switch=elem;
	union=name;
}

function parse_case(value,type,elem) {
	case=value;
	add_elem(type, elem, 0);
}

function end_union() {
	union="";
	case="";
	switch="";
}

