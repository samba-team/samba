# tokenise the input file

function parse_error(msg) {
	printf("PARSE ERROR: %s\nLine "NR" : "$0"\n", msg);
	exit 1;
}

# ignore blank lines
/^[ \t]*$/ {
	next;
}

/^\#define.*;/ {
	split($0,a,"[ \t;]*");
	parse_define(a[2], a[3]);
	next;
}

# ignore comments
/^[ \t]*\#/ {
	next;
}

# ignore C comments
/^[ \t]*\/\*.*\*\// {
	next;
}

/^[ \t]*module/ {
	{if (module!="") parse_error("you can only specify one module name");}
	start_module($2);
	next;
}

{if (module=="") parse_error("you must specify the module name first");}

/^[ \t]*typedef struct.*\{/ {
	{if (current_struct!="") parse_error("you cannot have nested structures");}
	start_struct($3);
	next;
}

/^[ \t]*struct.*\{/ {
	{if (current_struct!="") parse_error("you cannot have nested structures");}
	start_struct($2);
	next;
}

{if (current_struct=="") parse_error("this must appear inside a structure");}

/^[ \t]*union.*\{/ {
	{if (current_union!="") parse_error("you cannot have nested unions");}
	start_union($2);
	next;
}

/^[ \t]*case.*;/ {
	{if (current_union=="") parse_error("this must appear inide a union");}
	split($0,a,"[ \t;]*");
	parse_case(a[3],a[4],a[5]);
	next;
}

/^[ \t]*\}$/ {
	{if (current_union=="") parse_error("this must appear inside a union");}
	end_union();
	next;
}

{if (current_union!="") parse_error("this cannot appear inside a union");}

/^[ \t]*\};/ {
	end_struct("");
	next;
}

/^[ \t]*\} .*;/ {
	split($2,a,"[ \t;]*");
	end_struct(a[1]);
	next;
}

/^.*;/ {
	split($0,a,"[ \t;]*");
	add_struct_elem(a[2], a[3]);
	next;
}

{
	parse_error("Unknown construct.");
}
