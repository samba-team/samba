# tokenise the input file

function parse_error(msg) {
	printf("PARSE ERROR: %s\nLine "NR" : "$0"\n", msg);
	exit 1;
}

# ignore multi-line C comments.
{
  if (t = index($0, "/*")) {
    if (t > 1)
      tmp = substr($0, 1, t - 1)
    else
      tmp = ""
    u = index(substr($0, t + 2), "*/")
    while (u == 0) {
      getline
      t = -1
      u = index($0, "*/")
    }
    if (u <= length($0) - 2)
      $0 = tmp substr($0, t + u + 3)
    else
      $0 = tmp
  }
}

# ignore blank lines
/^[ \t]*$/ {
	next;
}

/^\#define.*/ {
	split($0,a,"[ \t;]*");
	parse_define(a[2], a[3]);
	next;
}

# ignore comments
/^[ \t]*\#/ {
	next;
}

/^[ \t]*module/ {
	{if (module!="") parse_error("you can only specify one module name");}
	start_module($2);
	next;
}

{if (module=="") parse_error("you must specify the module name first");}

/^[ \t]*option/ {
	set_option($2, $3);
	next;
}

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

/^[ \t]*typedef union.*\{/ {
	{if (current_struct!="") parse_error("this cannot appear inside a structure");}
	split($0,a,"[ \t;()]*");
	start_union_encap(a[4], a[6], a[7], a[8]);
	next;
}

/^[ \t]*void.*\(/ {
	{if (current_struct!="") parse_error("you cannot have nested structures");}
	split($0,a,"[ \t;()]*");
	start_function(a[2], a[3]);
	return_result="void";
	next;
}

/^[ \t]*STATUS.*\(|^[ \t]*void.*\(/ {
	{if (current_struct!="") parse_error("you cannot have nested structures");}
	split($0,a,"[ \t;()]*");
	start_function(a[2], a[3]);
	return_result="STATUS";
	next;
}

{if (current_struct=="") parse_error("this must appear inside a structure");}

/^[ \t]*union.*\{/ {
	{if (current_union!="") parse_error("you cannot have nested unions");}
	start_union($2);
	next;
}

/^[ \t]*\[switch_is.*union.*\{/ {
	{if (current_union!="") parse_error("you cannot have nested unions");}
	split($0,a,"[ \t;()]*");
	start_union_notencap(a[3]);
	next;
}

/^[ \t]*case.*;/ {
	{if (current_union=="") parse_error("this must appear inide a union");}
	split($0,a,"[ \t;]*");
	parse_case(a[3],a[4],a[5]);
	next;
}

/^[ \t]*\[case(.*)\].*;/ {
	{if (current_union=="") parse_error("this must appear inide a union");}
	split($0,a,"[ \t;()[\]]*");
	parse_case(a[6],a[8],a[9]);
	next;
}

/^[ \t]*\}$/ {
	{if (current_union=="") parse_error("this must appear inside a union");}
	end_union("");
	next;
}

/^[ \t]*\} .*;/ {
	if (current_union!="") {
		split($2,a,"[ \t;]*");
		end_union(a[1]);
		next;
	}
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

/^[ \t]*\);/ {
	end_function();
	return_result="";
	next;
}

/^.*size_is.*\*.*;/ {
	split($0,a,"[ \t;()]*");
	add_sizeis_array(a[3], a[5], a[6]);
	next;
}

/^.*;/ {
	split($0,a,"[ \t;]*");
	add_struct_elem(a[2], a[3]);
	next;
}

/^[\t ]*void/ {
	next;
}

/^[ \t]*\[.*\].*/ {
	split($0,a,"[ \t;]*");
	split(a[4], b, "[,]");
	add_function_param(a[2], a[3], b[1]);
	next;
}

{
	parse_error("Unknown construct.");
}

