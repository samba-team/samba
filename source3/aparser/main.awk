# the main program

@include dump.awk
@include parsetree.awk
@include header.awk
@include util.awk
@include template.awk
@include parsefn.awk
@include harness.awk

/^module/ {
	start_module($2);
	next;
}

/^test/ {
	add_test($2);
	next;
}

/^struct.*\{/ {
	start_struct($2);
	next;
}

/^[ \t]*union.*\{/ {
	start_union($2);
	next;
}

/^[ \t]*case.*;/ {
	split($0,a,"[ \t;]*");
	parse_case(a[3],a[4],a[5]);
	next;
}

/^\};/ {
	end_struct();
	next;
}

/^[ \t]*\}/ {
	end_union();
	next;
}

/.*;/ {
	split($0,a,"[ \t;]*");
	add_struct_elem(a[2], a[3]);
}

END {
	dump_structs("debug.out");
	produce_headers("prs_"module".h");
	produce_parsers("prs_"module".c");
	produce_harness("test.h");
}
