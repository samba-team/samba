@include basic.awk
@include struct.awk
@include union.awk
@include func.awk

function produce_preamble() {
	printf("#define TEST_STRUCT %s\n", struct_name);
	printf("#define TEST_FUNC %s\n", func_name);
	printf("#define TEST_NAME \"%s\"\n", func_name);
	printf("\n\n");
}


/^module/ {
	module=$2;
	next;
}

/^test/ {
	test=$2;
	next;
}

/^struct/ {
	start_struct($2);
	next;
}

/^[ \t]*union/ {
	start_union($2, $3);
	next;
}

/^[ \t]*case/ {
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

/^[ \t]*REF/ {
	split($0,a,"[ \t;]*");
	add_elem(a[3],a[4], 1);
	next;
}

/.*;/ {
	split($0,a,"[ \t;]*");
	add_elem(a[2], a[3], 0);
}
