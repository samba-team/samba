function produce_harness(f,
			 LOCAL, v, struct_num, i)
{
	struct_num=structs[test];

	v["MODULE"]=module;

	print_template(f, "harness_start.tpl", v);

	for (i=0;i<num_tests;i++) {
		v["TEST"] = tests[i];
		print_template(f, "harness.tpl", v);
	}

	print_template(f, "harness_end.tpl", v);
}

function add_test(test)
{
	tests[num_tests] = test;
	num_tests++;
}
