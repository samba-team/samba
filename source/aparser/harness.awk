function produce_harness(f,
			 LOCAL, v, struct_num, i)
{
	struct_num=structs[test];

	v["MODULE"]=module;

	print_template(f, "harness_start.tpl", v);

	for (i=0;i<num_structs;i++) {
		v["TEST"] = structs[i, "name"];
		print_template(f, "harness.tpl", v);
	}

	print_template(f, "harness_end.tpl", v);
}

