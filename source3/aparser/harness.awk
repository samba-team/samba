function produce_harness(f,
			 LOCAL, v, struct_num)
{
	struct_num=structs[test];

	v["MODULE"]=module;
	v["TEST"]=test;
	v["TEST_FUNC"]=moduletest;
	v["STRUCTNAME"] = structs[struct_num, "name"];
	v["FUNCNAME"] = "io_" v["STRUCTNAME"];

	print_template(f, "harness_start.tpl", v);
}
