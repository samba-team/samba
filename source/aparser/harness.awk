function produce_harness(f,
			 LOCAL, v, struct_num)
{
	struct_num=structs[test];

	v["MODULE"]=module;
	v["TEST"]=test;
	v["TEST_FUNC"]=moduletest;
	v["STRUCTNAME"] = structs[struct_num, "name"];
	v["FUNCNAME"] = v["MODULE"] "_io_" v["STRUCTNAME"];

	print_template(f, "harness_start.tpl", v);
}
