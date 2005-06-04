/* 
  Demonstrate use of resolveName() js function
*/

var result;
res = resolveName(result, "frogurt");

if (!res.is_ok) {
	println(res.errstr);
} else {
	println(result);
}
