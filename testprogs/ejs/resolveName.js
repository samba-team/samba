/* 
  Demonstrate use of resolveName() js function
*/

var result = new Object();

res = resolveName(result, ARGV[0]);

if (res.is_ok) {
	println(result.value);
} else {
	println(res.errstr);
}
