function isaptr(elem) 
{
	if (substr(elem, 1, 1) == "*") {
		return 1;
	}
	return 0;
}

function noptr(elem) 
{
	if (!isaptr(elem)) return elem;
	return substr(elem, 2);
}

function xprintf(f, fmt, v1, v2, v3, v4, v5, v6, v7)
{
	printf(fmt, v1, v2, v3, v4, v5, v6) > f;
}

function fatal(why)
{
	printf("FATAL: %s\n", why);
	exit 1;
}

function numlines(fname,
		  LOCAL, line, count)
{
	count=0;
	while ((getline line < fname) > 0) count++;
	close(fname);
	return count;
}

# return 1 if the string is a constant
function is_constant(s) 
{
    return match(s,"^[0-9]+$");
}
