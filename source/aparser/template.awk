# template file handling

function print_template(f, tplname, v,
			LOCAL, i, pat, line)
{
	tplname="templates/"tplname;
	if (numlines(tplname) <= 0) fatal("no template "tplname);
	while ((getline line < tplname) > 0) {
		while ((i = match(line,"@[a-zA-Z_]*@")) != 0) {
			pat=substr(line,i+1,RLENGTH-2);
			if (v[pat] == "") fatal("no value for "pat" in "tplname);
			gsub("@"pat"@", v[pat], line);
		}
		
		xprintf(f, "%s\n", line);
	}
	close(tplname);
}
