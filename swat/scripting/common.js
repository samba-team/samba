/*
	js functions and code common to all pages
*/

/* define some global variables for this request */
global.page = new Object();

/* fill in some defaults */
global.page.title = "Samba Web Administration Tool";

/* to cope with browsers that don't support cookies we append the sessionid
   to the URI */
global.SESSIONURI = "";
if (request['COOKIE_SUPPORT'] != "True") {
	global.SESSIONURI="?SwatSessionId=" + request['SESSION_ID'];
}

/*
  possibly adjust a local URI to have the session id appended
  used for browsers that don't support cookies
*/
function session_uri(uri) {
	return uri + global.SESSIONURI;
}

/*
  like printf, but to the web page
*/
function writef()
{
	write(vsprintf(arguments));
}

/*
  like writef with a <br>
*/
function writefln()
{
	write(vsprintf(arguments));
	write("<br/>\n");
}


/* if the browser was too dumb to set the HOST header, then
   set it now */
if (headers['HOST'] == undefined) {
	headers['HOST'] = server['SERVER_HOST'] + ":" + server['SERVER_PORT'];
}

/*
  show the page header. page types include "plain" and "column" 
*/
function page_header(pagetype, title) {
	global.page.pagetype = pagetype;
	global.page.title = title;
	include("/scripting/header_" + pagetype + ".esp");
}

/*
  show the page footer, getting the page type from page.pagetype
  set in page_header()
*/
function page_footer() {
	include("/scripting/footer_" + global.page.pagetype + ".esp");
}


/*
  check if a uri is one of the 'always allowed' pages, even when not logged in
  This allows the login page to use the same style sheets and images
*/
function always_allowed(uri) {
	var allowed = new Array("/images/favicon.ico", 
				"/images/linkpad.png",
				"/images/logo.png",
				"/style/main.css",
				"/style/common.css");
	for (i in allowed) {
		if (allowed[i] == uri) {
			return true;
		}
	}
	return false;
}

/*
  create a menu object with the defaults filled in, ready for display_menu()
 */
function MenuObj(name, num_elements)
{
	var o = new Object();
	o.name = name;
	o.class = "menu";
	o.style = "simple";
	o.orientation = "vertical"
	o.element = new Array(num_elements);
	for (i in o.element) {
		o.element[i] = new Object();
	}
	return o;
}

/*
  display a menu object. Currently only the "simple", "vertical" menu style
  is supported
*/
function display_menu(m) {
	assert(m.style == "simple" && m.orientation == "vertical");
	write('<div class="' + m.class + '">\n');
	write("<i>" + m.name + "</i><br /><ul>\n");
	for (i = 0; i < m.element.length; i++) {
		var e = m.element[i];
		write("<li><a href=\"" + e.link + "\">" + e.label + "</a></li>\n");
	}
	write("</ul></div>\n");
}

function simple_menu() {
	var i, m = MenuObj(arguments[0], (arguments.length-1)/2);
	for (i=0;i<m.element.length;i++) {
		var ndx = i*2;
		m.element[i].label = arguments[ndx+1];
		m.element[i].link = arguments[ndx+2];
	}
	display_menu(m);
}

/*
  display a table element
*/
function table_element(i, o) {
	write("<tr><td>" + i + "</td><td>");
	if (typeof(o[i]) == "object") {
		var j, first;
		first = true;
		for (j in o[i]) {
			if (first == false) {
				write("<br />");
			}
			write(o[i][j]);
			first = false;
		}
	} else {
		write(o[i]);
	}
	write("</td></tr>\n");
}

/*
  display a ejs object as a table. The header is optional
*/
function simple_table(v) {
	if (v.length == 0) {
		return;
	}
	write("<table class=\"data\">\n");
	var r;
	for (r in v) {
		table_element(r, v);
	}
	write("</table>\n");
}

/*
  display an array of objects, with the header for each element from the given 
  attribute
*/
function multi_table(array, header) {
	var i, n;
	write("<table class=\"data\">\n");
	for (i=0;i<array.length;i++) {
		var r, v = array[i];
		write('<tr><th colspan="2">' + v[header] + "</th></tr>\n");
		for (r in v) {
			if (r != header) {
			    table_element(r, v);
			}
		}
	}
	write("</table>\n");
}

/*
  create a Form object with the defaults filled in, ready for display_form()
 */
function FormObj(name, num_elements, num_submits)
{
	var f = new Object();
	f.name = name;
	f.element = new Array(num_elements);
	f.submit =  new Array(num_submits);
	f.action = session_uri(request.REQUEST_URI);
	f.class = "defaultform";
	for (i in f.element) {
		f.element[i] = new Object();
		f.element[i].type = "text";
		f.element[i].value = "";
	}
	return f;
}

/*
  display a simple form from a ejs Form object
  caller should fill in
    f.name          = form name
    f.action        = action to be taken on submit (optional, defaults to current page)
    f.class         = css class (optional, defaults to 'form')
    f.submit        = an array of submit labels
    f.element[i].label = element label
    f.element[i].name  = element name (defaults to label)
    f.element[i].type  = element type (defaults to text)
    f.element[i].value = current value (optional, defaults to "")
 */
function display_form(f) {
	var i, size = 20;
	write('<form name="' + f.name +
	      '" method="post" action="' + f.action + 
	      '" class="' + f.class + '">\n');
	if (f.element.length > 0) {
		write("<table>\n");
	}
	for (i in f.element) {
		var e = f.element[i];
		if (e.name == undefined) {
			e.name = e.label;
		}
		if (e.value == undefined) {
			e.value = "";
		}
		if (strlen(e.value) > size) {
			size = strlen(e.value) + 4;
		}
	}
	for (i in f.element) {
		var e = f.element[i];
		write("<tr>");
		write("<td>" + e.label + "</td>");
		if (e.type == "select") {
			write('<td><select name="' + e.name + '">\n');
			for (s in e.list) {
				if (e.value == e.list[s]) {
					write('<option selected=selected>' + e.list[s] + '</option>\n');
				} else {
					write('<option>' + e.list[s] + '</option>\n');
				}
			}
			write('</select></td>\n');
		} else {
			var sizestr = "";
			if (e.type == "text" || e.type == "password") {
				sizestr = sprintf('size="%d"', size);
			}
			writef('<td><input name="%s" type="%s" value="%s" %s /></td>\n',
			       e.name, e.type, e.value, sizestr);
		}
		write("</tr>");
	}
	if (f.element.length > 0) {
		write("</table>\n");
	}
	for (i in f.submit) {
		write('<input name="submit" type="submit" value="' + f.submit[i] + '" />\n');
	}
	write("</form>\n");
}

