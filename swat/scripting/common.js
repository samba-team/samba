/*
	js functions and code common to all pages
*/

/* define some global variables for this request */
global.page = new Object();

/* fill in some defaults */
global.page.title = "Samba Web Administration Tool";


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
				"/images/linkpad.gif",
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
  display a simple menu. First argument is menu title, followed by
  pairs of menu item name and link
*/
function simple_menu() {
	write("<i>" + arguments[0] + "</i><br /><ul>\n");
	for (i = 1; i < arguments.length; i = i + 2) {
		write("<li><a href=\"" + arguments[i+1] + "\">" + arguments[i] + "</a></li>\n");
	}
	write("</ul>\n");
}
