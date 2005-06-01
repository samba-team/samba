/* show a menu for the docs directory */
var m = MenuObj("Samba Information", 9);

m.element[0].label = "Samba4 development";
m.element[0].link  = "http://devel.samba.org/";
m.element[1].label = "Recent Checkins";
m.element[1].link  = "http://build.samba.org/?tree=samba4;function=Recent+Checkins";
m.element[2].label = "Recent Builds";
m.element[2].link  = "http://build.samba.org/?tree=samba4;function=Recent+Builds";
m.element[3].label = "EJS Information";
m.element[3].link  = "http://www.appwebserver.org/products/ejs/ejs.html";
m.element[4].label = "ESP Information";
m.element[4].link  = "http://www.appwebserver.org/products/esp/esp.html";
m.element[5].label = "XHTML Spec";
m.element[5].link  = "http://www.w3.org/TR/xhtml1/";
m.element[6].label = "JavaScript Spec";
m.element[6].link  = "http://www.ecma-international.org/publications/files/ecma-st/ECMA-262.pdf";
m.element[7].label = "CSS Specs";
m.element[7].link = "http://www.w3.org/Style/CSS/#specs";
m.element[8].label = "CSS1/2 Reference";
m.element[8].link  = "http://www.w3schools.com/css/css_reference.asp";

display_menu(m);

