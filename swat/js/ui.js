/*
  UI customizing functions for SWAT.
  Copyright (C) Deryck Hodge 2005

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/


var page = document.getElementsByTagName('body')[0];

function openHelp(url) 
{
	if ( (screen.width - 50) >= (window.screenX + window.outerWidth + 100) ) {
		left = (screenX + outerWidth) - 350;
	} else {
		left = screen.width - 450;
	}

	if ((screenY - 50) > 0 ) {
		top = screenY - 50; 
	} else {
		top = 0;
	}

	window.open(url, 'helpPop', 'menubar=yes, resizeable=yes, scrollbars=yes, width=450px, height=530px, screenX='	+ String(left) + ', screenY=' + String(top));
}

function formatHelp() 
{
	var banner = document.getElementById('banner');
	var nav = document.getElementById('nav')
	var footer = document.getElementById('footer');
	var mainStyle = document.getElementsByTagName('link')[1];

	// Hide elements as extra-precaution against flicker
	banner.style.display = 'none';
	nav.style.display = 'none';
	footer.style.display = 'none';

	var altLink = document.createElement('link');
	altLink.setAttribute('rel', 'stylesheet');
	altLink.setAttribute('href', '/swat/include/help.css');
	altLink.setAttribute('type', 'text/css');
	altLink.setAttribute('media', 'screen');

	var head = document.getElementsByTagName('head')[0];
	head.removeChild(mainStyle);
	head.appendChild(altLink);
}

function hidePage(page, state)
{
	if (state == 'on') {
		page.style.visibility = 'hidden';
	} else if (state == 'off') {
		page.style.visibility = 'visible';
	}
}

function catchHardReload(event)
{
	if (event.ctrlKey && event.which == 82) {
		setCookie();
	}
}

function setCookie()
{
	document.cookie = "SWATHardReload=TRUE";
}

function deleteCookie()
{
	document.cookie = document.cookie + ";expires=Thu, 24-Jan-1972 00:00:01 GMT";
}


/*********************************************************************
 Initialize each page.
*********************************************************************/
window.onload = function initPage(e) 
{
	window.captureEvents(Event.KEYPRESS);
	window.onkeypress = catchHardReload;
	
	if (location.href.indexOf('help') > -1 || location.href.indexOf('viewconfig') > -1) {
		// Init iframe for file loads
		setStage();

		if (document.cookie != '') { 
			hidePage(page, 'on');
			setTimeout('formatHelp()', 100);
			setTimeout('hidePage(page, "off")', 150);
			deleteCookie();
		} else {
			formatHelp();
		}
	}
}

