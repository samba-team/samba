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

function addTocNav()
{
	var page = document.getElementsByTagName('body')[0];
	var docList = document.getElementById('controls');

	// Create "back" link on the fly
	var toc = document.createElement('p');
	var link = document.createElement('a');
	link.setAttribute('href', 'help');
	var linkText = document.createTextNode('Return to Help Menu');
	link.appendChild(linkText);
	toc.appendChild(link);

	// Add "back" link to top of the page
	var pageTop = page.firstChild;
	page.insertBefore(toc, pageTop);
	
	// Remove the docs list when done
	var docListKids = docList.childNodes

	for (i=docListKids.length - 2; i>=0; i--) {
		docList.removeChild(docListKids[i]);
	}
}


/*********************************************************************
 Initialize each page.
*********************************************************************/
window.onload = function initPage() 
{
	var page = document.getElementsByTagName('body')[0];

	if (location.href.indexOf('viewconfig') > -1) {
		formatHelp();
		page.style.visibility = 'visible';
	}

	if (location.href.indexOf('help') > -1 ) {
		// Init iframe for file loads
		setStage();
		formatHelp();
		page.style.visibility = 'visible';
	}
}

