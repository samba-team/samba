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

	helpPop = window.open(url, 'docsWindow', 'menubar=yes, resizeable=yes, scrollbars=yes, width=450px, height=530px, screenX='	+ String(left) + ', screenY=' + String(top));

	helpPop.focus();
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

function addTocTitle()
{
	var page = document.getElementsByTagName('body')[0];

	var tocTitle = document.createElement('div');
	tocTitle.setAttribute('id', 'toc');

	var helpHeading = document.createElement('h4');
	helpHeading.appendChild( document.createTextNode('SWAT Help | Documentation') );

	var hbar = document.createElement('hr');
	
	tocTitle.appendChild(helpHeading);
	tocTitle.appendChild(hbar);

	var topPage = page.firstChild;
	page.insertBefore(tocTitle, topPage);
}

/*********************************************************************
 Initialize help pages.
*********************************************************************/
window.onload = function initPage() 
{
	var page = document.getElementsByTagName('body')[0];

	if (location.href.indexOf('viewconfig') > -1) {
		formatHelp();
		page.style.visibility = 'visible';
	}

	if (location.href.indexOf('help') > -1) {
		formatHelp();
		addTocTitle();
		page.style.visibility = 'visible';
	}
}

