/*
 Simulate a file read from server within the browser.
 Copyright (C) Deryck Hodge 2005

 Example usage: onclick="loadDoc(this.href, TARGET)"
 where target is id of the element to append to, or 'page'
 to mean the current document.

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


// Create iframe off page
function setStage()
{
	// Don't declare page as local to this function
	page = document.getElementsByTagName('body')[0];

	var sandbox = document.createElement('iframe');
	sandbox.setAttribute('name', 'stage');
	sandbox.setAttribute('id', 'stage');
	page.appendChild(sandbox);

	// Don't declare this one local, either
	curtain = document.getElementById('stage');
	curtain.style.position = 'absolute';
	curtain.style.top = '-1200px';
}

// Load the file in iframe
function loadStage(url)
{
	stage.document.location.href = url;
}

// Cut nodes from iframe and paste into document
function getPage(target)
{
	var doc;
	var section;

	// Establish file type and nodes to get
	if (stage.document.firstChild.nodeName.toLowerCase() == 'html') {
		doc = stage.document.getElementsByTagName('body')[0];
	} else {
		doc = stage.document;
	}

	var kids = doc.childNodes;	
	var allNodes = kids.length;
	var elements = new Array;

	for (i=allNodes-1; i>=0; i--) {
		elements[i] = doc.removeChild(kids[i]);
	}
	
	if (!target.nodeName) {
		// Ensure target exists before appending to it
		if (!document.getElementById(target)) {
			var div = document.createElement('div');
			div.setAttribute('id', target);
			// Use CSS to position as needed, or change to 
			// page.insertBefore(div, targetElement);
			page.appendChild(div);
		} 
		section = document.getElementById(target);
	} else {
		section = target;
	}
		
	for (i=0; i<=allNodes-1; i++) {
		section.appendChild(elements[i]);
	}
}

function removeLink(url)
{
	var allLinks = document.getElementsByTagName('a')
	
	for (i=0; i<=allLinks.length; i++) {
		if (allLinks[i].href == url) {
			visitedLink = allLinks[i];
		}
	}
	
	page.removeChild(visitedLink);
}

// Ensure iframe has finished loading before cut-n-paste
function checkStage(target)
{
	if ( (stage.document.getElementsByTagName('body')[0]) && (stage.document.getElementsByTagName('body')[0].childNodes.length >= 1) ) {
		getPage(target);
		page.removeChild(curtain)
		clearInterval(docCheck);
	}
}

// Wrap functions in a single call to be made from webpage
function loadDoc(url, id)
{
	var target;

	// Pass id as quoted string if not 'page'
	if (id == 'page') {
		target = id;
	} else {
		target = "'" + id + "'";
	}

	loadStage(url);
	// Ensure new page has loaded
	docCheck = setInterval("checkStage(" + target + ")", 50);
}

