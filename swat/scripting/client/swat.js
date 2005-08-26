/*
   Windows, tabs, and general widgetry for SWAT.

   Copyright (C) Deryck Hodge 2005
   released under the GNU GPL Version 2 or later
*/


/* Qooxdoo's browser sniffer doesn't distinguish IE version.
We'll cover IE 6 for now, but these checks need to be
revisited for fuller browser coverage. */
var browser = QxClient().engine;

function docX()
{
	var x;
	if (browser != "mshtml") {
		x = window.innerWidth;
	} else {
		x = document.documentElement.clientWidth;
	}
	return x;
}

function docY()
{
	var y;
	// Less 25px to not cover the toolbar
	if (browser != "mshtml") {
		y = window.innerHeight - 25;
	} else {
		y = document.documentElement.clientHeight;
	}
	return y;
}

function sizeX()
{
	var sX = Math.floor(docX() * .45);
	return sX;
}

function sizeY()
{
	var sY = Math.floor(docY() * .45);
	return sY;
}

function getPosX()
{
	var y = Math.floor( (docY() - sizeY()) * Math.random() );
	return y;
}

function getPosY()
{
	var x = Math.floor( (docX() - sizeX()) * Math.random() );
	return x;
}

function openIn(e)
{
	var blank = new Window("New Menu");
	e.add(blank);
	blank.setVisible(true);
}
	
function winMenu(e)
{
	var self = this;
	var WinWin = new QxCommand();
	WinWin.addEventListener("execute", function() {
		var blank = new QxWindow();
		self.add(blank);
		blank.setVisible(true);
	}); 

	var inset = new QxMenu;
	var sub1 = new QxMenuButton("Open window in a window", null, WinWin);

	inset.add(sub1);
	self.add(inset)

	cmenu.setVisible(false);
	inset.setVisible(true);
}

function Window(title)
{
	var self = new QxWindow(title);
	self.setTop(getPosX());
	self.setLeft(getPosY());
	self.setMinWidth(sizeX());
	self.setMinHeight(sizeY());
	self.addEventListener("contextmenu", winMenu);
	return self;
}


