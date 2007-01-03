/* ************************************************************************

   qooxdoo - the new era of web development

   http://qooxdoo.org

   Copyright:
     2004-2006 by 1&1 Internet AG, Germany, http://www.1and1.org

   License:
     LGPL 2.1: http://www.gnu.org/licenses/lgpl.html

   Authors:
     * Sebastian Werner (wpbasti)
     * Andreas Ecker (ecker)

************************************************************************ */

/* ************************************************************************

#module(ui_form)

************************************************************************ */

qx.OO.defineClass("qx.ui.form.List", qx.ui.layout.VerticalBoxLayout,
function()
{
  qx.ui.layout.VerticalBoxLayout.call(this);


  // ************************************************************************
  //   INITILISIZE MANAGER
  // ************************************************************************
  this._manager = new qx.manager.selection.SelectionManager(this);


  // ************************************************************************
  //   BEHAVIOR
  // ************************************************************************
  this.setSelectable(false);
  this.setTabIndex(1);


  // ************************************************************************
  //   MOUSE EVENT LISTENER
  // ************************************************************************
  this.addEventListener("mouseover", this._onmouseover);
  this.addEventListener("mousedown", this._onmousedown);
  this.addEventListener("mouseup", this._onmouseup);
  this.addEventListener("click", this._onclick);
  this.addEventListener("dblclick", this._ondblclick);


  // ************************************************************************
  //   KEY EVENT LISTENER
  // ************************************************************************
  this.addEventListener("keydown", this._onkeydown);
  this.addEventListener("keypress", this._onkeypress);
  this.addEventListener("keyinput", this._onkeyinput);
});

qx.OO.changeProperty({ name : "appearance", type : "string", defaultValue : "list" });

qx.OO.addProperty({ name : "enableInlineFind", type : "boolean", defaultValue : true });
qx.OO.addProperty({ name : "markLeadingItem", type : "boolean", defaultValue : false });

qx.Proto._pressedString = "";





/*
---------------------------------------------------------------------------
  MANAGER BINDING
---------------------------------------------------------------------------
*/

qx.Proto.getManager = function() {
  return this._manager;
}

qx.Proto.getListItemTarget = function(vItem)
{
  while (vItem != null && vItem.getParent() != this) {
    vItem = vItem.getParent();
  }

  return vItem;
}

qx.Proto.getSelectedItem = function() {
  return this.getSelectedItems()[0];
}

qx.Proto.getSelectedItems = function() {
  return this._manager.getSelectedItems();
}



/*
---------------------------------------------------------------------------
  MOUSE EVENT HANDLER
---------------------------------------------------------------------------
*/

qx.Proto._onmouseover = function(e)
{
  var vItem = this.getListItemTarget(e.getTarget());

  if (vItem) {
    this._manager.handleMouseOver(vItem, e);
  }
}

qx.Proto._onmousedown = function(e)
{
  var vItem = this.getListItemTarget(e.getTarget());

  if (vItem) {
    this._manager.handleMouseDown(vItem, e);
  }
}

qx.Proto._onmouseup = function(e)
{
  var vItem = this.getListItemTarget(e.getTarget());

  if (vItem) {
    this._manager.handleMouseUp(vItem, e);
  }
}

qx.Proto._onclick = function(e)
{
  var vItem = this.getListItemTarget(e.getTarget());

  if (vItem) {
    this._manager.handleClick(vItem, e);
  }
}

qx.Proto._ondblclick = function(e)
{
  var vItem = this.getListItemTarget(e.getTarget());

  if (vItem) {
    this._manager.handleDblClick(vItem, e);
  }
}




/*
---------------------------------------------------------------------------
  KEY EVENT HANDLER
---------------------------------------------------------------------------
*/

qx.Proto._onkeydown = function(e)
{
  // Execute action on press <ENTER>
  if (e.getKeyIdentifier() == "Enter" && !e.getAltKey())
  {
    var items = this.getSelectedItems();
    var currentItem;

    for (var i=0; i<items.length; i++) {
      items[i].createDispatchEvent("action");
    }
  }
};


qx.Proto._onkeypress = function(e)
{
  // Give control to selectionManager
  this._manager.handleKeyPress(e);
};


qx.Proto._lastKeyPress = 0;

qx.Proto._onkeyinput = function(e)
{
  if (!this.getEnableInlineFind()) {
    return;
  }

  // Reset string after a second of non pressed key
  if (((new Date).valueOf() - this._lastKeyPress) > 1000) {
    this._pressedString = "";
  }

  // Combine keys the user pressed to a string
  this._pressedString += String.fromCharCode(e.getCharCode());

  // Find matching item
  var matchedItem = this.findString(this._pressedString, null);

  if (matchedItem)
  {
    var oldVal = this._manager._getChangeValue();

    // Temporary disable change event
    var oldFireChange = this._manager.getFireChange();
    this._manager.setFireChange(false);

    // Reset current selection
    this._manager._deselectAll();

    // Update manager
    this._manager.setItemSelected(matchedItem, true);
    this._manager.setAnchorItem(matchedItem);
    this._manager.setLeadItem(matchedItem);

    // Scroll to matched item
    matchedItem.scrollIntoView();

    // Recover event status
    this._manager.setFireChange(oldFireChange);

    // Dispatch event if there were any changes
    if (oldFireChange && this._manager._hasChanged(oldVal)) {
      this._manager._dispatchChange();
    }
  }

  // Store timestamp
  this._lastKeyPress = (new Date).valueOf();
  e.preventDefault();
}




/*
---------------------------------------------------------------------------
  FIND SUPPORT
---------------------------------------------------------------------------
*/

qx.Proto._findItem = function(vUserValue, vStartIndex, vType)
{
  var vAllItems = this.getChildren();

  // If no startIndex given try to get it by current selection
  if (vStartIndex == null)
  {
    vStartIndex = vAllItems.indexOf(this.getSelectedItem());

    if (vStartIndex == -1) {
      vStartIndex = 0;
    }
  }

  var methodName = "matches" + vType;

  // Mode #1: Find all items after the startIndex
  for (var i=vStartIndex; i<vAllItems.length; i++) {
    if (vAllItems[i][methodName](vUserValue)) {
      return vAllItems[i];
    }
  }

  // Mode #2: Find all items before the startIndex
  for (var i=0; i<vStartIndex; i++) {
    if (vAllItems[i][methodName](vUserValue)) {
      return vAllItems[i];
    }
  }

  return null;
}

qx.Proto.findString = function(vText, vStartIndex) {
  return this._findItem(vText, vStartIndex || 0, "String");
}

qx.Proto.findStringExact = function(vText, vStartIndex) {
  return this._findItem(vText, vStartIndex || 0, "StringExact");
}

qx.Proto.findValue = function(vText, vStartIndex) {
  return this._findItem(vText, vStartIndex || 0, "Value");
}

qx.Proto.findValueExact = function(vText, vStartIndex) {
  return this._findItem(vText, vStartIndex || 0, "ValueExact");
}






/*
---------------------------------------------------------------------------
  SORT SUPPORT
---------------------------------------------------------------------------
*/

qx.Proto._sortItemsCompare = function(a, b) {
  return a.key < b.key ? -1 : a.key == b.key ? 0 : 1;
}

qx.Proto.sortItemsByString = function(vReverse)
{
  var sortitems = [];
  var items = this.getChildren();

  for(var i=0, l=items.length; i<l; i++) {
    sortitems[i] = { key : items[i].getLabel(), item : items[i] }
  }

  sortitems.sort(this._sortItemsCompare);
  if (vReverse) {
    sortitems.reverse();
  }

  for(var i=0; i<l; i++) {
    this.addAt(sortitems[i].item, i);
  }
}

qx.Proto.sortItemsByValue = function(vReverse)
{
  var sortitems = [];
  var items = this.getChildren();

  for(var i=0, l=items.length; i<l; i++) {
    sortitems[i] = { key : items[i].getValue(), item : items[i] }
  }

  sortitems.sort(this._sortItemsCompare);
  if (vReverse) {
    sortitems.reverse();
  }

  for(var i=0; i<l; i++) {
    this.addAt(sortitems[i].item, i);
  }
}









/*
---------------------------------------------------------------------------
  DISPOSER
---------------------------------------------------------------------------
*/

qx.Proto.dispose = function()
{
  if (this.getDisposed()) {
    return;
  }

  if (this._manager)
  {
    this._manager.dispose();
    this._manager = null;
  }

  this.removeEventListener("mouseover", this._onmouseover);
  this.removeEventListener("mousedown", this._onmousedown);
  this.removeEventListener("mouseup", this._onmouseup);
  this.removeEventListener("click", this._onclick);
  this.removeEventListener("dblclick", this._ondblclick);
  this.removeEventListener("keydown", this._onkeydown);
  this.removeEventListener("keypress", this._onkeypress);
  this.removeEventListener("keyinput", this._onkeyinput);

  return qx.ui.layout.VerticalBoxLayout.prototype.dispose.call(this);
}
