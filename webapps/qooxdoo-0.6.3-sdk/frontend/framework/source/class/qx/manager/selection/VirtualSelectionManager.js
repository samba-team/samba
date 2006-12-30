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

#module(ui_listview)

************************************************************************ */

/*!
  This class represents a selection and manage incoming events for widgets which need selection support.
*/
qx.OO.defineClass("qx.manager.selection.VirtualSelectionManager", qx.manager.selection.SelectionManager,
function(vBoundedWidget) {
  qx.manager.selection.SelectionManager.call(this, vBoundedWidget);
});





/*
---------------------------------------------------------------------------
  MAPPING TO BOUNDED WIDGET
---------------------------------------------------------------------------
*/

qx.Proto.getFirst = function() {
  return qx.lang.Array.getFirst(this.getItems());
}

qx.Proto.getLast = function() {
  return qx.lang.Array.getLast(this.getItems());
}

qx.Proto.getItems = function() {
  return this.getBoundedWidget().getData();
}

qx.Proto.getNextSibling = function(vItem)
{
  var vData = this.getItems();
  return vData[vData.indexOf(vItem)+1];
}

qx.Proto.getPreviousSibling = function(vItem)
{
  var vData = this.getItems();
  return vData[vData.indexOf(vItem)-1];
}




/*
---------------------------------------------------------------------------
  MAPPING TO ITEM PROPERTIES
---------------------------------------------------------------------------
*/

qx.Proto.getItemHashCode = function(oItem)
{
  if (oItem._hash) {
    return oItem._hash;
  }

  return oItem._hash = qx.core.Object.toHashCode(oItem);
}





/*
---------------------------------------------------------------------------
  MAPPING TO ITEM DIMENSIONS
---------------------------------------------------------------------------
*/

qx.Proto.scrollItemIntoView = function(vItem, vTopLeft) {
  this.getBoundedWidget().scrollItemIntoView(vItem, vTopLeft);
}

qx.Proto.getItemLeft = function(vItem) {
  return this.getBoundedWidget().getItemLeft(vItem);
}

qx.Proto.getItemTop = function(vItem) {
  return this.getBoundedWidget().getItemTop(vItem);
}

qx.Proto.getItemWidth = function(vItem) {
  return this.getBoundedWidget().getItemWidth(vItem);
}

qx.Proto.getItemHeight = function(vItem) {
  return this.getBoundedWidget().getItemHeight(vItem);
}

/*!
  In a qx.ui.listview.ListView there are no disabled entries support currently.
*/
qx.Proto.getItemEnabled = function(vItem) {
  return true;
}






/*
---------------------------------------------------------------------------
  ITEM STATE MANAGMENT
---------------------------------------------------------------------------
*/

qx.Proto.renderItemSelectionState = function(vItem, vIsSelected) {
  this.getBoundedWidget()._updateSelectionState(vItem, vIsSelected);
}

qx.Proto.renderItemAnchorState = function(vItem, vIsAnchor) {
  this.getBoundedWidget()._updateAnchorState(vItem, vIsAnchor);
}

qx.Proto.renderItemLeadState = function(vItem, vIsLead) {
  this.getBoundedWidget()._updateLeadState(vItem, vIsLead);
}
