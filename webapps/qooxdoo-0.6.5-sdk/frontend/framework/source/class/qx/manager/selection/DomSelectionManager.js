/* ************************************************************************

   qooxdoo - the new era of web development

   http://qooxdoo.org

   Copyright:
     2004-2007 1&1 Internet AG, Germany, http://www.1and1.org

   License:
     LGPL: http://www.gnu.org/licenses/lgpl.html
     EPL: http://www.eclipse.org/org/documents/epl-v10.php
     See the LICENSE file in the project's top-level directory for details.

   Authors:
     * Sebastian Werner (wpbasti)
     * Andreas Ecker (ecker)

************************************************************************ */

/* ************************************************************************


************************************************************************ */

qx.OO.defineClass("qx.manager.selection.DomSelectionManager", qx.manager.selection.SelectionManager,
function(vBoundedWidget)
{
  qx.manager.selection.SelectionManager.call(this, vBoundedWidget);

  // the children does not fire onmouseover events so we could
  // not enable this and make it functional
  this.setDragSelection(false);

  this._selectedItems.getItemHashCode = this.getItemHashCode;
});



/*
---------------------------------------------------------------------------
  MAPPING TO BOUNDED WIDGET (DOM NODES)
---------------------------------------------------------------------------
*/

qx.Proto.getItemEnabled = function(oItem) {
  return true;
}

qx.Proto.getItemClassName = function(vItem) {
  return vItem.className || "";
}

qx.Proto.setItemClassName = function(vItem, vClassName) {
  return vItem.className = vClassName;
}

qx.Proto.getItemBaseClassName = function(vItem)
{
  var p = vItem.className.split(" ")[0];
  return p ? p : "Status";
}

qx.Proto.getNextSibling = function(vItem) {
  return vItem.nextSibling;
}

qx.Proto.getPreviousSibling = function(vItem) {
  return vItem.previousSibling;
}

qx.Proto.getFirst = function() {
  return this.getItems()[0];
}

qx.Proto.getLast = function()
{
  var vItems = this.getItems();
  return vItems[vItems.length-1];
}





/*
---------------------------------------------------------------------------
  MAPPING TO ITEM DIMENSIONS
---------------------------------------------------------------------------
*/

qx.Proto.getItemLeft = function(vItem) {
  return vItem.offsetLeft;
}

qx.Proto.getItemTop = function(vItem) {
  return vItem.offsetTop;
}

qx.Proto.getItemWidth = function(vItem) {
  return vItem.offsetWidth;
}

qx.Proto.getItemHeight = function(vItem) {
  return vItem.offsetHeight;
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

qx.Proto.isBefore = function(vItem1, vItem2)
{
  var pa = vItem1.parentNode;

  for (var i=0, l=pa.childNodes.length; i<l; i++)
  {
    switch(pa.childNodes[i])
    {
      case vItem2:
        return false;

      case vItem1:
        return true;
    }
  }
}

qx.Proto.scrollItemIntoView = function(vItem) {
  this.getBoundedWidget().scrollItemIntoView(vItem);
}

qx.Proto.getItems = function() {
  return this.getBoundedWidget().getItems();
}

qx.Proto.getAbove = function(vItem)
{
  var vParent = vItem.parentNode;
  var vFound = false;
  var vLeft = vItem.offsetLeft;
  var vChild;

  for (var i=vParent.childNodes.length-1; i>0; i--)
  {
    vChild = vParent.childNodes[i];

    if (vFound == false)
    {
      if (vChild == vItem) {
        vFound = true;
      }
    }
    else
    {
      if (vChild.offsetLeft == vLeft)
      {
        return vChild;
      }
    }
  }
}

qx.Proto.getUnder = function(vItem)
{
  var vParent = vItem.parentNode;
  var vFound = false;
  var vLeft = vItem.offsetLeft;
  var vChild;

  for (var i=0, l=vParent.childNodes.length; i<l; i++)
  {
    vChild = vParent.childNodes[i];

    if (vFound == false)
    {
      if (vChild == vItem) {
        vFound = true;
      }
    }
    else
    {
      if (vChild.offsetLeft == vLeft)
      {
        return vChild;
      }
    }
  }
}














/*
---------------------------------------------------------------------------
  ITEM CSS STATE MANAGMENT
---------------------------------------------------------------------------
*/

qx.Proto._updateState = function(vItem, vState, vIsState)
{
  var c = this.getItemClassName(vItem);
  var n = this.getItemBaseClassName(vItem) + "-" + vState;

  this.setItemClassName(vItem, vIsState ? qx.lang.String.addListItem(c, n, " ") : qx.lang.String.removeListItem(c, n, " "));
}

qx.Proto.renderItemSelectionState = function(vItem, vIsSelected) {
  this._updateState(vItem, "Selected", vIsSelected);
}

qx.Proto.renderItemAnchorState = function(vItem, vIsAnchor) {
  this._updateState(vItem, "Anchor", vIsAnchor);
}

qx.Proto.renderItemLeadState = function(vItem, vIsLead) {
  this._updateState(vItem, "Lead", vIsLead);
}
