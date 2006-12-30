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

#module(ui_tree)

************************************************************************ */

qx.OO.defineClass("qx.ui.tree.TreeFolder", qx.ui.tree.AbstractTreeElement,
function(vLabel, vIcon, vIconSelected)
{
  qx.ui.tree.AbstractTreeElement.call(this, vLabel, vIcon, vIconSelected);

  this._iconObject.setAppearance("tree-folder-icon");
  this._labelObject.setAppearance("tree-folder-label");

  this.addEventListener("dblclick", this._ondblclick);

  // Remapping of add/remove methods
  this.add = this.addToFolder;
  this.addBefore = this.addBeforeToFolder;
  this.addAfter = this.addAfterToFolder;
  this.addAt = this.addAtToFolder;
  this.addAtBegin = this.addAtBeginToFolder;
  this.addAtEnd = this.addAtEndToFolder;
  this.remove = this.removeFromFolder;
});



/*
---------------------------------------------------------------------------
  PROPERTIES
---------------------------------------------------------------------------
*/


qx.OO.changeProperty({ name : "appearance", type : "string", defaultValue : "tree-folder" });
qx.OO.changeProperty({ name : "icon", type : "string" });
qx.OO.changeProperty({ name : "iconSelected", type : "string" });

qx.OO.addProperty({ name : "open", type : "boolean", defaultValue : false });
qx.OO.addProperty({ name : "alwaysShowPlusMinusSymbol", type : "boolean", defaultValue : false });




/*
---------------------------------------------------------------------------
  UTILITIES
---------------------------------------------------------------------------
*/

qx.Proto.hasContent = function() {
  return this._containerObject && this._containerObject.getChildrenLength() > 0;
}

qx.Proto.open = function()
{
  if (this.getOpen()) {
    return;
  }

  if (this.hasContent() && this.isSeeable())
  {
    this.getTopLevelWidget().setGlobalCursor("progress");
    qx.client.Timer.once(this._openCallback, this, 0);
  }
  else
  {
    this.setOpen(true);
  }
}

qx.Proto.close = function() {
  this.setOpen(false);
}

qx.Proto.toggle = function() {
  this.getOpen() ? this.close() : this.open();
}

qx.Proto._openCallback = function()
{
  this.setOpen(true);
  qx.ui.core.Widget.flushGlobalQueues();
  this.getTopLevelWidget().setGlobalCursor(null);
}








/*
---------------------------------------------------------------------------
  CHILDREN HANDLING
---------------------------------------------------------------------------
*/

qx.Proto._createChildrenStructure = function()
{
  this.setAppearance(this instanceof qx.ui.tree.Tree ? "tree-container" : "tree-folder-container");

  if (!this._horizontalLayout)
  {
    this.setOrientation("vertical");

    this._horizontalLayout = new qx.ui.layout.HorizontalBoxLayout;
    this._horizontalLayout.setWidth(null);
    this._horizontalLayout.setParent(this);
    this._horizontalLayout.setAnonymous(true);
    this._horizontalLayout.setAppearance(this instanceof qx.ui.tree.Tree ? "tree" : "tree-folder");

    this._indentObject.setParent(this._horizontalLayout);
    this._iconObject.setParent(this._horizontalLayout);
    this._labelObject.setParent(this._horizontalLayout);
  }

  if (!this._containerObject)
  {
    this._containerObject = new qx.ui.layout.VerticalBoxLayout;
    this._containerObject.setWidth(null);
    this._containerObject.setAnonymous(true);

    // it should be faster to first handle display,
    // because the default display value is true and if we first
    // setup the parent the logic do all to make the
    // widget first visible and then, if the folder is not
    // opened again invisible.
    this._containerObject.setDisplay(this.getOpen());
    this._containerObject.setParent(this);

    // remap remove* functions
    this.remapChildrenHandlingTo(this._containerObject);
  }
}

qx.Proto._handleChildMove = function(vChild, vRelationIndex, vRelationChild)
{
  if (vChild.isDisplayable())
  {
    var vChildren = this._containerObject.getChildren();
    var vOldChildIndex = vChildren.indexOf(vChild);

    if (vOldChildIndex != -1)
    {
      if (vRelationChild) {
        vRelationIndex = vChildren.indexOf(vRelationChild);
      }

      if (vRelationIndex == vChildren.length-1)
      {
        vChild._updateIndent();

        // Update indent of previous last child
        this._containerObject.getLastVisibleChild()._updateIndent();
      }
      else if (vChild._wasLastVisibleChild)
      {
        vChild._updateIndent();

        // Update indent for new last child
        var vPreviousSibling = vChild.getPreviousVisibleSibling();
        if (vPreviousSibling) {
          vPreviousSibling._updateIndent();
        }
      }
    }
  }
}

qx.Proto.addToFolder = function()
{
  this._createChildrenStructure();

  if (this._containerObject) {
    return this._containerObject.add.apply(this._containerObject, arguments);
  }
}

qx.Proto.addBeforeToFolder = function(vChild, vBefore)
{
  this._createChildrenStructure();

  if (this._containerObject)
  {
    this._handleChildMove(vChild, null, vBefore);
    return this._containerObject.addBefore.apply(this._containerObject, arguments);
  }
}

qx.Proto.addAfterToFolder = function(vChild, vAfter)
{
  this._createChildrenStructure();

  if (this._containerObject)
  {
    this._handleChildMove(vChild, null, vAfter);
    return this._containerObject.addAfter.apply(this._containerObject, arguments);
  }
}

qx.Proto.addAtToFolder = function(vChild, vIndex)
{
  this._createChildrenStructure();

  if (this._containerObject)
  {
    this._handleChildMove(vChild, vIndex);
    return this._containerObject.addAt.apply(this._containerObject, arguments);
  }
}

qx.Proto.addAtBeginToFolder = function(vChild) {
  return this.addAtToFolder(vChild, 0);
}

qx.Proto.addAtEndToFolder = function(vChild)
{
  this._createChildrenStructure();

  if (this._containerObject)
  {
    var vLast = this._containerObject.getLastChild();

    if (vLast)
    {
      this._handleChildMove(vChild, null, vLast);
      return this._containerObject.addAfter.call(this._containerObject, vChild, vLast);
    }
    else
    {
      return this.addAtBeginToFolder(vChild);
    }
  }
}

qx.Proto._remappingChildTable = [ "remove", "removeAt", "removeAll" ];






/*
---------------------------------------------------------------------------
  CHILDREN UTILITIES
---------------------------------------------------------------------------
*/

qx.Proto.getContainerObject = function() {
  return this._containerObject;
}

qx.Proto.getHorizontalLayout = function() {
  return this._horizontalLayout;
}

qx.Proto.getFirstVisibleChildOfFolder = function()
{
  if (this._containerObject) {
    return this._containerObject.getFirstChild();
  }
}

qx.Proto.getLastVisibleChildOfFolder = function()
{
  if (this._containerObject) {
    return this._containerObject.getLastChild();
  }
}

qx.Proto.getItems = function(recursive, invisible)
{
  var a = [this];

  if (this._containerObject)
  {
    var ch = invisible == true ? this._containerObject.getChildren() : this._containerObject.getVisibleChildren();

    if (recursive == false)
    {
      a = a.concat(ch);
    }
    else
    {
      for (var i=0, chl=ch.length; i<chl; i++) {
        a = a.concat(ch[i].getItems(recursive, invisible));
      }
    }
  }

  return a;
}

/**
 * <p>deselects, disconnects, removes and disposes the
 *    content of the folder and its subfolders.
 * </p>
 *
 * <p>the current items subitems (and the subitems of each
 * subitem) are destoyed going top down the TreeFolder
 * hierarchy. The current item is left as is.
 * </p>
 */
qx.Proto.destroyContent = function() {
  if(this.hasContent()) {

    var manager = this.getTree() ? this.getTree().getManager() : null;

    var leadItem;
    var anchorItem;
    if(manager) {
      leadItem = manager.getLeadItem();
      anchorItem = manager.getAnchorItem();
    }

    var items = this.getItems();
    var item;

    for(var i=items.length-1;i>=0;--i) {
      item = items[i];

      // this.getItems seems to also contain this.
      // In order to avoid endless loops by calling
      // recursively destroyContent we have to avoid
      // destroying ourselves
      if(item != this) {
        if(manager) {
          // set the leadItem to null if the current
          // destroyed item is the leadItem
          if(leadItem == item) {
            manager.setLeadItem(null);
          }
          // set the anchorItem to null if the current
          // destroyed item is the anchorItem
          if(anchorItem == item) {
            manager.setAnchorItem(null);
          }

          // if the current destroyed item is
          // selectd deselect the item. If we are
          // in single selection mode we have to
          // call deselectAll because setItemSelected
          // refuses to deselect in this case
          if(manager.getItemSelected(item)) {
            if(manager.getMultiSelection()) {
              manager.setItemSelected(item,false);
            }
            else {
              manager.deselectAll();
            }
          }

          // if the item has the method destroyContent defined
          // then it is a TreeFolder (and it's subclasses)
          // which potentially have content which also
          // has to be destroyed
          if (item.destroyContent) {
            item.destroyContent();
          }
        }

        // first disconnect the item so rendering
        // of the tree lines can be done correctly
        item.disconnect();
        this.remove(item);
        item.dispose();
      }
    }
  }
}






/*
---------------------------------------------------------------------------
  MODIFIER
---------------------------------------------------------------------------
*/

qx.Proto._evalCurrentIcon = function()
{
  if (this.getSelected()) {
    return this.getIconSelected() || "icon/16/folder-open.png";
  } else {
    return this.getIcon() || "icon/16/folder.png";
  }
}

qx.Proto._modifyOpen = function(propValue, propOldValue, propData)
{
  this._updateLastColumn();

  if (this._containerObject) {
    this._containerObject.setDisplay(propValue);
  }

  return true;
}

qx.Proto._modifyAlwaysShowPlusMinusSymbol = function(propValue, propOldValue, propData)
{
  this._updateLastColumn();

  return true;
}

qx.Proto._updateLastColumn = function()
{
  if (this._indentObject)
  {
    var vElement = this._indentObject.getElement();

    if (vElement && vElement.firstChild) {
      vElement.firstChild.src = this.BASE_URI + this.getIndentSymbol(this.getTree().getUseTreeLines(), true) + ".gif";
    }
  }
}







/*
---------------------------------------------------------------------------
  EVENT LISTENERS
---------------------------------------------------------------------------
*/

qx.Proto._onmousedown = function(e)
{
  var vOriginalTarget = e.getOriginalTarget();

  switch(vOriginalTarget)
  {
    case this._indentObject:
      if (this._indentObject.getElement().firstChild == e.getDomTarget())
      {
        this.getTree().getManager().handleMouseDown(this, e);
        this.toggle();
      }

      break;

    case this._containerObject:
      break;

    case this:
      if (this._containerObject) {
        break;
      }

      // no break here

    default:
      this.getTree().getManager().handleMouseDown(this, e);
  }

  e.stopPropagation();
}

qx.Proto._onmouseup = function(e)
{
  var vOriginalTarget = e.getOriginalTarget();

  switch(vOriginalTarget)
  {
    case this._indentObject:
    case this._containerObject:
    case this:
      break;

    default:
      if (!this.getTree().getUseDoubleClick()) {
        this.open();
      }
  }
}

qx.Proto._ondblclick = function(e)
{
  if (!this.getTree().getUseDoubleClick()) {
    return;
  }

  this.toggle();
  e.stopPropagation();
}







/*
---------------------------------------------------------------------------
  INDENT HELPER
---------------------------------------------------------------------------
*/

qx.Proto.getIndentSymbol = function(vUseTreeLines, vIsLastColumn)
{
  if (vIsLastColumn)
  {
    if (this.hasContent() || this.getAlwaysShowPlusMinusSymbol())
    {
      if (!vUseTreeLines)
      {
        return this.getOpen() ? "minus" : "plus";
      }
      else if (this.isLastChild())
      {
        return this.getOpen() ? "end_minus" : "end_plus";
      }
      else
      {
        return this.getOpen() ? "cross_minus" : "cross_plus";
      }
    }
    else if (vUseTreeLines)
    {
      return this.isLastChild() ? "end" : "cross";
    }
  }
  else
  {
    return vUseTreeLines && !this.isLastChild() ? "line" : null;
  }
}

qx.Proto._updateIndent = function()
{
  // Intentionally bypass superclass; the _updateIndent we want is in TreeFile
  qx.ui.tree.TreeFile.prototype._updateIndent.call(this);

  if (!this._containerObject) {
    return;
  }

  var ch = this._containerObject.getVisibleChildren();
  for (var i=0, l=ch.length; i<l; i++) {
    ch[i]._updateIndent();
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

  this.removeEventListener("dblclick", this._ondblclick);

  if (this._horizontalLayout)
  {
    this._horizontalLayout.dispose();
    this._horizontalLayout = null;
  }

  if (this._containerObject)
  {
    this._containerObject.dispose();
    this._containerObject = null;
  }

  return qx.ui.tree.AbstractTreeElement.prototype.dispose.call(this);
}
