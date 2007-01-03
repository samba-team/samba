/* ************************************************************************

   qooxdoo - the new era of web development

   http://qooxdoo.org

   Copyright:
     2004-2006 by 1&1 Internet AG, Germany, http://www.1and1.org
     2006 by Derrell Lipman

   License:
     LGPL 2.1: http://www.gnu.org/licenses/lgpl.html

   Authors:
     * Sebastian Werner (wpbasti)
     * Andreas Ecker (ecker)
     * Derrell Lipman (derrell)

************************************************************************ */

/* ************************************************************************

#module(ui_treefullcontrol)

************************************************************************ */

/**
 * qx.ui.treefullcontrol.TreeFolder objects are tree rows which may contain
 * sub-trees
 *
 * @param
 * treeRowStructure -
 *   An instance of qx.ui.treefullcontrol.TreeRowStructure, defining the
 *   structure of this tree row.
 *
 * @event treeOpenWithContent {qx.event.type.DataEvent}
 * @event treeOpenWhileEmpty {qx.event.type.DataEvent}
 * @event treeClose {qx.event.type.DataEvent}
 */
qx.OO.defineClass("qx.ui.treefullcontrol.TreeFolder", qx.ui.treefullcontrol.AbstractTreeElement,
function(treeRowStructure)
{
  qx.ui.treefullcontrol.AbstractTreeElement.call(this, treeRowStructure);

  // Save the tree row field order. We'll need it to create children structure.
  this._treeRowStructureFields = treeRowStructure._fields;

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
});



/*
---------------------------------------------------------------------------
  PROPERTIES
---------------------------------------------------------------------------
*/


qx.OO.changeProperty({ name : "appearance",
                       type : "string",
                       defaultValue : "tree-folder"
                     });

qx.OO.changeProperty({ name : "icon",
                       type : "string"
                     });

qx.OO.changeProperty({ name : "iconSelected",
                       type : "string"
                     });

qx.OO.addProperty({ name : "open",
                    type : "boolean",
                    defaultValue : false
                  });

qx.OO.addProperty({ name : "alwaysShowPlusMinusSymbol",
                    type : "boolean",
                    defaultValue : false
                  });




/*
---------------------------------------------------------------------------
  UTILITIES
---------------------------------------------------------------------------
*/

qx.Proto.hasContent = function() {
  return (this._containerObject &&
          this._containerObject.getChildrenLength() > 0);
}

qx.Proto.open = function()
{
  if (this.getOpen()) {
    return;
  }

  if (this.hasContent())
  {
    // If there are listeners waiting for a treeOpenWithContent event...
    if (this.getTree().hasEventListeners("treeOpenWithContent")) {
      // ... then issue the event
      this.getTree().dispatchEvent(new qx.event.type.DataEvent("treeOpenWithContent", this), true);
    }

    this.getTopLevelWidget().setGlobalCursor("progress");
    qx.client.Timer.once(this._openCallback, this, 0);
  }
  else
  {
    // If there are listeners waiting for a treeOpenWithContent event...
    if (this.getTree().hasEventListeners("treeOpenWhileEmpty")) {
      // ... then issue the event
      this.getTree().dispatchEvent(new qx.event.type.DataEvent("treeOpenWhileEmpty", this), true);
    }

    this.setOpen(true);
  }
}

qx.Proto.close = function()
{
  // If there are listeners waiting for a treeClose event...
  if (this.getTree().hasEventListeners("treeClose")) {
    // ... then issue the event
    this.getTree().dispatchEvent(new qx.event.type.DataEvent("treeClose", this), true);
  }

  this.setOpen(false);
}

qx.Proto.toggle = function()
{
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
  this.setAppearance(this instanceof qx.ui.treefullcontrol.Tree
                     ? "tree-container"
                     : "tree-folder-container");

  if (!this._horizontalLayout)
  {
    this.setOrientation("vertical");

    // Create a horizontal layout for this tree row
    this._horizontalLayout = new qx.ui.layout.HorizontalBoxLayout;
    this._horizontalLayout.setWidth(null);
    this._horizontalLayout.setParent(this);
    this._horizontalLayout.setAnonymous(true);
    this._horizontalLayout.setAppearance(this instanceof qx.ui.treefullcontrol.Tree
                                         ? "tree"
                                         : "tree-folder");

    // Move the row fields into the horizontal layout
    for (var i = 0; i < this._treeRowStructureFields.length; i++)
    {
      this._treeRowStructureFields[i].setParent(this._horizontalLayout);
    }

    // We don't need the tree row structure any more.
    this._treeRowStructureFields = null;
  }

  if (!this._containerObject)
  {
    // Create a veritcal box layout for all of this folder's children
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
    return this._containerObject.addBefore.apply(this._containerObject,
                                                 arguments);
  }
}

qx.Proto.addAfterToFolder = function(vChild, vAfter)
{
  this._createChildrenStructure();

  if (this._containerObject)
  {
    this._handleChildMove(vChild, null, vAfter);
    return this._containerObject.addAfter.apply(this._containerObject,
                                                arguments);
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
      return this._containerObject.addAfter.call(this._containerObject,
                                                 vChild,
                                                 vLast);
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

qx.Proto.getContainerObject = function()
{
  return this._containerObject;
}

qx.Proto.getHorizontalLayout = function()
{
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

qx.Proto.getItems = function()
{
  var a = [this];

  if (this._containerObject)
  {
    var ch = this._containerObject.getVisibleChildren();

    for (var i=0, chl=ch.length; i<chl; i++) {
      a = a.concat(ch[i].getItems());
    }
  }

  return a;
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
  // we need the whole indent process if certain tree lines are to be excluded
  if (this.getTree().getExcludeSpecificTreeLines().length > 0) {
    this._updateIndent();
  } else {
    this._updateLastColumn();
  }

  if (this._containerObject) {
    this._containerObject.setDisplay(propValue);
  }

  return true;
}

qx.Proto._modifyAlwaysShowPlusMinusSymbol = function(propValue, propOldValue, propData)
{
  var t = this.getTree();
  if (t) {
    // we need the whole indent process if only certain tree lines are to be
    // excluded
    if (t.getExcludeSpecificTreeLines().length > 0) {
      this._updateIndent();
    } else {
      this._updateLastColumn();
    }
  }

  return true;
}

qx.Proto._updateLastColumn = function()
{
  if (this._indentObject)
  {
    var vElement = this._indentObject.getElement();

    if (vElement && vElement.firstChild) {
      vElement.firstChild.src =
        (this.BASE_URI +
         this.getIndentSymbol(this.getTree().getUseTreeLines(), 0, 0, 0) +
         ".gif");
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

qx.Proto.getIndentSymbol = function(vUseTreeLines,
                                    vColumn,
                                    vFirstColumn,
                                    vLastColumn)
{
  var vLevel = this.getLevel();
  var vExcludeList = this.getTree().getExcludeSpecificTreeLines();
  var vExclude = vExcludeList[vLastColumn - vColumn - 1];

  if (vColumn == vFirstColumn)
  {
    if (this.hasContent() || this.getAlwaysShowPlusMinusSymbol())
    {
      // If tree lines were not requested, don't display them
      if (!vUseTreeLines)
      {
        return this.getOpen() ? "minus" : "plus";
      }


      // If this is the first level under the root...
      if (vLevel == 1) {
        // ... and the root is not being displayed and this is the first
        // child...
        var vParentFolder = this.getParentFolder();
        if (vParentFolder &&
            !vParentFolder._horizontalLayout.getVisibility() &&
            this.isFirstChild())
        {
          //... then if this is also the last (i.e. only) child, use no tree
          // lines; otherwise, use descender lines but no ascender.
          if (this.isLastChild() || vExclude === true)
          {
            return this.getOpen() ? "only_minus" : "only_plus";
          }
          else
          {
            return this.getOpen() ? "start_minus" : "start_plus";
          }
        }
      }

      if (vExclude === true)
      {
        return this.getOpen() ? "only_minus" : "only_plus";
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
    else if (vUseTreeLines && ! (vExclude === true))
    {
      return this.isLastChild() ? "end" : "cross";
    }
  }
  else
  {
    if (vUseTreeLines && ! this.isLastChild()) {
      if (vExclude === true) {
        return null;
      }
      return "line";
    }
    return null;
  }
}

qx.Proto._updateIndent = function()
{
  // Intentionally bypass superclass; the _updateIndent we want is in TreeFile
  qx.ui.treefullcontrol.TreeFile.prototype._updateIndent.call(this);

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

  return qx.ui.treefullcontrol.AbstractTreeElement.prototype.dispose.call(this);
}
