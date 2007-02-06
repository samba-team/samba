/* ************************************************************************

   qooxdoo - the new era of web development

   http://qooxdoo.org

   Copyright:
     2004-2007 1&1 Internet AG, Germany, http://www.1and1.org
     2006 Derrell Lipman

   License:
     LGPL: http://www.gnu.org/licenses/lgpl.html
     EPL: http://www.eclipse.org/org/documents/epl-v10.php
     See the LICENSE file in the project's top-level directory for details.

   Authors:
     * Sebastian Werner (wpbasti)
     * Andreas Ecker (ecker)
     * Derrell Lipman (derrell)

************************************************************************ */

/* ************************************************************************

#module(ui_treefullcontrol)

************************************************************************ */

/**
 * qx.ui.treefullcontrol.Tree objects are tree root nodes but act like
 * TreeFolder.
 *
 * @param treeRowStructure An instance of qx.ui.treefullcontrol.TreeRowStructure,
 *   defining the structure of this tree row.
 */
qx.OO.defineClass("qx.ui.treefullcontrol.Tree", qx.ui.treefullcontrol.TreeFolder,
function(treeRowStructure)
{
  qx.ui.treefullcontrol.TreeFolder.call(this, treeRowStructure);

  // ************************************************************************
  //   INITILISIZE MANAGER
  // ************************************************************************
  this._manager = new qx.manager.selection.TreeFullControlSelectionManager(this);


  this._iconObject.setAppearance("tree-icon");
  this._labelObject.setAppearance("tree-label");


  // ************************************************************************
  //   DEFAULT STATE
  // ************************************************************************
  // The tree should be open by default
  this.setOpen(true);

  // Fix vertical alignment of empty tree
  this.addToFolder();


  // ************************************************************************
  //   KEY EVENT LISTENER
  // ************************************************************************
  this.addEventListener("keydown", this._onkeydown);
  this.addEventListener("keypress", this._onkeypress);
  this.addEventListener("keyup", this._onkeyup);
});





/*
---------------------------------------------------------------------------
  PROPERTIES
---------------------------------------------------------------------------
*/

qx.OO.addProperty({ name : "useDoubleClick",
                    type : "boolean",
                    defaultValue : false,
                    getAlias : "useDoubleClick"
                  });

qx.OO.addProperty({ name : "useTreeLines",
                    type : "boolean",
                    defaultValue : true,
                    getAlias : "useTreeLines"
                  });

/*!
  In specific applications, it is desirable to omit tree lines for only
  certain indentation levels.  This property provides an array wherein the
  index of the array corresponds to the indentation level, counted from left
  to right; and the value of that element, if it contains, specifically, the
  boolean value <i>true</i>, indicates that tree lines at that indentation
  level are to be omitted.  Any value of that element other than <i>true</i>,
  or if an indentation level's index does not exist in the array, means that
  tree lines should be displayed for that indentation level.  (There are some
  minor code efficiencies that are realized if this array is empty, so after
  having set an element to <i>true</i> and desiring to reset the default
  behavior, you should 'delete' the element rather than setting it to some
  value other than <i>true</i>.)

  If useTreeLines is <i>false</i>, then all tree lines are excluded and this
  property is ignored.
*/
qx.OO.addProperty({ name : "excludeSpecificTreeLines",
                    type : "object",
                    defaultValue : []
                  });

/*!
  Hide the root (Tree) node.  This differs from the visibility property in
  that this property hides *only* the current node, not the node's children.
*/
qx.OO.addProperty({ name : "hideNode",
                    type : "boolean",
                    defaultValue : false,
                    getAlias : "hideNode"
                  });

/*!
  Whether the Root should have an open/close button.  This may also be
  used in conjunction with the hideNode property to provide for virtual root
  nodes.  In the latter case, be very sure that the virtual root nodes are
  expanded programatically, since there will be no open/close button for the
  user to open them.
*/
qx.OO.addProperty({ name : "rootOpenClose",
                    type : "boolean",
                    defaultValue : true
                  });


/*
---------------------------------------------------------------------------
  MANAGER BINDING
---------------------------------------------------------------------------
*/

qx.Proto.getManager = function() {
  return this._manager;
}

qx.Proto.getSelectedElement = function() {
  return this.getManager().getSelectedItems()[0];
}






/*
---------------------------------------------------------------------------
  QUEUE HANDLING
---------------------------------------------------------------------------
*/

qx.Proto.addChildToTreeQueue = function(vChild)
{
  if (!vChild._isInTreeQueue && !vChild._isDisplayable) {
    this.debug("Ignoring invisible child: " + vChild);
  }

  if (!vChild._isInTreeQueue && vChild._isDisplayable)
  {
    qx.ui.core.Widget.addToGlobalWidgetQueue(this);

    if (!this._treeQueue) {
      this._treeQueue = {};
    }

    this._treeQueue[vChild.toHashCode()] = vChild;

    vChild._isInTreeQueue = true;
  }
}

qx.Proto.removeChildFromTreeQueue = function(vChild)
{
  if (vChild._isInTreeQueue)
  {
    if (this._treeQueue) {
      delete this._treeQueue[vChild.toHashCode()];
    }

    delete vChild._isInTreeQueue;
  }
}

qx.Proto.flushWidgetQueue = function() {
  this.flushTreeQueue();
}

qx.Proto.flushTreeQueue = function()
{
  if (!qx.lang.Object.isEmpty(this._treeQueue))
  {
    for (var vHashCode in this._treeQueue)
    {
      // this.debug("Flushing Tree Child: " + this._treeQueue[vHashCode]);
      this._treeQueue[vHashCode].flushTree();
      delete this._treeQueue[vHashCode]._isInTreeQueue;
    }

    delete this._treeQueue;
  }
}







/*
---------------------------------------------------------------------------
  MODIFIER
---------------------------------------------------------------------------
*/

qx.Proto._modifyUseTreeLines = function(propValue, propOldValue, propData)
{
  if (this._initialLayoutDone) {
    this._updateIndent();
  }

  return true;
}

qx.Proto._modifyHideNode = function(propValue, propOldValue, propData)
{
  if (! propValue) {
    this._horizontalLayout.setHeight(this._horizontalLayout.originalHeight);
    this._horizontalLayout.show();
  } else {
    this._horizontalLayout.originalHeight = this._horizontalLayout.getHeight();
    this._horizontalLayout.setHeight(0);
    this._horizontalLayout.hide();
  }

  if (this._initialLayoutDone) {
    this._updateIndent();
  }

  return true;
}

qx.Proto._modifyRootOpenClose = function(propValue, propOldValue, propData)
{
  if (this._initialLayoutDone) {
    this._updateIndent();
  }

  return true;
}

// Override getter so we can return a clone of the array.  Otherwise, the
// setter finds the identical array (after user modifications) and the modify
// function doesn't get called.
qx.Proto.getExcludeSpecificTreeLines = function()
{
  var vName = "excludeSpecificTreeLines";
  var vUpName = qx.lang.String.toFirstUp(vName);
  var vStorageField = "_value" + vUpName;

  return this[vStorageField].slice(0);
}

qx.Proto._modifyExcludeSpecificTreeLines = function(propValue,
                                                    propOldValue,
                                                    propData)
{
  if (this._initialLayoutDone) {
    this._updateIndent();
  }

  return true;
}






/*
---------------------------------------------------------------------------
  UTILITIES
---------------------------------------------------------------------------
*/

qx.Proto.getTree = function() {
  return this;
}

qx.Proto.getParentFolder = function() {
  return null;
}

qx.Proto.getLevel = function() {
  return 0;
}








/*
---------------------------------------------------------------------------
  COMMON CHECKERS
---------------------------------------------------------------------------
*/

qx.ui.treefullcontrol.Tree.isTreeFolder = function(vObject) {
  return (vObject &&
          vObject instanceof qx.ui.treefullcontrol.TreeFolder &&
          !(vObject instanceof qx.ui.treefullcontrol.Tree));
}

qx.ui.treefullcontrol.Tree.isOpenTreeFolder = function(vObject) {
  return (vObject instanceof qx.ui.treefullcontrol.TreeFolder &&
          vObject.getOpen() &&
          vObject.hasContent());
}







/*
---------------------------------------------------------------------------
  EVENT HANDLER
---------------------------------------------------------------------------
*/

qx.Proto._onkeydown = function(e)
{
  var vManager = this.getManager();
  var vSelectedItem = vManager.getSelectedItem();

  if (e.getKeyIdentifier() == "Enter")
  {
      e.preventDefault();
      if (qx.ui.treefullcontrol.Tree.isTreeFolder(vSelectedItem)) {
        return vSelectedItem.toggle();
      }
  }
}


qx.Proto._onkeypress = function(e)
{
  var vManager = this.getManager();
  var vSelectedItem = vManager.getSelectedItem();

  switch(e.getKeyIdentifier())
  {
    case "Left":
      e.preventDefault();

      if (qx.ui.treefullcontrol.Tree.isTreeFolder(vSelectedItem))
      {
        if (!vSelectedItem.getOpen())
        {
          var vParent = vSelectedItem.getParentFolder();
          if (vParent instanceof qx.ui.treefullcontrol.TreeFolder) {
            if (!(vParent instanceof qx.ui.treefullcontrol.Tree)) {
              vParent.close();
            }

            this.setSelectedElement(vParent);
          }
        }
        else
        {
          return vSelectedItem.close();
        }
      }
      else if (vSelectedItem instanceof qx.ui.treefullcontrol.TreeFile)
      {
        var vParent = vSelectedItem.getParentFolder();
        if (vParent instanceof qx.ui.treefullcontrol.TreeFolder) {
          if (!(vParent instanceof qx.ui.treefullcontrol.Tree)) {
            vParent.close();
          }

          this.setSelectedElement(vParent);
        }
      }

      break;

    case "Right":
      e.preventDefault();

      if (qx.ui.treefullcontrol.Tree.isTreeFolder(vSelectedItem))
      {
        if (!vSelectedItem.getOpen())
        {
          return vSelectedItem.open();
        }
        else if (vSelectedItem.hasContent())
        {
          var vFirst = vSelectedItem.getFirstVisibleChildOfFolder();
          this.setSelectedElement(vFirst);

          if (vFirst instanceof qx.ui.tree.TreeFolder) {
            vFirst.open();
          }

          return;
        }
      }

      break;

    default:
      if (!this._fastUpdate)
      {
        this._fastUpdate = true;
        this._oldItem = vSelectedItem;
      }

      vManager.handleKeyPress(e);
  }
};


qx.Proto._onkeyup = function(e)
{
  if (this._fastUpdate)
  {
    var vNewItem = this.getManager().getSelectedItem();

    if (! vNewItem) {
      return;
    }

    vNewItem.getIconObject().addState("selected");

    delete this._fastUpdate;
    delete this._oldItem;
  }
}

qx.Proto.getLastTreeChild = function()
{
  var vLast = this;

  while (vLast instanceof qx.ui.treefullcontrol.AbstractTreeElement)
  {
    if (!(vLast instanceof qx.ui.treefullcontrol.TreeFolder) ||
        !vLast.getOpen()) {
      return vLast;
    }

    vLast = vLast.getLastVisibleChildOfFolder();
  }

  return null;
}

qx.Proto.getFirstTreeChild = function() {
  return this;
}

qx.Proto.setSelectedElement = function(vElement)
{
  var vManager = this.getManager();

  vManager.setSelectedItem(vElement);
  vManager.setLeadItem(vElement);
}

/* Override getHierarchy: do not add label if root node is hidden */
qx.Proto.getHierarchy = function(vArr)
{
  if (! this.hideNode() && this._labelObject) {
    vArr.unshift(this._labelObject.getHtml());
  }
  return vArr;
}


qx.Proto.getIndentSymbol = function(vUseTreeLines, vColumn, vLastColumn)
{
  if (vColumn == vLastColumn &&
      (this.hasContent() || this.getAlwaysShowPlusMinusSymbol()))
  {
    if (! vUseTreeLines)
    {
      return this.getOpen() ? "minus" : "plus";
    }
    else
    {
      return this.getOpen() ? "only_minus" : "only_plus";
    }
  }
  else
  {
    return null;
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

  this.removeEventListener("keydown", this._onkeydown);
  this.removeEventListener("keypress", this._onkeypress);
  this.removeEventListener("keyup", this._onkeyup);

  if (this._manager)
  {
    this._manager.dispose();
    this._manager = null;
  }

  delete this._oldItem;

  return qx.ui.treefullcontrol.TreeFolder.prototype.dispose.call(this);
}
