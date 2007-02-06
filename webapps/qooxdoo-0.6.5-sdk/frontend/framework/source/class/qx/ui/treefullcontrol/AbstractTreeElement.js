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
#embed(qx.widgettheme/tree/*)
#embed(qx.icontheme/16/actions/document-new.png)

************************************************************************ */

qx.OO.defineClass("qx.ui.treefullcontrol.AbstractTreeElement", qx.ui.layout.BoxLayout,
function(treeRowStructure)
{
  if (this.classname == qx.ui.treefullcontrol.AbstractTreeElement.ABSTRACT_CLASS) {
    throw new Error("Please omit the usage of qx.ui.treefullcontrol.AbstractTreeElement directly. Choose between qx.ui.treefullcontrol.TreeFolder, qx.ui.treefullcontrol.TreeFolderSimple, qx.ui.treefullcontrol.TreeFile and qx.ui.treefullcontrol.TreeFileSimple instead!");
  }

  if (treeRowStructure !== qx.ui.treefullcontrol.TreeRowStructure.getInstance())
  {
    throw new Error("A qx.ui.treefullcontrol.TreeRowStructure parameter is required.");
  }

  // Precreate subwidgets
  this._indentObject = treeRowStructure._indentObject;
  this._iconObject = treeRowStructure._iconObject;
  this._labelObject = treeRowStructure._labelObject;

  // Make anonymous
  this._indentObject.setAnonymous(true);
  this._iconObject.setAnonymous(true);
  this._labelObject.setAnonymous(true);

  // Behaviour and Hard Styling
  this._labelObject.setSelectable(false);
  this._labelObject.setStyleProperty("lineHeight",
                                     "100%");

  qx.ui.layout.BoxLayout.call(this, "horizontal");

  if (qx.util.Validation.isValid(treeRowStructure._label)) {
    this.setLabel(treeRowStructure._label);
  }

  // Prohibit selection
  this.setSelectable(false);

  // Base URL used for indent images
  this.BASE_URI = qx.manager.object.AliasManager.getInstance().resolvePath("widget/tree/");

  /*
   * Add all of the objects which are to be in the horizontal layout.
   */
  for (var i = 0; i < treeRowStructure._fields.length; i++)
  {
    this.add(treeRowStructure._fields[i]);
  }

  // Set Icons
  if ((treeRowStructure._icons.unselected != null) &&
      (qx.util.Validation.isValidString(treeRowStructure._icons.unselected))) {
    this.setIcon(treeRowStructure._icons.unselected);
    this.setIconSelected(treeRowStructure._icons.unselected);
  }
  if ((treeRowStructure._icons.selected != null) &&
      (qx.util.Validation.isValidString(treeRowStructure._icons.selected))) {
    this.setIconSelected(treeRowStructure._icons.selected);
  }

  // Setup initial icon
  this._iconObject.setSource(this._evalCurrentIcon());

  // Set Appearance
  this._iconObject.setAppearance("tree-element-icon");
  this._labelObject.setAppearance("tree-element-label");

  // Register event listeners
  this.addEventListener("mousedown", this._onmousedown);
  this.addEventListener("mouseup", this._onmouseup);
});

qx.ui.treefullcontrol.AbstractTreeElement.ABSTRACT_CLASS = "qx.ui.treefullcontrol.AbstractTreeElement";




/*
---------------------------------------------------------------------------
  PROPERTIES
---------------------------------------------------------------------------
*/

qx.OO.changeProperty({ name : "appearance",
                       type : "string",
                       defaultValue : "tree-element"
                     });

/*!
  The icons
*/
qx.OO.addProperty({ name : "icon",
                    type : "string"
                  });

qx.OO.addProperty({ name : "iconSelected",
                    type : "string"
                  });

/*!
  The label/caption/text of the qx.ui.basic.Atom instance
*/
qx.OO.addProperty({ name : "label"
                  });

/*!
  Selected property
*/
qx.OO.addProperty({ name : "selected",
                    type : "boolean",
                    defaultValue : false
                  });






/*
---------------------------------------------------------------------------
  MODIFIER
---------------------------------------------------------------------------
*/

qx.Proto._modifyLabel = function(propValue, propOldValue, propData)
{
  if (this._labelObject) {
    this._labelObject.setHtml(propValue);
  }

  return true;
}

qx.Proto._modifySelected = function(propValue, propOldValue, propData)
{
  if (propValue) {
    this.addState("selected");
    this._labelObject.addState("selected");
  } else {
    this.removeState("selected");
    this._labelObject.removeState("selected");
  }

  var vTree = this.getTree();
  if (!vTree._fastUpdate ||
      (propOldValue && vTree._oldItem == this)) {
    this._iconObject.setSource(this._evalCurrentIcon());

    if (propValue) {
      this._iconObject.addState("selected");
    } else {
      this._iconObject.removeState("selected");
    }
  }

  var vManager = this.getTree().getManager();

  if (propOldValue && vManager.getSelectedItem() == this)
  {
    vManager.deselectAll();
  }
  else if (propValue && vManager.getSelectedItem() != this)
  {
    vManager.setSelectedItem(this);
  }

  return true;
}

qx.Proto._evalCurrentIcon = function()
{
  if (this.getSelected() && this.getIconSelected()) {
    return this.getIconSelected();
  } else {
    return this.getIcon() || "icon/16/actions/document-new.png";
  }
}





/*
---------------------------------------------------------------------------
  UTILITIES
---------------------------------------------------------------------------
*/

qx.Proto.getParentFolder = function()
{
  try {
    return this.getParent().getParent();
  } catch(ex) {}

  return null;
}

qx.Proto.getLevel = function()
{
  var vParentFolder = this.getParentFolder();
  return vParentFolder ? vParentFolder.getLevel() + 1 : null;
}

qx.Proto.getTree = function()
{
  var vParentFolder = this.getParentFolder();
  return vParentFolder ? vParentFolder.getTree() : null;
}

qx.Proto.getIndentObject = function() {
  return this._indentObject;
}

qx.Proto.getIconObject = function() {
  return this._iconObject;
}

qx.Proto.getLabelObject = function() {
  return this._labelObject;
}

/**
 * Obtain the entire hierarchy of labels from the root down to the current
 * node.
 *
 * @param
 *   vArr -
 *     When called by the user, arr should typically be an empty array.  Each
 *     level from the current node upwards will push its label onto the array.
 */
qx.Proto.getHierarchy = function(vArr) {
  // Add our label to the array
  if (this._labelObject) {
    vArr.unshift(this._labelObject.getHtml());
  }

  // Get the parent folder
  var parent = this.getParentFolder();

  // If it exists...
  if (parent) {
    // ... then add it and its ancestors' labels to the array.
    parent.getHierarchy(vArr);
  }

  // Give 'em what they came for
  return vArr;
}




/*
---------------------------------------------------------------------------
  QUEUE HANDLING
---------------------------------------------------------------------------
*/

qx.Proto.addToTreeQueue = function()
{
  var vTree = this.getTree();
  if (vTree) {
    vTree.addChildToTreeQueue(this);
  }
}

qx.Proto.removeFromTreeQueue = function()
{
  var vTree = this.getTree();
  if (vTree) {
    vTree.removeChildFromTreeQueue(this);
  }
}

qx.Proto.addToCustomQueues = function(vHint)
{
  this.addToTreeQueue();

  qx.ui.layout.BoxLayout.prototype.addToCustomQueues.call(this, vHint);
}

qx.Proto.removeFromCustomQueues = function(vHint)
{
  this.removeFromTreeQueue();

  qx.ui.layout.BoxLayout.prototype.removeFromCustomQueues.call(this, vHint);
}








/*
---------------------------------------------------------------------------
  DISPLAYBLE HANDLING
---------------------------------------------------------------------------
*/

qx.Proto._modifyParent = function(propValue, propOldValue, propData)
{
  qx.ui.layout.BoxLayout.prototype._modifyParent.call(this, propValue, propOldValue, propData);

  // Be sure to update previous folder also if it is closed currently
  // (plus/minus symbol)
  if (propOldValue &&
      !propOldValue.isDisplayable() &&
      propOldValue.getParent() &&
      propOldValue.getParent().isDisplayable()) {
    propOldValue.getParent().addToTreeQueue();
  }

  // Be sure to update new folder also if it is closed currently
  // (plus/minus symbol)
  if (propValue &&
      !propValue.isDisplayable() &&
      propValue.getParent() &&
      propValue.getParent().isDisplayable()) {
    propValue.getParent().addToTreeQueue();
  }

  return true;
}

qx.Proto._handleDisplayableCustom = function(vDisplayable, vParent, vHint)
{
  qx.ui.layout.BoxLayout.prototype._handleDisplayableCustom.call(this,
                                                                 vDisplayable,
                                                                 vParent,
                                                                 vHint);

  if (vHint)
  {
    var vParentFolder = this.getParentFolder();
    var vPreviousParentFolder = this._previousParentFolder;

    if (vPreviousParentFolder)
    {
      if (this._wasLastVisibleChild)
      {
        vPreviousParentFolder._updateIndent();
      }
      else if (!vPreviousParentFolder.hasContent())
      {
        vPreviousParentFolder.addToTreeQueue();
      }
    }

    if (vParentFolder &&
        vParentFolder.isDisplayable() &&
        vParentFolder._initialLayoutDone) {
      vParentFolder.addToTreeQueue();
    }

    if (this.isLastVisibleChild())
    {
      var vPrev = this.getPreviousVisibleSibling();

      if (vPrev &&
          vPrev instanceof qx.ui.treefullcontrol.AbstractTreeElement) {
        vPrev._updateIndent();
      }
    }

    if (vDisplayable) {
      this._updateIndent();
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
  this.getTree().getManager().handleMouseDown(this, e);
  e.stopPropagation();
}

qx.Proto._onmouseup = qx.lang.Function.returnTrue;





/*
---------------------------------------------------------------------------
  TREE FLUSH
---------------------------------------------------------------------------
*/

qx.Proto.flushTree = function()
{
  // store information for update process
  this._previousParentFolder = this.getParentFolder();
  this._wasLastVisibleChild = this.isLastVisibleChild();

  // generate html for indent area
  var vLevel = this.getLevel();
  var vTree = this.getTree();
  var vImage;
  var vHtml = [];
  var vCurrentObject = this;
  var vMinLevel = 0;
  var vMaxLevel = vLevel;

  // If we're displaying the open/close button for the root node (normal)...
  if (vTree.getRootOpenClose()) {
    // ... then we need one more level
    vMaxLevel = vLevel + 1;
  }

  // If we're not displaying the root node (creating virtual roots)...
  if (vTree.hideNode()) {
    // ... then start one level higher
    vMinLevel = 1;
  }

  for (var i=vMinLevel; i<vMaxLevel; i++)
  {
    vImage = vCurrentObject.getIndentSymbol(vTree.getUseTreeLines(),
                                            i,
                                            vMinLevel,
                                            vMaxLevel);

    if (vImage)
    {
      vHtml.push("<img style=\"position:absolute;top:0px;left:");

      // location of image; Root's image could be left of margin (invisible)
      vHtml.push((vMaxLevel-i-1) * 19);

      vHtml.push("px\" src=\"");
      vHtml.push(this.BASE_URI);
      vHtml.push(vImage);
      vHtml.push(".");
      vHtml.push("gif");
      vHtml.push("\" />");
    }

    vCurrentObject = vCurrentObject.getParentFolder();
  }

  this._indentObject.setHtml(vHtml.join(""));
  this._indentObject.setWidth((vMaxLevel - vMinLevel) * 19);
}










/*
---------------------------------------------------------------------------
  DISPOSER
---------------------------------------------------------------------------
*/

qx.Proto.dispose = function()
{
  if (this.getDisposed()) {
    return true;
  }

  if (this._indentObject)
  {
    this._indentObject.dispose();
    this._indentObject = null;
  }

  if (this._iconObject)
  {
    this._iconObject.dispose();
    this._iconObject = null;
  }

  if (this._labelObject)
  {
    this._labelObject.dispose();
    this._labelObject = null;
  }

  this._previousParentFolder = null;

  this.removeEventListener("mousedown", this._onmousedown);
  this.removeEventListener("mouseup", this._onmouseup);

  return qx.ui.layout.BoxLayout.prototype.dispose.call(this);
}
