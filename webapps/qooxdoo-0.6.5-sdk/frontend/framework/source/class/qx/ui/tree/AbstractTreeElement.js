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

#module(ui_tree)
#embed(qx.widgettheme/tree/*)
#embed(qx.icontheme/16/actions/document-new.png)

************************************************************************ */

qx.OO.defineClass("qx.ui.tree.AbstractTreeElement", qx.ui.layout.BoxLayout,
function(vLabel, vIcon, vIconSelected)
{
  if (this.classname == qx.ui.tree.AbstractTreeElement.ABSTRACT_CLASS) {
    throw new Error("Please omit the usage of qx.ui.tree.AbstractTreeElement directly. Choose between qx.ui.tree.TreeFolder and qx.ui.tree.TreeFile instead!");
  }

  // Precreate subwidgets
  this._indentObject = new qx.ui.embed.HtmlEmbed;
  this._iconObject = new qx.ui.basic.Image;
  this._labelObject = new qx.ui.basic.Label;

  // Make anonymous
  this._indentObject.setAnonymous(true);
  this._iconObject.setAnonymous(true);
  this._labelObject.setAnonymous(true);

  // Behaviour and Hard Styling
  this._labelObject.setSelectable(false);
  this._labelObject.setStyleProperty("lineHeight", "100%");

  qx.ui.layout.BoxLayout.call(this, "horizontal");

  this.setLabel(vLabel);

  // Prohibit selection
  this.setSelectable(false);

  // Base URL used for indent images
  this.BASE_URI = qx.manager.object.AliasManager.getInstance().resolvePath("widget/tree/");

  // Adding subwidgets
  this.add(this._indentObject, this._iconObject, this._labelObject);

  // Set Icons
  if (vIcon != null) {
    this.setIcon(vIcon);
    this.setIconSelected(vIcon);
  }

  if (vIconSelected != null) {
    this.setIconSelected(vIconSelected);
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

qx.ui.tree.AbstractTreeElement.ABSTRACT_CLASS = "qx.ui.tree.AbstractTreeElement";




/*
---------------------------------------------------------------------------
  PROPERTIES
---------------------------------------------------------------------------
*/

qx.OO.changeProperty({ name : "appearance", type : "string", defaultValue : "tree-element" });

/*!
  The icons
*/
qx.OO.addProperty({ name : "icon", type : "string" });
qx.OO.addProperty({ name : "iconSelected", type : "string" });

/*!
  The label/caption/text of the qx.ui.basic.Atom instance
*/
qx.OO.addProperty({ name : "label" });

/*!
  Selected property
*/
qx.OO.addProperty({ name : "selected", type : "boolean", defaultValue : false });






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
  propValue ? this.addState("selected") : this.removeState("selected");
  propValue ? this._labelObject.addState("selected") : this._labelObject.removeState("selected");

  var vTree = this.getTree();
  if (!vTree._fastUpdate || (propOldValue && vTree._oldItem == this))
  {
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
 * <p>deselects, disconnects, removes and disposes the
 *    current tree element and its content.
 * </p>
 *
 * <p>destroys the current item (TreeFile or TreeFolder)
 * and all its subitems. The destruction of the subitems
 * is done by calling destroyContent. This is done if the
 * subitem has the method destroyContent which is true if the
 * subitem is a TreeFolder (or one of its subclasses).
 * </p>
 *
 * <p>The method destroyContent is defined in the TreeFolder class.
 * </p>
 */
qx.Proto.destroy = function() {
   var manager = this.getTree() ? this.getTree().getManager() : null;
  if(manager) {

    // if the current destroyed item is
    // selectd deselect the item. If we are
    // in single selection mode we have to
    // call deselectAll because setItemSelected
    // refuses to deselect in this case
    if(manager.getItemSelected(this)) {
      if(manager.getMultiSelection()) {
        manager.setItemSelected(this,false);
      }
      else {
        manager.deselectAll();
      }
    }

    // set the leadItem to null if the current
    // destroyed item is the leadItem
    if(manager.getLeadItem() == this) {
      manager.setLeadItem(null);
    }
    // set the anchorItem to null if the current
    // destroyed item is the anchorItem
    if(manager.getAnchorItem() == this) {
      manager.setAnchorItem(null);
    }
  }

  // if the item has the method destroyContent defined
  // then it is a TreeFolder (and it's subclasses)
  // which potentially have content which also
  // has to be destroyed
  if(this.destroyContent) {
    this.destroyContent();
  }

  // first disconnect the item so rendering
  // of the tree lines can be done correctly
  this.disconnect();

  // remove the current item from
  // the parent folder
  var parentFolder = this.getParentFolder();
  if(parentFolder) {
    parentFolder.remove(this);
  }

  this.dispose();
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

  // Be sure to update previous folder also if it is closed currently (plus/minus symbol)
  if (propOldValue && !propOldValue.isDisplayable() && propOldValue.getParent() && propOldValue.getParent().isDisplayable()) {
    propOldValue.getParent().addToTreeQueue();
  }

  // Be sure to update new folder also if it is closed currently (plus/minus symbol)
  if (propValue && !propValue.isDisplayable() && propValue.getParent() && propValue.getParent().isDisplayable()) {
    propValue.getParent().addToTreeQueue();
  }

  return true;
}

qx.Proto._handleDisplayableCustom = function(vDisplayable, vParent, vHint)
{
  qx.ui.layout.BoxLayout.prototype._handleDisplayableCustom.call(this, vDisplayable, vParent, vHint);

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

    if (vParentFolder && vParentFolder.isDisplayable() && vParentFolder._initialLayoutDone) {
      vParentFolder.addToTreeQueue();
    }

    if (this.isLastVisibleChild())
    {
      var vPrev = this.getPreviousVisibleSibling();

      if (vPrev && vPrev instanceof qx.ui.tree.AbstractTreeElement) {
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
  // store informations for update process
  this._previousParentFolder = this.getParentFolder();
  this._wasLastVisibleChild = this.isLastVisibleChild();

  // generate html for indent area
  var vLevel = this.getLevel();
  var vTree = this.getTree();
  var vImage;
  var vHtml = [];
  var vCurrentObject = this;

  for (var i=0; i<vLevel; i++)
  {
    vImage = vCurrentObject.getIndentSymbol(vTree.getUseTreeLines(), i==0);

    if (vImage)
    {
      vHtml.push("<img style=\"position:absolute;top:0px;left:");
      vHtml.push((vLevel-i-1) * 19);
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
  this._indentObject.setWidth(vLevel * 19);
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
