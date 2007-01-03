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

#module(ui_menu)

************************************************************************ */

qx.OO.defineClass("qx.ui.menu.Button", qx.ui.layout.HorizontalBoxLayout,
function(vLabel, vIcon, vCommand, vMenu)
{
  qx.ui.layout.HorizontalBoxLayout.call(this);


  // ************************************************************************
  //   LAYOUT
  // ************************************************************************

  var io = this._iconObject = new qx.ui.basic.Image;
  io.setWidth(16);
  io.setAnonymous(true);

  var lo = this._labelObject = new qx.ui.basic.Label;
  lo.setAnonymous(true);
  lo.setSelectable(false);

  var so = this._shortcutObject = new qx.ui.basic.Label;
  so.setAnonymous(true);
  so.setSelectable(false);

  var ao = this._arrowObject = new qx.ui.basic.Image("widget/arrows/next.gif");
  ao.setAnonymous(true);


  // ************************************************************************
  //   INIT
  // ************************************************************************

  if (qx.util.Validation.isValidString(vLabel)) {
    this.setLabel(vLabel);
  }

  if (qx.util.Validation.isValidString(vIcon)) {
    this.setIcon(vIcon);
  }

  if (qx.util.Validation.isValid(vCommand)) {
    this.setCommand(vCommand);
  }

  if (qx.util.Validation.isValid(vMenu)) {
    this.setMenu(vMenu);
  }


  // ************************************************************************
  //   EVENTS
  // ************************************************************************

  this.addEventListener("mouseup", this._onmouseup);
});



/*
---------------------------------------------------------------------------
  PROPERTIES
---------------------------------------------------------------------------
*/

qx.OO.changeProperty({ name : "appearance", type : "string", defaultValue : "menu-button" });

qx.OO.addProperty({ name : "icon", type : "string" });
qx.OO.addProperty({ name : "label", type : "string" });
qx.OO.addProperty({ name : "menu", type : "object" });






/*
---------------------------------------------------------------------------
  UTILITIES
---------------------------------------------------------------------------
*/

qx.Proto._hasIcon = false;
qx.Proto._hasLabel = false;
qx.Proto._hasShortcut = false;
qx.Proto._hasMenu = false;

qx.Proto.hasIcon = function() {
  return this._hasIcon;
}

qx.Proto.hasLabel = function() {
  return this._hasLabel;
}

qx.Proto.hasShortcut = function() {
  return this._hasShortcut;
}

qx.Proto.hasMenu = function() {
  return this._hasMenu;
}

qx.Proto.getIconObject = function() {
  return this._iconObject;
}

qx.Proto.getLabelObject = function() {
  return this._labelObject;
}

qx.Proto.getShortcutObject = function() {
  return this._shortcutObject;
}

qx.Proto.getArrowObject = function() {
  return this._arrowObject;
}

qx.Proto.getParentMenu = function()
{
  var vParent = this.getParent();
  if (vParent)
  {
    vParent = vParent.getParent();

    if (vParent && vParent instanceof qx.ui.menu.Menu) {
      return vParent;
    }
  }

  return null;
}





/*
---------------------------------------------------------------------------
  INIT LAYOUT IMPL
---------------------------------------------------------------------------
*/

/*!
  This creates an new instance of the layout impl this widget uses
*/
qx.Proto._createLayoutImpl = function() {
  return new qx.renderer.layout.MenuButtonLayoutImpl(this);
}





/*
---------------------------------------------------------------------------
  MODIFIERS
---------------------------------------------------------------------------
*/

qx.Proto._modifyEnabled = function(propValue, propOldValue, propData)
{
  if (this._iconObject) {
    this._iconObject.setEnabled(propValue);
  }

  if (this._labelObject) {
    this._labelObject.setEnabled(propValue);
  }

  if (this._shortcutObject) {
     this._shortcutObject.setEnabled(propValue);
  }

  return qx.ui.layout.HorizontalBoxLayout.prototype._modifyEnabled.call(this, propValue, propOldValue, propData);
}

qx.Proto._modifyIcon = function(propValue, propOldValue, propData)
{
  this._iconObject.setSource(propValue);

  if (qx.util.Validation.isValidString(propValue))
  {
    this._hasIcon = true;

    if (qx.util.Validation.isInvalidString(propOldValue)) {
      this.addAtBegin(this._iconObject);
    }
  }
  else
  {
    this._hasIcon = false;
    this.remove(this._iconObject);
  }

  return true;
}

qx.Proto._modifyLabel = function(propValue, propOldValue, propData)
{
  this._labelObject.setHtml(propValue);

  if (qx.util.Validation.isValidString(propValue))
  {
    this._hasLabel = true;

    if (qx.util.Validation.isInvalidString(propOldValue)) {
      this.addAt(this._labelObject, this.getFirstChild() == this._iconObject ? 1 : 0);
    }
  }
  else
  {
    this._hasLabel = false;
    this.remove(this._labelObject);
  }

  return true;
}

qx.Proto._modifyCommand = function(propValue, propOldValue, propData)
{
  var vHtml = propValue ? propValue.getShortcut() : "";

  this._shortcutObject.setHtml(vHtml);

  if (qx.util.Validation.isValidString(vHtml))
  {
    this._hasShortcut = true;

    var vOldHtml = propOldValue ? propOldValue.getShortcut() : "";

    if (qx.util.Validation.isInvalidString(vOldHtml))
    {
      if (this.getLastChild() == this._arrowObject)
      {
        this.addBefore(this._shortcutObject, this._arrowObject);
      }
      else
      {
        this.addAtEnd(this._shortcutObject);
      }
    }
  }
  else
  {
    this._hasShortcut = false;
    this.remove(this._shortcutObject);
  }

  return true;
}

qx.Proto._modifyMenu = function(propValue, propOldValue, propData)
{
  if (qx.util.Validation.isValidObject(propValue))
  {
    this._hasMenu = true;

    if (qx.util.Validation.isInvalidObject(propOldValue)) {
      this.addAtEnd(this._arrowObject);
    }
  }
  else
  {
    this._hasMenu = false;
    this.remove(this._arrowObject);
  }

  return true;
}






/*
---------------------------------------------------------------------------
  EVENTS
---------------------------------------------------------------------------
*/

qx.Proto._onmouseup = function(e) {
  this.execute();
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

  // Dispose children
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

  if (this._shortcutObject)
  {
    this._shortcutObject.dispose();
    this._shortcutObject = null;
  }

  if (this._arrowObject)
  {
    this._arrowObject.dispose();
    this._arrowObject = null;
  }

  // Remove event listeners
  this.removeEventListener("mouseup", this._onmouseup);

  return qx.ui.layout.HorizontalBoxLayout.prototype.dispose.call(this);
}
