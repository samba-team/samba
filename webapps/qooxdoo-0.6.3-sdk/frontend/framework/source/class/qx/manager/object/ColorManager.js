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

#module(ui_core)
#optional(qx.ui.form.Button)

************************************************************************ */

qx.OO.defineClass("qx.manager.object.ColorManager", qx.manager.object.ObjectManager,
function()
{
  qx.manager.object.ObjectManager.call(this);

  // Themes
  this._colorThemes = {};

  // Contains the qx.renderer.color.ColorObjects which
  // represent a themed color.
  this._dependentObjects = {};
});





/*
---------------------------------------------------------------------------
  DEFAULT SETTINGS
---------------------------------------------------------------------------
*/

qx.Settings.setDefault("colorTheme", "qx.theme.color.WindowsRoyale");




/*
---------------------------------------------------------------------------
  PROPERTIES
---------------------------------------------------------------------------
*/

qx.OO.addProperty({ name : "colorTheme", type : "object", allowNull : false, instance : "qx.renderer.theme.ColorTheme" });






/*
---------------------------------------------------------------------------
  REGISTRATION
---------------------------------------------------------------------------
*/

qx.Proto.registerColorTheme = function(vThemeClass)
{
  this._colorThemes[vThemeClass.classname] = vThemeClass;

  if (vThemeClass.classname == this.getSetting("colorTheme")) {
    this.setColorTheme(vThemeClass.getInstance());
  }
}

qx.Proto.setColorThemeById = function(vId) {
  this.setColorTheme(this._colorThemes[vId].getInstance());
}






/*
---------------------------------------------------------------------------
  PUBLIC METHODS FOR qx.renderer.color.ColorOBJECTS
---------------------------------------------------------------------------
*/

qx.Proto.add = function(oObject)
{
  var vValue = oObject.getValue();

  this._objects[vValue] = oObject;

  if (oObject.isThemedColor()) {
    this._dependentObjects[vValue] = oObject;
  }
}

qx.Proto.remove = function(oObject)
{
  var vValue = oObject.getValue();

  delete this._objects[vValue];
  delete this._dependentObjects[vValue];
}

qx.Proto.has = function(vValue) {
  return this._objects[vValue] != null;
}

qx.Proto.get = function(vValue) {
  return this._objects[vValue];
}







/*
---------------------------------------------------------------------------
  MODIFIER
---------------------------------------------------------------------------
*/

qx.Proto._modifyColorTheme = function(propValue, propOldValue, propData)
{
  propValue.compile();

  for (var i in this._dependentObjects) {
    this._dependentObjects[i]._updateTheme(propValue);
  }

  return true;
}








/*
---------------------------------------------------------------------------
  UTILITY
---------------------------------------------------------------------------
*/

qx.Proto.createThemeList = function(vParent, xCor, yCor)
{
  var vButton;
  var vThemes = this._colorThemes;
  var vIcon = "icon/16/colors.png";
  var vPrefix = "Color Theme: ";
  var vEvent = "execute";

  for (var vId in vThemes)
  {
    var vObj = vThemes[vId].getInstance();
    var vButton = new qx.ui.form.Button(vPrefix + vObj.getTitle(), vIcon);

    vButton.setLocation(xCor, yCor);
    vButton.addEventListener(vEvent, new Function("qx.manager.object.ColorManager.getInstance().setColorThemeById('" + vId + "')"));

    vParent.add(vButton);

    yCor += 30;
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

  // Themes
  this._colorThemes = null;

  // Cleanup dependent objects
  for (var i in this._dependentObjects) {
    delete this._dependentObjects[i];
  }

  delete this._dependentObjects;

  return qx.manager.object.ObjectManager.prototype.dispose.call(this);
}







/*
---------------------------------------------------------------------------
  DEFER SINGLETON INSTANCE
---------------------------------------------------------------------------
*/

/**
 * Singleton Instance Getter
 */
qx.Class.getInstance = qx.util.Return.returnInstance;
