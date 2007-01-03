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

************************************************************************ */

qx.OO.defineClass("qx.manager.object.AppearanceManager", qx.manager.object.ObjectManager,
function() {
  qx.manager.object.ObjectManager.call(this);

  // Themes
  this._appearanceThemes = {};
});




/*
---------------------------------------------------------------------------
  DEFAULT SETTINGS
---------------------------------------------------------------------------
*/

qx.Settings.setDefault("appearanceTheme", "qx.theme.appearance.Classic");





/*
---------------------------------------------------------------------------
  PROPERTIES
---------------------------------------------------------------------------
*/

qx.OO.addProperty({ name : "appearanceTheme", type : "object", allowNull : false, instance : "qx.renderer.theme.AppearanceTheme" });






/*
---------------------------------------------------------------------------
  REGISTRATION
---------------------------------------------------------------------------
*/

qx.Proto.registerAppearanceTheme = function(vThemeClass)
{
  this._appearanceThemes[vThemeClass.classname] = vThemeClass;

  if (vThemeClass.classname == this.getSetting("appearanceTheme")) {
    this.setAppearanceTheme(vThemeClass.getInstance());
  }
}








/*
---------------------------------------------------------------------------
  MODIFIER
---------------------------------------------------------------------------
*/

qx.Proto._modifyAppearanceTheme = function(propValue, propOldValue, propData)
{
  var vComp = qx.core.Init.getInstance().getComponent();

  if (vComp && vComp.isUiReady()) {
    qx.ui.core.ClientDocument.getInstance()._recursiveAppearanceThemeUpdate(propValue, propOldValue);
  }

  return true;
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
  this._appearanceThemes = null;

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
