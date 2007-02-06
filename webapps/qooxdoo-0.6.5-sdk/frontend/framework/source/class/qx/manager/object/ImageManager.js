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

#module(ui_core)
#optional(qx.ui.form.Button)
#embed(qx.icontheme/16/apps/preferences-desktop-theme.png)
#require(qx.manager.object.ImagePreloaderManager)

************************************************************************ */

/*!
  This singleton manage the global image path (prefix) and allowes themed icons.
*/
qx.OO.defineClass("qx.manager.object.ImageManager", qx.manager.object.ObjectManager,
function()
{
  qx.manager.object.ObjectManager.call(this);

  // Themes
  this._iconThemes = {};
  this._widgetThemes = {};

  // Contains known image sources (all of them, if loaded or not)
  // The value is a number which represents the number of image
  // instances which use this source
  this._sources = {};

  // Change event connection to AliasManager
  qx.manager.object.AliasManager.getInstance().addEventListener("change", this._onaliaschange, this);
});




/*
---------------------------------------------------------------------------
  DEFAULT SETTINGS
---------------------------------------------------------------------------
*/

/*
  Make sure to select an icon theme that is compatible to the license you
  chose to receive the qooxdoo code under. For more information, please
  see the LICENSE file in the project's top-level directory.
 */
qx.Settings.setDefault("iconTheme", "qx.theme.icon.Nuvola");

qx.Settings.setDefault("widgetTheme", "qx.theme.widget.Windows");






/*
---------------------------------------------------------------------------
  PROPERTIES
---------------------------------------------------------------------------
*/

qx.OO.addProperty({ name : "iconTheme", type : "object", instance : "qx.renderer.theme.IconTheme" });
qx.OO.addProperty({ name : "widgetTheme", type : "object", instance : "qx.renderer.theme.WidgetTheme" });






/*
---------------------------------------------------------------------------
  REGISTRATION
---------------------------------------------------------------------------
*/

qx.Proto.registerIconTheme = function(vThemeClass)
{
  this._iconThemes[vThemeClass.classname] = vThemeClass;

  if (vThemeClass.classname == this.getSetting("iconTheme")) {
    this.setIconTheme(vThemeClass.getInstance());
  }
}

qx.Proto.registerWidgetTheme = function(vThemeClass)
{
  this._widgetThemes[vThemeClass.classname] = vThemeClass;

  if (vThemeClass.classname == this.getSetting("widgetTheme")) {
    this.setWidgetTheme(vThemeClass.getInstance());
  }
}

qx.Proto.setIconThemeById = function(vId) {
  this.setIconTheme(this._iconThemes[vId].getInstance());
}

qx.Proto.setWidgetThemeById = function(vId) {
  this.setWidgetTheme(this._widgetThemes[vId].getInstance());
}







/*
---------------------------------------------------------------------------
  EVENTS
---------------------------------------------------------------------------
*/

qx.Proto._onaliaschange = function() {
  this._updateImages();
}






/*
---------------------------------------------------------------------------
  MODIFIERS
---------------------------------------------------------------------------
*/

qx.Proto._modifyIconTheme = function(propValue, propOldValue, propData)
{
  propValue ? qx.manager.object.AliasManager.getInstance().add("icon", propValue.getSetting("imageUri")) : qx.manager.object.AliasManager.getInstance().remove("icon");
  return true;
}

qx.Proto._modifyWidgetTheme = function(propValue, propOldValue, propData)
{
  propValue ? qx.manager.object.AliasManager.getInstance().add("widget", propValue.getSetting("imageUri")) : qx.manager.object.AliasManager.getInstance().remove("widget");
  return true;
}






/*
---------------------------------------------------------------------------
  PRELOAD API
---------------------------------------------------------------------------
*/

qx.Proto.getPreloadImageList = function()
{
  var vPreload = {};

  for (var vSource in this._sources)
  {
    if (this._sources[vSource]) {
      vPreload[vSource] = true;
    }
  }

  return vPreload;
}

qx.Proto.getPostPreloadImageList = function()
{
  var vPreload = {};

  for (var vSource in this._sources)
  {
    if (!this._sources[vSource]) {
      vPreload[vSource] = true;
    }
  }

  return vPreload;
}







/*
---------------------------------------------------------------------------
  INTERNAL HELPER
---------------------------------------------------------------------------
*/

qx.Proto._updateImages = function()
{
  var vAll = this.getAll();
  var vPreMgr = qx.manager.object.ImagePreloaderManager.getInstance();
  var vAliasMgr = qx.manager.object.AliasManager.getInstance();
  var vObject;

  // Recreate preloader of affected images
  for (var vHashCode in vAll)
  {
    vObject = vAll[vHashCode];
    vObject.setPreloader(vPreMgr.create(vAliasMgr.resolvePath(vObject.getSource())));
  }

  return true;
}







/*
---------------------------------------------------------------------------
  UTILITY
---------------------------------------------------------------------------
*/

// TODO: rename to createIconThemeList
qx.Proto.createThemeList = function(vParent, xCor, yCor)
{
  var vButton;
  var vThemes = this._iconThemes;
  var vIcon = "icon/16/apps/preferences-desktop-theme.png";
  var vPrefix = "Icon Theme: ";
  var vEvent = "execute";

  for (var vId in vThemes)
  {
    var vObj = vThemes[vId].getInstance();
    var vButton = new qx.ui.form.Button(vPrefix + vObj.getTitle(), vIcon);

    vButton.setLocation(xCor, yCor);
    vButton.addEventListener(vEvent, new Function("qx.manager.object.ImageManager.getInstance().setIconThemeById('" + vId + "')"));

    vParent.add(vButton);

    yCor += 30;
  }
}

qx.Proto.preload = function(vPath) {
  qx.manager.object.ImagePreloaderManager.getInstance().create(qx.manager.object.AliasManager.getInstance().resolvePath(vPath));
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

  // Change event connection to AliasManager
  qx.manager.object.AliasManager.getInstance().removeEventListener("change", this._onaliaschange, this);

  // Delete counter field
  this._sources = null;

  // Themes
  this._iconThemes = null;
  this._widgetThemes = null;

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
qx.Class.getInstance = qx.lang.Function.returnInstance;
