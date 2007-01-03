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

#module(theme_icon)
#resource(images:icon/nuvola)

************************************************************************ */

qx.OO.defineClass("qx.theme.icon.Nuvola", qx.renderer.theme.IconTheme,
function() {
  qx.renderer.theme.IconTheme.call(this, "Nuvola");
});




/*
---------------------------------------------------------------------------
  DEFAULT SETTINGS
---------------------------------------------------------------------------
*/

qx.Settings.setDefault("imageUri", qx.Settings.getValueOfClass("qx.manager.object.AliasManager", "resourceUri") + "/icon/nuvola");




/*
---------------------------------------------------------------------------
  DEFER SINGLETON INSTANCE
---------------------------------------------------------------------------
*/

/**
 * Singleton Instance Getter
 */
qx.Class.getInstance = qx.util.Return.returnInstance;





/*
---------------------------------------------------------------------------
  REGISTER TO MANAGER
---------------------------------------------------------------------------
*/

qx.manager.object.ImageManager.getInstance().registerIconTheme(qx.Class);
