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
#module(theme_color)

************************************************************************ */

qx.OO.defineClass("qx.theme.color.WindowsRoyale", qx.renderer.theme.ColorTheme,
function() {
  qx.renderer.theme.ColorTheme.call(this, "Windows Royale");
});




/*
---------------------------------------------------------------------------
  DEFINE COLORS
---------------------------------------------------------------------------
*/

qx.Proto._colors = qx.lang.Object.carefullyMergeWith({
  activeborder : [ 212,208,200 ],
  activecaption : [ 51,94,168 ],
  appworkspace : [ 128,128,128 ],
  background : [ 0,0,64 ],
  buttonface : [ 235,233,237 ],
  buttonhighlight : [ 255,255,255 ],
  buttonshadow : [ 167,166,170 ],
  buttontext : [ 0,0,0 ],
  captiontext : [ 255,255,255 ],
  graytext : [ 167,166,170 ],
  highlight : [ 51,94,168 ],
  highlighttext : [ 255,255,255 ],
  inactiveborder : [ 212,208,200 ],
  inactivecaption : [ 111,161,217 ],
  inactivecaptiontext : [ 255,255,255 ],
  infobackground : [ 255,255,225 ],
  infotext : [ 0,0,0 ],
  menu : [ 255,255,255 ],
  menutext : [ 0,0,0 ],
  scrollbar : [ 212,208,200 ],
  threeddarkshadow : [ 133,135,140 ],
  threedface : [ 235,233,237 ],
  threedhighlight : [ 255,255,255 ],
  threedlightshadow : [ 220,223,228 ],
  threedshadow : [ 167,166,170 ],
  window : [ 255,255,255 ],
  windowframe : [ 0,0,0 ],
  windowtext : [ 0,0,0 ]
}, qx.Super.prototype._colors);





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

qx.manager.object.ColorManager.getInstance().registerColorTheme(qx.Class);
