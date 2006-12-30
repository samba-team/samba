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

#module(theme_color)

************************************************************************ */

qx.OO.defineClass("qx.theme.color.WindowsLunaBlue", qx.renderer.theme.ColorTheme,
function() {
  qx.renderer.theme.ColorTheme.call(this, "Windows Luna Blue");
});




/*
---------------------------------------------------------------------------
  DEFINE COLORS
---------------------------------------------------------------------------
*/

qx.Proto._colors = qx.lang.Object.carefullyMergeWith({
  activeborder : [ 212,208,200 ],
  activecaption : [ 0,84,227 ],
  appworkspace : [ 128,128,128 ],
  background : [ 0,78,152 ],
  buttonface : [ 236,233,216 ],
  buttonhighlight : [ 255,255,255 ],
  buttonshadow : [ 172,168,153 ],
  buttontext : [ 0,0,0 ],
  captiontext : [ 255,255,255 ],
  graytext : [ 172,168,153 ],
  highlight : [ 49,106,197 ],
  highlighttext : [ 255,255,255 ],
  inactiveborder : [ 212,208,200 ],
  inactivecaption : [ 122,150,223 ],
  inactivecaptiontext : [ 216,228,248 ],
  infobackground : [ 255,255,225 ],
  infotext : [ 0,0,0 ],
  menu : [ 255,255,255 ],
  menutext : [ 0,0,0 ],
  scrollbar : [ 212,208,200 ],
  threeddarkshadow : [ 113,111,100 ],
  threedface : [ 236,233,216 ],
  threedhighlight : [ 255,255,255 ],
  threedlightshadow : [ 241,239,226 ],
  threedshadow : [ 172,168,153 ],
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
