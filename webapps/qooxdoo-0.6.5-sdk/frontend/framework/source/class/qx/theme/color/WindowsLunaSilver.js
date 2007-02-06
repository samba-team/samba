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

#module(theme_color)

************************************************************************ */

/**
 * Windows luna silver color theme
 */
qx.OO.defineClass("qx.theme.color.WindowsLunaSilver", qx.renderer.theme.ColorTheme,
function() {
  qx.renderer.theme.ColorTheme.call(this, "Windows Luna Silver");
});




/*
---------------------------------------------------------------------------
  DEFINE COLORS
---------------------------------------------------------------------------
*/

qx.Proto._colors = qx.lang.Object.carefullyMergeWith({
  activeborder : [ 212,208,200 ],
  activecaption : [ 192,192,192 ],
  appworkspace : [ 128,128,128 ],
  background : [ 88,87,104 ],
  buttonface : [ 224,223,227 ],
  buttonhighlight : [ 255,255,255 ],
  buttonshadow : [ 157,157,161 ],
  buttontext : [ 0,0,0 ],
  captiontext : [ 14,16,16 ],
  graytext : [ 172,168,153 ],
  highlight : [ 178,180,191 ],
  highlighttext : [ 0,0,0 ],
  inactiveborder : [ 212,208,200 ],
  inactivecaption : [ 255,255,255 ],
  inactivecaptiontext : [ 162,161,161 ],
  infobackground : [ 255,255,225 ],
  infotext : [ 0,0,0 ],
  menu : [ 255,255,255 ],
  menutext : [ 0,0,0 ],
  scrollbar : [ 212,208,200 ],
  threeddarkshadow : [ 113,111,100 ],
  threedface : [ 224,223,227 ],
  threedhighlight : [ 255,255,255 ],
  threedlightshadow : [ 241,239,226 ],
  threedshadow : [ 157,157,161 ],
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
qx.Class.getInstance = qx.lang.Function.returnInstance;




/*
---------------------------------------------------------------------------
  REGISTER TO MANAGER
---------------------------------------------------------------------------
*/

qx.manager.object.ColorManager.getInstance().registerColorTheme(qx.Class);
