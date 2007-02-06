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

************************************************************************ */

/*!
  Some common used border styles.
*/
qx.OO.defineClass("qx.renderer.border.BorderPresets", qx.core.Object, function()
{
  qx.core.Object.call(this);

  this.black = new qx.renderer.border.Border(1, "solid", "black");
  this.white = new qx.renderer.border.Border(1, "solid", "white");
  this.none = new qx.renderer.border.Border(0, "none");

  this.inset = new qx.renderer.border.BorderObject(2, "inset");
  this.outset = new qx.renderer.border.BorderObject(2, "outset");
  this.groove = new qx.renderer.border.BorderObject(2, "groove");
  this.ridge = new qx.renderer.border.BorderObject(2, "ridge");
  this.thinInset = new qx.renderer.border.BorderObject(1, "inset");
  this.thinOutset = new qx.renderer.border.BorderObject(1, "outset");

  this.verticalDivider = new qx.renderer.border.BorderObject(1, "inset");
  this.verticalDivider.setLeftWidth(0);
  this.verticalDivider.setRightWidth(0);

  this.horizontalDivider = new qx.renderer.border.BorderObject(1, "inset");
  this.horizontalDivider.setTopWidth(0);
  this.horizontalDivider.setBottomWidth(0);

  this.shadow = new qx.renderer.border.BorderObject(1, "solid", "threedshadow");
  this.lightShadow = new qx.renderer.border.BorderObject(1, "solid", "threedlightshadow");
  this.info = new qx.renderer.border.BorderObject(1, "solid", "infotext");
});







/*
---------------------------------------------------------------------------
  DEFER SINGLETON INSTANCE
---------------------------------------------------------------------------
*/

/**
 * Singleton Instance Getter
 */
qx.Class.getInstance = qx.lang.Function.returnInstance;
