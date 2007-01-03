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

/*!
  A small helper class to create a special layout handler for qx.ui.menu.Menus
*/
qx.OO.defineClass("qx.ui.menu.Layout", qx.ui.layout.VerticalBoxLayout,
function()
{
  qx.ui.layout.VerticalBoxLayout.call(this);

  this.setAnonymous(true);
});


/*!
  Appearance of the widget
*/
qx.OO.changeProperty({ name : "appearance", type : "string", defaultValue : "menu-layout" });




/*
---------------------------------------------------------------------------
  INIT LAYOUT IMPL
---------------------------------------------------------------------------
*/

/*!
  This creates an new instance of the layout impl this widget uses
*/
qx.Proto._createLayoutImpl = function() {
  return new qx.renderer.layout.MenuLayoutImpl(this);
}
