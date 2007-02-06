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

#module(ui_menu)
#embed(qx.widgettheme/menu/checkbox.gif)
#embed(qx.static/image/blank.gif)

************************************************************************ */

/*!
  A checkbox for the menu system.
*/
qx.OO.defineClass("qx.ui.menu.CheckBox", qx.ui.menu.Button,
function(vLabel, vCommand, vChecked)
{
  qx.ui.menu.Button.call(this, vLabel, "static/image/blank.gif", vCommand);

  if (vChecked != null) {
    this.setChecked(vChecked);
  }

  qx.manager.object.ImageManager.getInstance().preload("widget/menu/checkbox.gif");
});



/*
---------------------------------------------------------------------------
  PROPERTIES
---------------------------------------------------------------------------
*/

qx.OO.changeProperty({ name : "appearance", type : "string", defaultValue : "menu-check-box" });
qx.OO.addProperty({ name : "name", type : "string" });
qx.OO.addProperty({ name : "value", type : "string" });
qx.OO.addProperty({ name : "checked", type : "boolean", defaultValue : false, getAlias : "isChecked" });





/*
---------------------------------------------------------------------------
  MODIFIERS
---------------------------------------------------------------------------
*/

qx.Proto._modifyChecked = function(propValue, propOldValue, propData)
{
  propValue ? this.addState("checked") : this.removeState("checked");
  this.getIconObject().setSource(propValue ? "widget/menu/checkbox.gif" : "static/image/blank.gif");

  return true;
}





/*
---------------------------------------------------------------------------
  EXECUTE
---------------------------------------------------------------------------
*/

qx.Proto.execute = function()
{
  this.setChecked(!this.getChecked());
  qx.ui.menu.Button.prototype.execute.call(this);
}
