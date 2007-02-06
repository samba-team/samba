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
#embed(qx.widgettheme/menu/radiobutton.gif)
#embed(qx.static/image/blank.gif)

************************************************************************ */

qx.OO.defineClass("qx.ui.menu.RadioButton", qx.ui.menu.CheckBox,
function(vLabel, vCommand, vChecked)
{
  qx.ui.menu.CheckBox.call(this, vLabel, vCommand, vChecked);

  qx.manager.object.ImageManager.getInstance().preload("widget/menu/radiobutton.gif");
});


/*
---------------------------------------------------------------------------
  PROPERTIES
---------------------------------------------------------------------------
*/

qx.OO.changeProperty({ name : "appearance", type : "string", defaultValue : "menu-radio-button" });

/*!
  The assigned qx.manager.selection.RadioManager which handles the switching between registered buttons
*/
qx.OO.addProperty({ name : "manager", type : "object", instance : "qx.manager.selection.RadioManager", allowNull : true });






/*
---------------------------------------------------------------------------
  MODIFIER
---------------------------------------------------------------------------
*/

qx.Proto._modifyChecked = function(propValue, propOldValue, propData)
{
  var vManager = this.getManager();

  if (vManager)
  {
    if (propValue)
    {
      vManager.setSelected(this);
    }
    else if (vManager.getSelected() == this)
    {
      vManager.setSelected(null);
    }
  }

  propValue ? this.addState("checked") : this.removeState("checked");
  this.getIconObject().setSource(propValue ? "widget/menu/radiobutton.gif" : "static/image/blank.gif");

  return true;
}

qx.Proto._modifyManager = function(propValue, propOldValue, propData)
{
  if (propOldValue) {
    propOldValue.remove(this);
  }

  if (propValue) {
    propValue.add(this);
  }

  return true;
}

qx.Proto._modifyName = function(propValue, propOldValue, propData)
{
  if (this.getManager()) {
    this.getManager().setName(propValue);
  }

  return true;
}





/*
---------------------------------------------------------------------------
  EXECUTE
---------------------------------------------------------------------------
*/

qx.Proto.execute = function()
{
  this.setChecked(true);

  // Intentionally bypass superclass and call super.super.execute
  qx.ui.menu.Button.prototype.execute.call(this);
}
