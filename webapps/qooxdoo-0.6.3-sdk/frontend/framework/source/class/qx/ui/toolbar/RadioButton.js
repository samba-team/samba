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

#module(ui_toolbar)

************************************************************************ */

qx.OO.defineClass("qx.ui.toolbar.RadioButton", qx.ui.toolbar.CheckBox,
function(vText, vIcon, vChecked) {
  qx.ui.toolbar.CheckBox.call(this, vText, vIcon, vChecked);
});




/*
---------------------------------------------------------------------------
  PROPERTIES
---------------------------------------------------------------------------
*/

/*!
  The assigned qx.manager.selection.RadioManager which handles the switching between registered buttons
*/
qx.OO.addProperty({ name : "manager", type : "object", instance : "qx.manager.selection.RadioManager", allowNull : true });

/*!
  The name of the radio group. All the radio elements in a group (registered by the same manager)
  have the same name (and could have a different value).
*/
qx.OO.addProperty({ name : "name", type : "string" });

/*!
  Prohibit the deselction of the checked radio button when clicked on it.
*/
qx.OO.addProperty({ name : "disableUncheck", type : "boolean", defaultValue : false });






/*
---------------------------------------------------------------------------
  MODIFIER
---------------------------------------------------------------------------
*/

qx.Proto._modifyChecked = function(propValue, propOldValue, propData)
{
  qx.ui.toolbar.CheckBox.prototype._modifyChecked.call(this, propValue, propOldValue, propData);

  var vManager = this.getManager();
  if (vManager) {
    vManager.handleItemChecked(this, propValue);
  }

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





/*
---------------------------------------------------------------------------
  EVENTS
---------------------------------------------------------------------------
*/

qx.Proto._onmouseup = function(e)
{
  this.setCapture(false);

  if (!this.hasState("abandoned"))
  {
    this.addState("over");
    this.setChecked(this.getDisableUncheck() || !this.getChecked());
    this.execute();
  }

  this.removeState("abandoned");
  this.removeState("pressed");

  e.stopPropagation();
}
