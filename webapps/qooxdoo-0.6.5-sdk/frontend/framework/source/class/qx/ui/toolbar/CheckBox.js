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

#module(ui_toolbar)

************************************************************************ */

qx.OO.defineClass("qx.ui.toolbar.CheckBox", qx.ui.toolbar.Button,
function(vText, vIcon, vChecked)
{
  qx.ui.toolbar.Button.call(this, vText, vIcon);

  if (vChecked != null) {
    this.setChecked(vChecked);
  }
});



/*
---------------------------------------------------------------------------
  PROPERTIES
---------------------------------------------------------------------------
*/

qx.OO.addProperty({ name : "checked", type : "boolean", defaultValue : false, getAlias:"isChecked" });





/*
---------------------------------------------------------------------------
  MODIFIER
---------------------------------------------------------------------------
*/

qx.Proto._modifyChecked = function(propValue, propOldValue, propData)
{
  propValue ? this.addState("checked") : this.removeState("checked");
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
    this.setChecked(!this.getChecked());
    this.execute();
  }

  this.removeState("abandoned");
  this.removeState("pressed");

  e.stopPropagation();
}
