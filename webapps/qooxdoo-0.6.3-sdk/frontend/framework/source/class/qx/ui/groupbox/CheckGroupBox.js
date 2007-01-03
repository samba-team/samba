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

#module(ui_form)

************************************************************************ */

qx.OO.defineClass("qx.ui.groupbox.CheckGroupBox", qx.ui.groupbox.GroupBox,
function(vLegend) {
  qx.ui.groupbox.GroupBox.call(this, vLegend);
});

qx.Proto._createLegendObject = function()
{
  this._legendObject = new qx.ui.form.CheckBox;
  this._legendObject.setAppearance("check-box-field-set-legend");
  this._legendObject.setChecked(true);

  this.add(this._legendObject);
}

qx.Proto.setIcon = qx.Proto.getIcon = null;
