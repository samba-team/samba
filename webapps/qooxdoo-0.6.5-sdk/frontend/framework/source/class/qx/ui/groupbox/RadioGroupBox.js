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

#module(ui_form)

************************************************************************ */

qx.OO.defineClass("qx.ui.groupbox.RadioGroupBox", qx.ui.groupbox.GroupBox,
function(vLegend) {
  qx.ui.groupbox.GroupBox.call(this, vLegend);
});

qx.Proto._createLegendObject = function()
{
  this._legendObject = new qx.ui.form.RadioButton;
  this._legendObject.setAppearance("radio-button-field-set-legend");
  this._legendObject.setChecked(true);

  this.add(this._legendObject);
}

qx.Proto.setIcon = qx.Proto.getIcon = null;
