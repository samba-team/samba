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

#module(ui_buttonview)

************************************************************************ */

qx.OO.defineClass("qx.ui.pageview.buttonview.Pane", qx.ui.pageview.AbstractPane,
function() {
  qx.ui.pageview.AbstractPane.call(this);
});

qx.OO.changeProperty({ name : "appearance", type : "string", defaultValue : "bar-view-pane" });







/*
---------------------------------------------------------------------------
  APPEARANCE ADDITIONS
---------------------------------------------------------------------------
*/

qx.Proto._applyStateAppearance = function()
{
  var vPos = this.getParent().getBarPosition();

  this._states.barHorizontal = vPos === "top" || vPos === "bottom";

  qx.ui.pageview.AbstractButton.prototype._applyStateAppearance.call(this);
}
