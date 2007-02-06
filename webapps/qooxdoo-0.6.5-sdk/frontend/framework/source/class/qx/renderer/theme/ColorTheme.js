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
#after(qx.manager.object.ColorManager)

************************************************************************ */

qx.OO.defineClass("qx.renderer.theme.ColorTheme", qx.core.Object,
function(vTitle)
{
  qx.core.Object.call(this);

  this._compiledColors = {};
  this.setTitle(vTitle);
});





/*
---------------------------------------------------------------------------
  PROPERTIES
---------------------------------------------------------------------------
*/

qx.OO.addProperty({ name : "title", type : "string", allowNull : false, defaultValue : "" });





/*
---------------------------------------------------------------------------
  DATA
---------------------------------------------------------------------------
*/

qx.Proto._needsCompilation = true;
qx.Proto._colors = {};




/*
---------------------------------------------------------------------------
  PUBLIC METHODS
---------------------------------------------------------------------------
*/

qx.Proto.getValueByName = function(vName) {
  return this._colors[vName] || "";
}

qx.Proto.getStyleByName = function(vName) {
  return this._compiledColors[vName] || "";
}






/*
---------------------------------------------------------------------------
  PRIVATE METHODS
---------------------------------------------------------------------------
*/

qx.Proto.compile = function()
{
  if (!this._needsCompilation) {
    return;
  }

  for (var vName in qx.renderer.color.Color.themedNames) {
    this._compileValue(vName);
  }

  this._needsCompilation = false;
}

qx.Proto._compileValue = function(vName)
{
  var v = this._colors[vName];
  this._compiledColors[vName] = v ? qx.renderer.color.Color.rgb2style.apply(this, this._colors[vName]) : vName;
}

qx.Proto._register = function() {
  return qx.manager.object.ColorManager.getInstance().registerTheme(this);
}






/*
---------------------------------------------------------------------------
  DISPOSER
---------------------------------------------------------------------------
*/

qx.Proto.dispose = function()
{
  if (this.getDisposed()) {
    return;
  }

  delete this._colors;
  delete this._compiledColors;

  qx.core.Object.prototype.dispose.call(this);
}
