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

#module(ui_basic)

************************************************************************ */

qx.OO.defineClass("qx.renderer.font.FontObject", qx.renderer.font.Font,
function(vSize, vName)
{
  this._dependentObjects = {};

  qx.renderer.font.Font.call(this, vSize, vName);
});




/*
---------------------------------------------------------------------------
  WIDGET CONNECTION
---------------------------------------------------------------------------
*/

qx.Proto.addListenerWidget = function(o) {
  this._dependentObjects[o.toHashCode()] = o;
}

qx.Proto.removeListenerWidget = function(o) {
  delete this._dependentObjects[o.toHashCode()];
}

qx.Proto._sync = function(vEdge)
{
  var vAll = this._dependentObjects;
  var vCurrent;

  for (vKey in vAll)
  {
    vCurrent = vAll[vKey];

    if (vCurrent.isCreated()) {
      vCurrent._updateFont(vEdge);
    }
  }
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

  if (typeof this._dependentObjects === "object")
  {
    for (vKey in this._dependentObjects) {
      delete this._dependentObjects[vKey];
    }

    delete this._dependentObjects;
  }

  return qx.renderer.font.Font.prototype.dispose.call(this);
}
