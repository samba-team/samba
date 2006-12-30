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

#module(ui_core)

************************************************************************ */

qx.OO.defineClass("qx.renderer.color.ColorObject", qx.renderer.color.Color,
function(vValue)
{
  // this.debug("Value: " + vValue);
  this.setValue(vValue);

  if(qx.manager.object.ColorManager.getInstance().has(this._value)) {
    return qx.manager.object.ColorManager.getInstance().get(this._value);
  }

  qx.core.Object.call(this);

  // Register this color object to manager instance
  qx.manager.object.ColorManager.getInstance().add(this);

  // Here will all objects with a dependency to this
  // color stored.
  this._dependentObjects = {};
});




/*
---------------------------------------------------------------------------
  UTILITY
---------------------------------------------------------------------------
*/

qx.renderer.color.ColorObject.fromString = function(vDefString) {
  return new qx.renderer.color.ColorObject(vDefString);
}




/*
---------------------------------------------------------------------------
  PUBLIC METHODS
---------------------------------------------------------------------------
*/

/*!
  Set a new value from selected theme (only for Operating System Colors)
*/
qx.Proto._updateTheme = function(vTheme)
{
  if (!this._isThemedColor) {
    throw new Error("Could not redefine themed value of non os colors!");
  }

  this._applyThemedValue();
  this._syncObjects();
}

qx.Proto._applyThemedValue = function()
{
  var vTheme = qx.manager.object.ColorManager.getInstance().getColorTheme();
  var vRgb = vTheme.getValueByName(this._value);

  if (vRgb)
  {
    this._red = vRgb[0];
    this._green = vRgb[1];
    this._blue = vRgb[2];
  }

  this._style = vTheme.getStyleByName(this._value);
  this._hex = null;
}

qx.Proto._syncObjects = function()
{
  for (var i in this._dependentObjects) {
    this._dependentObjects[i]._updateColors(this, this._style);
  }
}

qx.Proto.setValue = function(vValue)
{
  this._normalize(vValue);
  this._syncObjects();
}





/*
---------------------------------------------------------------------------
  OBJECT MANAGMENT
---------------------------------------------------------------------------
*/

qx.Proto.add = function(vObject) {
  this._dependentObjects[vObject.toHashCode()] = vObject;
}

qx.Proto.remove = function(vObject) {
  delete this._dependentObjects[vObject.toHashCode()];
}






/*
---------------------------------------------------------------------------
  DISPOSER
---------------------------------------------------------------------------
*/

qx.Proto.dispose = function()
{
  if (this.getDisposed()) {
    return true;
  }

  if (this._dependentObjects)
  {
    for (var i in this._dependentObjects) {
      delete this._dependentObjects[i];
    }

    delete this._dependentObjects;
  }

  return qx.renderer.color.Color.prototype.dispose.call(this);
}
