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


************************************************************************ */

/*!
  This class allows basic managment of assigned objects.
*/
qx.OO.defineClass("qx.manager.object.ObjectManager", qx.core.Target,
function()
{
  qx.core.Target.call(this);

  this._objects = {};
});





/*
---------------------------------------------------------------------------
  USER API
---------------------------------------------------------------------------
*/

qx.Proto.add = function(vObject)
{
  if (this.getDisposed()) {
    return;
  }

  this._objects[vObject.toHashCode()] = vObject;
  return true;
}

qx.Proto.remove = function(vObject)
{
  if (this.getDisposed()) {
    return;
  }

  delete this._objects[vObject.toHashCode()];
  return true;
}

qx.Proto.has = function(vObject) {
  return this._objects[vObject.toHashCode()] != null;
}

qx.Proto.get = function(vObject) {
  return this._objects[vObject.toHashCode()];
}

qx.Proto.getAll = function() {
  return this._objects;
}

qx.Proto.enableAll = function()
{
  for (var vHashCode in this._objects) {
    this._objects[vHashCode].setEnabled(true);
  };
};

qx.Proto.disableAll = function()
{
  for (var vHashCode in this._objects) {
    this._objects[vHashCode].setEnabled(false);
  };
};





/*
---------------------------------------------------------------------------
  DISPOSER
---------------------------------------------------------------------------
*/

qx.Proto.dispose = function()
{
  if(this.getDisposed()) {
    return;
  }

  if (this._objects)
  {
    for (var i in this._objects) {
      delete this._objects[i];
    }

    delete this._objects;
  }

  return qx.core.Target.prototype.dispose.call(this);
}
