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
  Helper for qx.manager.selection.SelectionManager, contains data for selections
*/
qx.OO.defineClass("qx.type.Selection", qx.core.Object,
function(vManager)
{
  qx.core.Object.call(this);

  this._manager = vManager;
  this.removeAll();
});





/*
---------------------------------------------------------------------------
  USER METHODS
---------------------------------------------------------------------------
*/

qx.Proto.add = function(oItem) {
  this._storage[this.getItemHashCode(oItem)] = oItem;
}

qx.Proto.remove = function(oItem) {
  delete this._storage[this.getItemHashCode(oItem)];
}

qx.Proto.removeAll = function() {
  this._storage = {};
}

qx.Proto.contains = function(oItem) {
  return this.getItemHashCode(oItem) in this._storage;
}

qx.Proto.toArray = function()
{
  var res = [];

  for (var key in this._storage) {
    res.push(this._storage[key]);
  }

  return res;
}

qx.Proto.getFirst = function()
{
  for (var key in this._storage) {
    return this._storage[key];
  }
}

qx.Proto.getChangeValue = function()
{
  var sb = [];

  for (var hc in this._storage) {
    sb.push(hc);
  }

  sb.sort();
  return sb.join(";");
}

qx.Proto.getItemHashCode = function(oItem) {
  return this._manager.getItemHashCode(oItem);
}

qx.Proto.isEmpty = function() {
  return qx.lang.Object.isEmpty(this._storage);
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

  this._storage = null;
  this._manager = null;

  qx.core.Object.prototype.dispose.call(this);
}