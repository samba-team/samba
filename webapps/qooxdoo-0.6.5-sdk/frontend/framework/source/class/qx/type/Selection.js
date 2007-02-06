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



************************************************************************ */

/**
 * Helper for qx.manager.selection.SelectionManager, contains data for selections
 *
 * @param vManager {Object} a class which implements a getItemHashCode(oItem) method
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

/**
 * Add an item to the selection
 *
 * @param oItem {var} item to add
 */
qx.Proto.add = function(oItem) {
  this._storage[this.getItemHashCode(oItem)] = oItem;
};


/**
 * Remove an item from the selection
 *
 * @param oItem {var} item to remove
 */
qx.Proto.remove = function(oItem) {
  delete this._storage[this.getItemHashCode(oItem)];
};


/**
 * Remove all items from the selection
 */
qx.Proto.removeAll = function() {
  this._storage = {};
};


/**
 * Check whether the selection contains a given item
 *
 * @param oItem {var} item to check for
 * @return {Boolean} whether the selection contains the item
 */
qx.Proto.contains = function(oItem) {
  return this.getItemHashCode(oItem) in this._storage;
};


/**
 * Convert selection to an array
 *
 * @return {Array} array representation of the selection
 */
qx.Proto.toArray = function()
{
  var res = [];

  for (var key in this._storage) {
    res.push(this._storage[key]);
  }

  return res;
};


/**
 * Return first element of the Selection
 *
 * @return {var} first item of the selection
 */
qx.Proto.getFirst = function()
{
  for (var key in this._storage) {
    return this._storage[key];
  }
}


/**
 * Get a string representation of the Selection. The return value can be used to compare selections.
 *
 * @return {String} string representation of the Selection
 */
qx.Proto.getChangeValue = function()
{
  var sb = [];

  for (var hc in this._storage) {
    sb.push(hc);
  }

  sb.sort();
  return sb.join(";");
};


/**
 * Compute a hash code for an item using the manager
 *
 * @param oItem {var} the item
 * @return {var} unique hash code for the item
 */
qx.Proto.getItemHashCode = function(oItem) {
  return this._manager.getItemHashCode(oItem);
};


/**
 * Whether the selection is empty
 *
 * @return {Boolean} whether the selection is empty
 */
qx.Proto.isEmpty = function() {
  return qx.lang.Object.isEmpty(this._storage);
};




/*
---------------------------------------------------------------------------
  DISPOSER
---------------------------------------------------------------------------
*/

/**
 * Destructor
 */
qx.Proto.dispose = function()
{
  if (this.getDisposed()) {
    return;
  }

  this._storage = null;
  this._manager = null;

  qx.core.Object.prototype.dispose.call(this);
};