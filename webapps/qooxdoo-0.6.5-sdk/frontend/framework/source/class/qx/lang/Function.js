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

#module(core)

************************************************************************ */


/**
 * Collection of helper methods operatinf on functions.
 */
qx.OO.defineClass("qx.lang.Function");





/*
---------------------------------------------------------------------------
  SIMPLE RETURN METHODS
---------------------------------------------------------------------------
*/

/**
 * Simply return true.
 *
 * @return {Boolean} Always returns true.
 */
qx.lang.Function.returnTrue = function() {
  return true;
};


/**
 * Simply return false.
 *
 * @return {Boolean} Always returns false.
 */

qx.lang.Function.returnFalse = function() {
  return false;
};


/**
 * Simply return null.
 *
 * @return {var} Always returns null.
 */

qx.lang.Function.returnNull = function() {
  return null;
};


/**
 * Return "this".
 *
 * @return {Object} Always returns "this".
 */
qx.lang.Function.returnThis = function() {
  return this;
};


/**
 * Used to return a refernce to an singleton. Classes which should act as singletons can use this
 * function to implement the "getInstance" methods.
 *
 * @returns {Object} Singleton instance of the class this method is bound to.
 */
qx.lang.Function.returnInstance = function()
{
  if (!this._instance)
  {
    this._instance = new this;

    /*
    if (this._instance.debug) {
      this._instance.debug("Created...");
    }*/
  }

  return this._instance;
};


/**
 * Simply return 0.
 *
 * @return {Number} Always returns 0.
 */

qx.lang.Function.returnZero = function() {
  return 0;
};


/**
 * Simply return a negative index (-1).
 *
 * @return {Number} Always returns -1.
 */

qx.lang.Function.returnNegativeIndex = function() {
  return -1;
};
