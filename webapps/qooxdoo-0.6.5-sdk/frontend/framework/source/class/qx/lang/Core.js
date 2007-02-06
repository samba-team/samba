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
 * The intention of this class is to add features to native JavaScript
 * objects so that all browsers operate on a common JavaScript language level
 * (particularly JavaScript 1.6).
 *
 * For reference:
 *
 * * http://www.ecma-international.org/publications/standards/Ecma-262.htm
 * * http://developer.mozilla.org/en/docs/Core_JavaScript_1.5_Reference
 * * http://developer.mozilla.org/en/docs/New_in_JavaScript_1.6
 *
 * The following methods are added if they are not supported natively:
 *
 * * Error.toString()
 * * Array.indexOf()
 * * Array.lastIndexOf()
 * * Array.forEach()
 * * Array.filter()
 * * Array.map()
 * * Array.some()
 * * Array.every()
 * * String.quote()
 */
qx.OO.defineClass("qx.lang.Core");


/*
---------------------------------------------------------------------------
  FEATURE EXTENSION OF NATIVE ERROR OBJECT
---------------------------------------------------------------------------
*/

if (!Error.prototype.toString)
{
  /**
   * Some browsers (e.g. Internet Explorer) do not support to stringify
   * error objects like other browsers usually do. This feature is added to
   * those browsers.
   */
  Error.prototype.toString = function() {
    return this.message;
  };
}







/*
---------------------------------------------------------------------------
  FEATURE EXTENSION OF NATIVE ARRAY OBJECT
---------------------------------------------------------------------------
*/

if (!Array.prototype.indexOf)
{
  /**
   * Returns the first index at which a given element can be found in the array,
   * or <code>-1</code> if it is not present. It compares <code>searchElement</code> to elements of the Array
   * using strict equality (the same method used by the <code>===</code>, or
   * triple-equals, operator).
   *
   * Natively supported in Gecko since version 1.8.
   * http://developer.mozilla.org/en/docs/Core_JavaScript_1.5_Reference:Objects:Array:indexOf
   *
   * @param searchElement {var} Element to locate in the array.
   * @param fromIndex {Integer} The index at which to begin the search. Defaults to 0, i.e. the whole
   *   array will be searched. If the index is greater than or equal to the length of the array,
   *   <code>-1</code> is returned, i.e. the array will not be searched. If negative, it is taken as the
   *   offset from the end of the array. Note that even when the index is negative, the array is still
   *   searched from front to back. If the calculated index is less than 0, the whole array will be searched.
   */
  Array.prototype.indexOf = function(searchElement, fromIndex)
  {
    if (fromIndex == null)
    {
      fromIndex = 0;
    }
    else if (fromIndex < 0)
    {
      fromIndex = Math.max(0, this.length + fromIndex);
    }

    for (var i=fromIndex; i<this.length; i++)
    {
      if (this[i] === searchElement) {
        return i;
      }
    }

    return -1;
  };
}

if (!Array.prototype.lastIndexOf)
{
  /**
   * Returns the last index at which a given element can be found in the array, or <code>-1</code>
   * if it is not present. The array is searched backwards, starting at <code>fromIndex</code>.
   * It compares <code>searchElement</code> to elements of the Array using strict equality
   * (the same method used by the <code>===</code>, or triple-equals, operator).
   *
   * Natively supported in Gecko since version 1.8.
   * http://developer.mozilla.org/en/docs/Core_JavaScript_1.5_Reference:Objects:Array:lastIndexOf
   *
   * @param searchElement {var} Element to locate in the array.
   * @param fromIndex {Integer} The index at which to start searching backwards.
   *   Defaults to the array's length, i.e. the whole array will be searched. If
   *   the index is greater than or equal to the length of the array, the whole array
   *   will be searched. If negative, it is taken as the offset from the end of the
   *   array. Note that even when the index is negative, the array is still searched
   *   from back to front. If the calculated index is less than 0, -1 is returned,
   *   i.e. the array will not be searched.
   */
  Array.prototype.lastIndexOf = function(searchElement, fromIndex)
  {
    if (fromIndex == null)
    {
      fromIndex = this.length-1;
    }
    else if (fromIndex < 0)
    {
      fromIndex = Math.max(0, this.length + fromIndex);
    }

    for (var i=fromIndex; i>=0; i--)
    {
      if (this[i] === searchElement) {
        return i;
      }
    }

    return -1;
  };
}

if (!Array.prototype.forEach)
{
  /**
   * Executes a provided function once per array element.
   *
   * <code>forEach</code> executes the provided function (<code>callback</code>) once for each
   * element present in the array.  <code>callback</code> is invoked only for indexes of the array
   * which have assigned values; it is not invoked for indexes which have been deleted or which
   * have never been assigned values.
   *
   * <code>callback</code> is invoked with three arguments: the value of the element, the index
   * of the element, and the Array object being traversed.
   *
   * If a <code>obj</code> parameter is provided to <code>forEach</code>, it will be used
   * as the <code>this</code> for each invocation of the <code>callback</code>.  If it is not
   * provided, or is <code>null</code>, the global object associated with <code>callback</code>
   * is used instead.
   *
   * <code>forEach</code> does not mutate the array on which it is called.
   *
   * The range of elements processed by <code>forEach</code> is set before the first invocation of
   * <code>callback</code>.  Elements which are appended to the array after the call to
   * <code>forEach</code> begins will not be visited by <code>callback</code>. If existing elements
   * of the array are changed, or deleted, their value as passed to <code>callback</code> will be
   * the value at the time <code>forEach</code> visits them; elements that are deleted are not visited.
   *
   * Natively supported in Gecko since version 1.8.
   * http://developer.mozilla.org/en/docs/Core_JavaScript_1.5_Reference:Objects:Array:forEach
   *
   * @param callback {Function} Function to execute for each element.
   * @param obj {Object} Object to use as this when executing callback.
   */
  Array.prototype.forEach = function(callback, obj)
  {
    // The array length should be fixed, like in the native implementation.
    var l = this.length;

    for (var i=0; i<l; i++) {
      callback.call(obj, this[i], i, this);
    }
  };
}

if (!Array.prototype.filter)
{
  /**
   * Creates a new array with all elements that pass the test implemented by the provided
   * function.
   *
   * <code>filter</code> calls a provided <code>callback</code> function once for each
   * element in an array, and constructs a new array of all the values for which
   * <code>callback</code> returns a true value.  <code>callback</code> is invoked only
   * for indexes of the array which have assigned values; it is not invoked for indexes
   * which have been deleted or which have never been assigned values.  Array elements which
   * do not pass the <code>callback</code> test are simply skipped, and are not included
   * in the new array.
   *
   * <code>callback</code> is invoked with three arguments: the value of the element, the
   * index of the element, and the Array object being traversed.
   *
   * If a <code>obj</code> parameter is provided to <code>filter</code>, it will
   * be used as the <code>this</code> for each invocation of the <code>callback</code>.
   * If it is not provided, or is <code>null</code>, the global object associated with
   * <code>callback</code> is used instead.
   *
   * <code>filter</code> does not mutate the array on which it is called. The range of
   * elements processed by <code>filter</code> is set before the first invocation of
   * <code>callback</code>. Elements which are appended to the array after the call to
   * <code>filter</code> begins will not be visited by <code>callback</code>. If existing
   * elements of the array are changed, or deleted, their value as passed to <code>callback</code>
   * will be the value at the time <code>filter</code> visits them; elements that are deleted
   * are not visited.
   *
   * Natively supported in Gecko since version 1.8.
   * http://developer.mozilla.org/en/docs/Core_JavaScript_1.5_Reference:Objects:Array:filter
   *
   * @param callback {Function} Function to test each element of the array.
   * @param obj {Object} Object to use as <code>this</code> when executing <code>callback</code>.
   */
  Array.prototype.filter = function(callback, obj)
  {
    // The array length should be fixed, like in the native implementation.
    var l = this.length;
    var res = [];

    for (var i=0; i<l; i++)
    {
      if (callback.call(obj, this[i], i, this)) {
        res.push(this[i]);
      }
    }

    return res;
  };
}

if (!Array.prototype.map)
{
  /**
   * Creates a new array with the results of calling a provided function on every element in this array.
   *
   * <code>map</code> calls a provided <code>callback</code> function once for each element in an array,
   * in order, and constructs a new array from the results.  <code>callback</code> is invoked only for
   * indexes of the array which have assigned values; it is not invoked for indexes which have been
   * deleted or which have never been assigned values.
   *
   * <code>callback</code> is invoked with three arguments: the value of the element, the index of the
   * element, and the Array object being traversed.
   *
   * If a <code>obj</code> parameter is provided to <code>map</code>, it will be used as the
   * <code>this</code> for each invocation of the <code>callback</code>. If it is not provided, or is
   * <code>null</code>, the global object associated with <code>callback</code> is used instead.
   *
   * <code>map</code> does not mutate the array on which it is called.
   *
   * The range of elements processed by <code>map</code> is set before the first invocation of
   * <code>callback</code>. Elements which are appended to the array after the call to <code>map</code>
   * begins will not be visited by <code>callback</code>.  If existing elements of the array are changed,
   * or deleted, their value as passed to <code>callback</code> will be the value at the time
   * <code>map</code> visits them; elements that are deleted are not visited.
   *
   * Natively supported in Gecko since version 1.8.
   * http://developer.mozilla.org/en/docs/Core_JavaScript_1.5_Reference:Objects:Array:map
   *
   * @param callback {Function} Function produce an element of the new Array from an element of the current one.
   * @param obj {Object} Object to use as <code>this</code> when executing <code>callback</code>.
   */
  Array.prototype.map = function(callback, obj)
  {
    // The array length should be fixed, like in the native implementation.
    var l = this.length;
    var res = [];

    for (var i=0; i<l; i++) {
      res.push(callback.call(obj, this[i], i, this));
    }

    return res;
  };
}

if (!Array.prototype.some)
{
  /**
   * Tests whether some element in the array passes the test implemented by the provided function.
   *
   * <code>some</code> executes the <code>callback</code> function once for each element present in
   * the array until it finds one where <code>callback</code> returns a true value. If such an element
   * is found, <code>some</code> immediately returns <code>true</code>. Otherwise, <code>some</code>
   * returns <code>false</code>. <code>callback</code> is invoked only for indexes of the array which
   * have assigned values; it is not invoked for indexes which have been deleted or which have never
   * been assigned values.
   *
   * <code>callback</code> is invoked with three arguments: the value of the element, the index of the
   * element, and the Array object being traversed.
   *
   * If a <code>obj</code> parameter is provided to <code>some</code>, it will be used as the
   * <code>this</code> for each invocation of the <code>callback</code>. If it is not provided, or is
   * <code>null</code>, the global object associated with <code>callback</code> is used instead.
   *
   * <code>some</code> does not mutate the array on which it is called.
   *
   * The range of elements processed by <code>some</code> is set before the first invocation of
   * <code>callback</code>.  Elements that are appended to the array after the call to <code>some</code>
   * begins will not be visited by <code>callback</code>. If an existing, unvisited element of the array
   * is changed by <code>callback</code>, its value passed to the visiting <code>callback</code> will
   * be the value at the time that <code>some</code> visits that element's index; elements that are
   * deleted are not visited.
   *
   * Natively supported in Gecko since version 1.8.
   * http://developer.mozilla.org/en/docs/Core_JavaScript_1.5_Reference:Objects:Array:some
   *
   * @param callback {Function} Function to test for each element.
   * @param obj {Object} Object to use as <code>this</code> when executing <code>callback</code>.
   */
  Array.prototype.some = function(callback, obj)
  {
    // The array length should be fixed, like in the native implementation.
    var l = this.length;

    for (var i=0; i<l; i++)
    {
      if (callback.call(obj, this[i], i, this)) {
        return true;
      }
    }

    return false;
  };
}

if (!Array.prototype.every)
{
  /**
   * Tests whether all elements in the array pass the test implemented by the provided function.
   *
   * <code>every</code> executes the provided <code>callback</code> function once for each element
   * present in the array until it finds one where <code>callback</code> returns a false value. If
   * such an element is found, the <code>every</code> method immediately returns <code>false</code>.
   * Otherwise, if <code>callback</code> returned a true value for all elements, <code>every</code>
   * will return <code>true</code>.  <code>callback</code> is invoked only for indexes of the array
   * which have assigned values; it is not invoked for indexes which have been deleted or which have
   * never been assigned values.
   *
   * <code>callback</code> is invoked with three arguments: the value of the element, the index of
   * the element, and the Array object being traversed.
   *
   * If a <code>obj</code> parameter is provided to <code>every</code>, it will be used as
   * the <code>this</code> for each invocation of the <code>callback</code>. If it is not provided,
   * or is <code>null</code>, the global object associated with <code>callback</code> is used instead.
   *
   * <code>every</code> does not mutate the array on which it is called. The range of elements processed
   * by <code>every</code> is set before the first invocation of <code>callback</code>. Elements which
   * are appended to the array after the call to <code>every</code> begins will not be visited by
   * <code>callback</code>.  If existing elements of the array are changed, their value as passed
   * to <code>callback</code> will be the value at the time <code>every</code> visits them; elements
   * that are deleted are not visited.
   *
   * Natively supported in Gecko since version 1.8.
   * http://developer.mozilla.org/en/docs/Core_JavaScript_1.5_Reference:Objects:Array:every
   *
   * @param callback {Function} Function to test for each element.
   * @param obj {Object} Object to use as <code>this</code> when executing <code>callback</code>.
   */
  Array.prototype.every = function (callback, obj)
  {
    // The array length should be fixed, like in the native implementation.
    var l = this.length;

    for (var i=0; i<l; i++)
    {
      if (!callback.call(obj, this[i], i, this)) {
        return false;
      }
    }

    return true;
  };
}







/*
---------------------------------------------------------------------------
  FEATURE EXTENSION OF NATIVE STRING OBJECT
---------------------------------------------------------------------------
*/

if (!String.prototype.quote)
{
  /**
   * Surrounds the string with double quotes and escapes all double quotes
   * and backslashes within the string.
   *
   * Note: Not part of ECMAScript Language Specification ECMA-262
   *       3rd edition (December 1999), but implemented by Gecko:
   *       http://lxr.mozilla.org/seamonkey/source/js/src/jsstr.c
   */
  String.prototype.quote = function () {
    return '"' + this.replace(/\\/g, "\\\\").replace(/\"/g, "\\\"") + '"';
  };
}
