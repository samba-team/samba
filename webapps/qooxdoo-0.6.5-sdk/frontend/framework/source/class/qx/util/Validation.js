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
 * Collection of validation methods.
 *
 * All methods use the strict comparison operators as all modern
 * browsers (needs support for JavaScript 1.3) support this.
 *
 * http://developer.mozilla.org/en/docs/Core_JavaScript_1.5_Reference:Operators:Comparison_Operators
 */
qx.OO.defineClass("qx.util.Validation");

/**
 * Whether a value is valid. Invalid values are:
 * <ul>
 *   <li>undefined</li>
 *   <li>null</li>
 *   <li>"" (empty string)</li>
 *   <li>Nan (not a number)</li>
 *   <li>false</li>
 * </ul>
 * All other values are considered valid.
 *
 * @param v {var} the value to validate.
 * @return {Boolean} whether the variable is valid
 */
qx.util.Validation.isValid = function(v)
{
  switch(typeof v)
  {
    case "undefined":
      return false;

    case "object":
      return v !== null;

    case "string":
      return v !== "";

    case "number":
      return !isNaN(v);

    case "function":
    case "boolean":
      return true;
  }

  return false;
};


/**
 * Whether a value is invalid. Invalid values are:
 * <ul>
 *   <li>undefined</li>
 *   <li>null</li>
 *   <li>"" (empty string)</li>
 *   <li>Nan (not a number)</li>
 *   <li>false</li>
 * </ul>
 * All other values are considered valid.
 *
 * @param v {var} the value to validate.
 * @return {Boolean} whether the variable is invalid
 */
qx.util.Validation.isInvalid = function(v)
{
  switch(typeof v)
  {
    case "undefined":
      return true;

    case "object":
      return v === null;

    case "string":
      return v === "";

    case "number":
      return isNaN(v);

    case "function":
    case "boolean":
      return false;
  }

  return true;
};


/**
 * Whether a value is a valid number. Valid numbers are:
 * <ul>
 *   <li>type is number</li>
 *   <li>not NaN</li>
 * </ul>
 *
 * @param v {var} the value to validate.
 * @return {Boolean} whether the variable is valid
 */
qx.util.Validation.isValidNumber = function(v) {
  return typeof v === "number" && !isNaN(v);
};


/**
 * Whether a value is an invalid number.
 *
 * @param v {var} the value to validate.
 * @return {Boolean} whether the variable is valid
 */
qx.util.Validation.isInvalidNumber = function(v) {
  return typeof v !== "number" || isNaN(v);
};


/**
 * Whether a value is valid string. Valid strings are:
 * <ul>
 *   <li>type is string</li>
 *   <li>not an empty string</li>
 * </ul>
 *
 * @param v {var} the value to validate.
 * @return {Boolean} whether the variable is valid
 */
qx.util.Validation.isValidString = function(v) {
  return typeof v === "string" && v !== "";
};


/**
 * Whether a value is an invalid string.
 *
 * @param v {var} the value to validate.
 * @return {Boolean} whether the variable is valid
 */
qx.util.Validation.isInvalidString = function(v) {
  return typeof v !== "string" || v === "";
};


/**
 * Whether a value is a valid array. Valid arrays are:
 * <ul>
 *   <li>type is object</li>
 *   <li>instance is Array</li>
 * </ul>
 *
 * @param v {var} the value to validate.
 * @return {Boolean} whether the variable is valid
 */
qx.util.Validation.isValidArray = function(v) {
  return typeof v === "object" && v !== null && v instanceof Array;
};


/**
 * Whether a value is an invalid array.
 *
 * @param v {var} the value to validate.
 * @return {Boolean} whether the variable is valid
 */
qx.util.Validation.isInvalidArray = function(v) {
  return typeof v !== "object" || v === null || !(v instanceof Array);
};


/**
 * Whether a value is a valid object. Valid object are:
 * <ul>
 *   <li>type is object</li>
 *   <li>instance != Array</li>
 * </ul>
 *
 * @param v {var} the value to validate.
 * @return {Boolean} whether the variable is valid
 */
qx.util.Validation.isValidObject = function(v) {
  return typeof v === "object" && v !== null && !(v instanceof Array);
}


/**
 * Whether a value is an invalid object.
 *
 * @param v {var} the value to validate.
 * @return {Boolean} whether the variable is valid
 */
qx.util.Validation.isInvalidObject = function(v) {
  return typeof v !== "object" || v === null || v instanceof Array;
};


/**
 * Whether a value is a valid DOM node. Valid nodes are:
 * <ul>
 *   <li>type is object</li>
 * </ul>
 *
 * @param v {var} the value to validate.
 * @return {Boolean} whether the variable is valid
 */
qx.util.Validation.isValidNode = function(v) {
  return typeof v === "object" && v !== null;
};


/**
 * Whether a value is an invalid node.
 *
 * @param v {var} the value to validate.
 * @return {Boolean} whether the variable is valid
 */
qx.util.Validation.isInvalidNode = function(v) {
  return typeof v !== "object" || v === null;
};


/**
 * Whether a value is valid DOM element number. Valid elements are:
 * <ul>
 *   <li>type is object</li>
 *   <li>v.nodeType === 1</li>
 * </ul>
 *
 * @param v {var} the value to validate.
 * @return {Boolean} whether the variable is valid
 */
qx.util.Validation.isValidElement = function(v) {
  return typeof v === "object" && v !== null || v.nodeType !== 1;
};


/**
 * Whether a value is not a DOM element.
 *
 * @param v {var} the value to validate.
 * @return {Boolean} whether the variable is valid
 */
qx.util.Validation.isInvalidElement = function(v) {
  return typeof v !== "object" || v === null || v.nodeType !== 1;
};


/**
 * Whether a value is a function.
 * <ul>
 *   <li>type is function</li>
 * </ul>
 *
 * @param v {var} the value to validate.
 * @return {Boolean} whether the variable is valid
 */
qx.util.Validation.isValidFunction = function(v) {
  return typeof v === "function";
};


/**
 * Whether a value is not a function.
 *
 * @param v {var} the value to validate.
 * @return {Boolean} whether the variable is valid
 */
qx.util.Validation.isInvalidFunction = function(v) {
  return typeof v !== "function";
};


/**
 * Whether a value is a boolean. Valid booleans are:
 * <ul>
 *   <li>type is boolean</li>
 * </ul>
 *
 * @param v {var} the value to validate.
 * @return {Boolean} whether the variable is valid
 */
qx.util.Validation.isValidBoolean = function(v) {
  return typeof v === "boolean";
};


/**
 * Whether a value is not boolean.
 *
 * @param v {var} the value to validate.
 * @return {Boolean} whether the variable is valid
 */
qx.util.Validation.isInvalidBoolean = function(v) {
  return typeof v !== "boolean";
};


/**
 * Whether a value is valid a non empty string or a valid number. Valid values are:
 * <ul>
 *   <li>type is string or number</li>
 *   <li>values is not "" or NaN</li>
 * </ul>
 *
 * @param v {var} the value to validate.
 * @return {Boolean} whether the variable is valid
 */
qx.util.Validation.isValidStringOrNumber = function(v)
{
  switch(typeof v)
  {
    case "string":
      return v !== "";

    case "number":
      return !isNaN(v);
  }

  return false;
};


/**
 * Whether a value not a valid string or number.
 *
 * @param v {var} the value to validate.
 * @return {Boolean} whether the variable is valid
 */
qx.util.Validation.isInvalidStringOrNumber = function(v)
{
  switch(typeof v)
  {
    case "string":
      return v === "";

    case "number":
      return isNaN(v);
  }

  return false;
};
