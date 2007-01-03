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

#module(core)

************************************************************************ */

qx.OO.defineClass("qx.util.Validation");

/*
  All methods use the strict comparison operators as all modern
  browsers (needs support for JavaScript 1.3) seems to support this.

  http://developer.mozilla.org/en/docs/Core_JavaScript_1.5_Reference:Operators:Comparison_Operators
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
}

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
}

qx.util.Validation.isValidNumber = function(v) {
  return typeof v === "number" && !isNaN(v);
}

qx.util.Validation.isInvalidNumber = function(v) {
  return typeof v !== "number" || isNaN(v);
}

qx.util.Validation.isValidString = function(v) {
  return typeof v === "string" && v !== "";
}

qx.util.Validation.isInvalidString = function(v) {
  return typeof v !== "string" || v === "";
}

qx.util.Validation.isValidArray = function(v) {
  return typeof v === "object" && v !== null && v instanceof Array;
}

qx.util.Validation.isInvalidArray = function(v) {
  return typeof v !== "object" || v === null || !(v instanceof Array);
}

qx.util.Validation.isValidObject = function(v) {
  return typeof v === "object" && v !== null && !(v instanceof Array);
}

qx.util.Validation.isInvalidObject = function(v) {
  return typeof v !== "object" || v === null || v instanceof Array;
}

qx.util.Validation.isValidNode = function(v) {
  return typeof v === "object" && v !== null;
}

qx.util.Validation.isInvalidNode = function(v) {
  return typeof v !== "object" || v === null;
}

qx.util.Validation.isValidElement = function(v) {
  return typeof v === "object" && v !== null || v.nodeType !== 1;
}

qx.util.Validation.isInvalidElement = function(v) {
  return typeof v !== "object" || v === null || v.nodeType !== 1;
}

qx.util.Validation.isValidFunction = function(v) {
  return typeof v === "function";
}

qx.util.Validation.isInvalidFunction = function(v) {
  return typeof v !== "function";
}

qx.util.Validation.isValidBoolean = function(v) {
  return typeof v === "boolean";
}

qx.util.Validation.isInvalidBoolean = function(v) {
  return typeof v !== "boolean";
}

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
}

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
}
