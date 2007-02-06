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
 * String helper functions
 *
 * The native JavaScript String is not modified by this class. However,
 * there are modifications to the native String in {@link qx.lang.Core} for
 * browsers that do not support certain features.
 *
 * The additions implemented here may be added directly to native String by
 * a setting in {@link qx.lang.Prototypes}. This feature is not enabled by
 * default.
 *
 * The string/array generics introduced in JavaScript 1.6 are supported by
 * {@link qx.lang.Generics}.
 */
qx.OO.defineClass("qx.lang.String");


/**
 * converts a string seperated by '-' to camel case.
 * Example:
 * <pre>qx.lang.String.toCamelCase("to-camel-case") == "toCamelCase"</pre>
 *
 * @param str {String} string seperated by '-'
 * @return {String} camel case string
 */
qx.Class.toCamelCase = function(str)
{
  var vArr = str.split("-"), vLength = vArr.length;

  if(vLength == 1) {
    return vArr[0];
  }

  var vNew = str.indexOf("-") == 0 ? vArr[0].charAt(0).toUpperCase() + vArr[0].substring(1) : vArr[0];

  for (var vPart, i=1; i<vLength; i++)
  {
    vPart = vArr[i];
    vNew += vPart.charAt(0).toUpperCase() + vPart.substring(1);
  }

  return vNew;
};


/**
 * removes white space from the left side of a string
 *
 * @param str {String} the string to trim
 * @return {String}
 */
qx.Class.trimLeft = function(str) {
  return str.replace(/^\s+/, "");
};


/**
 * removes white space from the right side of a string
 *
 * @param str {String} the string to trim
 * @return {String}
 */
qx.Class.trimRight = function(str) {
  return str.replace(/\s+$/, "");
};


/**
 * removes white space from the left and the right side of a string
 *
 * @param str {String} the string to trim
 * @return {String}
 */
qx.Class.trim = function(str) {
  return str.replace(/^\s+|\s+$/g, "");
};


/**
 * Check whether the string starts with the given substring
 *
 * @param fullstr {String} the string to search in
 * @param substr {String} the substring to look for
 * @return {Boolean} whether the string starts with the given substring
 */
qx.Class.startsWith = function(fullstr, substr) {
  return !fullstr.indexOf(substr);
};


/**
 * Check whether the string ends with the given substring
 *
 * @param fullstr {String} the string to search in
 * @param substr {String} the substring to look for
 * @return {Boolean} whether the string ends with the given substring
 */
qx.Class.endsWith = function(fullstr, substr) {
  return fullstr.lastIndexOf(substr) === fullstr.length-substr.length;
};


/**
 * Pad a string up to a given length. Padding characters are added to the left of the string.
 *
 * @param str {String} the string to pad
 * @param length {Integer} the final length of the string
 * @param ch {String?"0"} character used to fill up the string
 * @return {String} paddded string
 */
qx.Class.pad = function(str, length, ch)
{
  if (typeof ch === "undefined") {
    ch = "0";
  }

  var temp = "";

  for (var i=str.length; i<length; i++) {
    temp += ch;
  }

  return temp + str;
};


/**
 * Convert the first character of the string to upper case.
 *
 * @param str {String} the string
 * @return {String} the string with a upper case first character
 */
qx.Class.toFirstUp = function(str) {
  return str.charAt(0).toUpperCase() + str.substr(1);
};


/**
 * Add a list item to a serialized list string
 * Example:
 * <pre>qx.lang.String.addListItem("red, yellow, green", "blue", ", ") == "red, yellow, green, blue"</pre>
 *
 * @param str {String} serialized list. The items are seperated by "sep"
 * @param item {String} list item to be added
 * @param sep {String?","} separator
 * @return {String} the string with the added item
 */
qx.Class.addListItem = function(str, item, sep)
{
  if (str == item || str == "")
  {
    return item;
  }

  if (sep == null) {
    sep = ",";
  }

  var a = str.split(sep);

  if (a.indexOf(item) == -1)
  {
    a.push(item);
    return a.join(sep);
  }
  else
  {
    return str;
  }

};


/**
 * Remove a list item from a serialized list string
 * Example:
 * <pre>qx.lang.String.removeListItem("red, yellow, green", "yellow", ", ") == "red, green, blue"</pre>
 *
 * @param str {String} serialized list. The items are seperated by "sep"
 * @param item {String} list item to be removed
 * @param sep {String?","} separator
 * @return {String} the string with the removed item
 */
qx.Class.removeListItem = function(str, item, sep)
{
  if (str == item || str == "")
  {
    return "";
  }
  else
  {
    if (sep == null) {
      sep = ",";
    }

    var a = str.split(sep);
    var p = a.indexOf(item);

    if (p === -1) {
      return str;
    }

    do { a.splice(p, 1); }
    while((p = a.indexOf(item)) != -1);

    return a.join(sep);
  }
};


/**
 * Check whether the string contains a given substring
 *
 * @param str {String} the string
 * @param substring {String} substring to search for
 * @return {Boolean} whether the string contains the substring
 */
qx.Class.contains = function(str, substring) {
  return str.indexOf(substring) != -1;
};


/**
 * Print a list of arguments using a format string
 * In the format string occurences of %n are replaced by the n'th element of the args list.
 * Example:
 * <pre>qx.lang.String.format("Hello %1, my name is %2", ["Egon", "Franz"]) == "Hello Egon, my name is Franz"</pre>
 *
 * @param pattern {String} format string
 * @param args {Array} array of arguments to insert into the format string
 * @return {String}
 */
qx.Class.format = function(pattern, args)
{
  var str = pattern;

  for (var i=0; i<args.length; i++) {
    str = str.replace(new RegExp("%" + (i+1), "g"), args[i]);
  }

  return str;
};


/**
 * Escapes all chars that have a special meaning in regular expressions
 *
 * @param str {String} the string where to escape the chars.
 * @return {String} the string with the escaped chars.
 */
qx.Class.escapeRegexpChars = function(str) {
  return str.replace(/([\\\.\(\)\[\]\{\}\^\$\?\+\*])/g, "\\$1");
};
