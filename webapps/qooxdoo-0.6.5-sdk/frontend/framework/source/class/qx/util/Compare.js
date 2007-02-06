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
 * Collection of methods to compare two values.
 */
qx.OO.defineClass("qx.util.Compare");


/**
 * Compare two Strings
 *
 * @param a {String} first value
 * @param b {String} second value
 *
 * @return {Number}
 *     0 if both values are equal
 *     a number > 0 if the first value if greater than the second one
 *     a value < 0  otherwise
 */
qx.util.Compare.byString = function(a, b) {
  return a==b ? 0 : a > b ? 1 : -1;
};


/**
 * Compare two Strings ignoring the letter case.
 *
 * @param a {String} first value
 * @param b {String} second value
 *
 * @return {Number}
 *     0 if both values are equal
 *     a number > 0 if the first value if greater than the second one
 *     a value < 0  otherwise
 */

qx.util.Compare.byStringCaseInsensitive = function(a, b) {
  return qx.util.Compare.byString(a.toLowerCase(), b.toLowerCase());
};


/**
 * Compare two Strings but first convert umlauts to an ascii character.
 *
 * @param a {String} first value
 * @param b {String} second value
 *
 * @return {Number}
 *     0 if both values are equal
 *     a number > 0 if the first value if greater than the second one
 *     a value < 0  otherwise
 */
qx.util.Compare.byStringUmlautsShort = function(a, b) {
  return qx.util.Compare.byString(qx.util.Normalization.umlautsShort(a), qx.util.Normalization.umlautsShort(b));
};


/**
 * Compare two Strings but first convert umlauts to an ascii character and ignore letter case.
 *
 * @param a {String} first value
 * @param b {String} second value
 *
 * @return {Number}
 *     0 if both values are equal
 *     a number > 0 if the first value if greater than the second one
 *     a value < 0  otherwise
 */
qx.util.Compare.byStringUmlautsShortCaseInsensitive = function(a, b) {
  return qx.util.Compare.byString(qx.util.Normalization.umlautsShort(a).toLowerCase(), qx.util.Normalization.umlautsShort(b).toLowerCase());
};


/**
 * Compare two Strings but first convert umlauts to ascii characters.
 *
 * @param a {String} first value
 * @param b {String} second value
 *
 * @return {Number}
 *     0 if both values are equal
 *     a number > 0 if the first value if greater than the second one
 *     a value < 0  otherwise
 */
qx.util.Compare.byStringUmlautsLong = function(a, b) {
  return qx.util.Compare.byString(qx.util.Normalization.umlautsLong(a), qx.util.Normalization.umlautsLong(b));
};


/**
 * Compare two Strings but first convert umlauts to ascii characters and ignore letter case.
 *
 * @param a {String} first value
 * @param b {String} second value
 *
 * @return {Number}
 *     0 if both values are equal
 *     a number > 0 if the first value if greater than the second one
 *     a value < 0  otherwise
 */
qx.util.Compare.byStringUmlautsLongCaseInsensitive = function(a, b) {
  return qx.util.Compare.byString(qx.util.Normalization.umlautsLong(a).toLowerCase(), qx.util.Normalization.umlautsLong(b).toLowerCase());
};


/**
 * Compare two Float numbers.
 *
 * @param a {Float} first value
 * @param b {Float} second value
 *
 * @return {Number}
 *     0 if both values are equal
 *     a number > 0 if the first value if greater than the second one
 *     a value < 0  otherwise
 */
qx.util.Compare.byFloat = function(a, b) {
  return a - b;
};

qx.util.Compare.byInteger = qx.util.Compare.byNumber = qx.util.Compare.byFloat;


/**
 * Compare two Strings representing integers. First convert the strings to  an interger.
 *
 * @param a {String} first value
 * @param b {String} second value
 *
 * @return {Number}
 *     0 if both values are equal
 *     a number > 0 if the first value if greater than the second one
 *     a value < 0  otherwise
 */
qx.util.Compare.byIntegerString = function(a, b) {
  return parseInt(a) - parseInt(b);
};


/**
 * Compare two Strings representing floats. First convert the strings to  an float.
 *
 * @param a {String} first value
 * @param b {String} second value
 *
 * @return {Number}
 *     0 if both values are equal
 *     a number > 0 if the first value if greater than the second one
 *     a value < 0  otherwise
 */
qx.util.Compare.byFloatString = function(a, b) {
  return parseFloat(a) - parseFloat(b);
};

qx.util.Compare.byNumberString = qx.util.Compare.byFloatString;


/**
 * Compare two Strings representing IPv4 adresses.
 * Example: "192.168.1.2"
 *
 * @param a {String} first value
 * @param b {String} second value
 *
 * @return {Number}
 *     0 if both values are equal
 *     a number > 0 if the first value if greater than the second one
 *     a value < 0  otherwise
 */
qx.util.Compare.byIPv4 = function(a, b)
{
  var ipa = a.split(".", 4);
  var ipb = b.split(".", 4);

  for (var i=0; i<3; i++)
  {
    a = parseInt(ipa[i]);
    b = parseInt(ipb[i]);

    if (a != b) {
      return a - b;
    }
  }

  return parseInt(ipa[3]) - parseInt(ipb[3]);
};


/**
 * Compare the zIndex property of two widgets.
 *
 * @param a {qx.ui.core.Widget} first value
 * @param b {qx.ui.core.Widget} second value
 *
 * @return {Number}
 *     0 if both values are equal
 *     a number > 0 if the first value if greater than the second one
 *     a value < 0  otherwise
 */
qx.util.Compare.byZIndex = function(a, b) {
  return a.getZIndex() - b.getZIndex();
};
