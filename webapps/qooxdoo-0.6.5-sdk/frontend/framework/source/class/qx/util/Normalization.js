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

qx.OO.defineClass("qx.util.Normalization");





/*
---------------------------------------------------------------------------
  HANDLING OF UMLAUTS
---------------------------------------------------------------------------
*/

qx.util.Normalization._umlautsRegExp = /[\xE4\xF6\xFC\xDF\xC4\xD6\xDC]/g;

qx.util.Normalization._umlautsShortData = { "\xC4": "A", "\xD6": "O", "\xDC": "U", "\xE4": "a", "\xF6": "o", "\xFC": "u", "\xDF": "s" };


/**
 * Private helper
 *
 * @param vChar {String} char to convert
 * @return {String}
 */
qx.util.Normalization._umlautsShort = function(vChar) {
  return qx.util.Normalization._umlautsShortData[vChar];
};


/**
 * Converts (German) umlauts in the string to a one letter ASCI form.
 * Example: &Auml; -> A, &uuml; -> u, &szlig; -> s, ...
 *
 * @param vString {String} string to normalize
 * @return {String} normalized string
 */
qx.util.Normalization.umlautsShort = function(vString) {
  return vString.replace(qx.util.Normalization._umlautsRegExp, qx.util.Normalization._umlautsShort);
};


qx.util.Normalization._umlautsLongData = { "\xC4": "Ae", "\xD6": "Oe", "\xDC": "Ue", "\xE4": "ae", "\xF6": "oe", "\xFC": "ue", "\xDF": "ss" };


/**
 * Private helper
 *
 * @param vChar {String} char to convert
 * @return {String}
 */
qx.util.Normalization._umlautsLong = function(vChar) {
  return qx.util.Normalization._umlautsLongData[vChar];
};


/**
 * Converts (German) umlauts in the string to a two letter ASCI form.
 * Example: &Auml; -> Ae, &uuml; -> ue, &szlig; -> ss, ...
 *
 * @param vString {String} string to normalize
 * @return {String} normalized string
 */
qx.util.Normalization.umlautsLong = function(vString) {
  return vString.replace(qx.util.Normalization._umlautsRegExp, qx.util.Normalization._umlautsLong);
};