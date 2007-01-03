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

qx.OO.defineClass("qx.util.Normalization");





/*
---------------------------------------------------------------------------
  HANDLING OF UMLAUTS
---------------------------------------------------------------------------
*/

qx.util.Normalization._umlautsRegExp = /[\xE4\xF6\xFC\xDF\xC4\xD6\xDC]/g;

qx.util.Normalization._umlautsShortData = { "\xC4": "A", "\xD6": "O", "\xDC": "U", "\xE4": "a", "\xF6": "o", "\xFC": "u", "\xDF": "s" }

qx.util.Normalization._umlautsShort = function(vChar) {
  return qx.util.Normalization._umlautsShortData[vChar];
}

qx.util.Normalization.umlautsShort = function(vString) {
  return vString.replace(qx.util.Normalization._umlautsRegExp, qx.util.Normalization._umlautsShort);
}

qx.util.Normalization._umlautsLongData = { "\xC4": "Ae", "\xD6": "Oe", "\xDC": "Ue", "\xE4": "ae", "\xF6": "oe", "\xFC": "ue", "\xDF": "ss" }

qx.util.Normalization._umlautsLong = function(vChar) {
  return qx.util.Normalization._umlautsLongData[vChar];
}

qx.util.Normalization.umlautsLong = function(vString) {
  return vString.replace(qx.util.Normalization._umlautsRegExp, qx.util.Normalization._umlautsLong);
}
