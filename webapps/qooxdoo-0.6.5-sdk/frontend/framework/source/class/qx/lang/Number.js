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
 * Helper functions for numbers.
 *
 * The native JavaScript Number is not modified by this class.
 *
 * The additions implemented here may be added directly to the native Number
 * by a setting in {@link qx.lang.Prototypes}. This feature is not enabled by
 * default.
 */
qx.OO.defineClass("qx.lang.Number");

/**
 * Check whether the number is in a given range
 *
 * @param nr {Number} the number to check
 * @param vmin {Integer} lower bound of the range
 * @param vmax {Integer} upper bound of the range
 * @return {Boolean} whether the number is >= vmin and <= vmax
 */
qx.lang.Number.isInRange = function(nr, vmin, vmax) {
  return nr >= vmin && nr <= vmax;
};


/**
 * Check whether the number is between a given range
 *
 * @param nr {Number} the number to check
 * @param vmin {Integer} lower bound of the range
 * @param vmax {Integer} upper bound of the range
 * @return {Boolean} whether the number is > vmin and < vmax
 */
qx.lang.Number.isBetweenRange = function(nr, vmin, vmax) {
  return nr > vmin && nr < vmax;
};


/**
 * Limit the nuber to a given range
 *
 * * If the number is greater than the upper bound, the upper bound is returned
 * * If the number is smaller than the lower bound, the lower bound is returned
 * * If the number is in the range, the number is retuned
 *
 * @param nr {Number} the number to limit
 * @param vmin {Integer} lower bound of the range
 * @param vmax {Integer} upper bound of the range
 * @return {Integer} the limited number
 */
qx.lang.Number.limit = function(nr, vmin, vmax)
{
  if (typeof vmax === "number" && nr > vmax)
  {
    return vmax;
  }
  else if (typeof vmin === "number" && nr < vmin)
  {
    return vmin;
  }
  else
  {
    return nr;
  }
};
