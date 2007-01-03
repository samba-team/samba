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
#random(386)

************************************************************************ */

/**
 * qooxdoo version number information
 */
qx.OO.defineClass("qx.core.Version",
{
  /**
   * qooxdoo major version number
   */
  major : 0,

  /**
   * qooxdoo minor version number
   */
  minor : 6,

  /**
   * qooxdoo revision number
   */
  revision : 3,

  /**
   * qooxdoo revision state
   */
  state : "",

  /**
   * qooxdoo subversion revision number
   */
  svn : Number("$Rev: 5000 $".match(/[0-9]+/)[0]),

  /**
   * returns the qooxdoo version string
   *
   * @return {string} qooxdoo version string
   */
  toString: function()
  {
    with(qx.core.Version) {
      return major + "." + minor + (revision==0 ? "" : "." + revision) + (state == "" ? "" : "-" + state) + " (r" + svn + ")";
    }
  }
});
