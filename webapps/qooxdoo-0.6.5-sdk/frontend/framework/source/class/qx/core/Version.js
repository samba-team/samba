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
 * Framework version number information
 *
 * TODO:
 * <ul>
 *   <li>Resemble naming of http://en.wikipedia.org/wiki/Software_version</li>
 *   <li>Compare/unify with qx.type.Version</li>
 *   <li>The following class variables are not yet included in the api viewer:
 *     <ul>
 *       <li>major</li>
  *      <li>minor</li>
  *      <li>revision (rename to: maintenance)</li>
  *      <li>state</li>
  *      <li>svn (rename to: revision)</li>
  *    </ul>
  *  </li>
  * </ul>
 */
qx.OO.defineClass("qx.core.Version");

/** {Integer} Major version number */
qx.Class.major = 0;

/** {Integer} Minor version number */
qx.Class.minor = 0;

/** {Integer} Maintenance number */
qx.Class.revision = 0;

/** {String} Revision state */
qx.Class.state = "";

/** {Integer} Subversion revision number */
qx.Class.svn = 0;

/** {String} Subversion folder e.g. trunk, release_0_6_3, ... */
qx.Class.folder = "";

/**
 * returns the qooxdoo version string
 *
 * @return {String} qooxdoo version string
 */
qx.Class.toString = function()
{
  var vClass = qx.core.Version;
  return vClass.major + "." + vClass.minor
    + (vClass.revision==0 ? "" : "." + vClass.revision)
    + (vClass.state == "" ? "" : "-" + vClass.state)
    + (vClass.svn==0 ? "" : " (r" + vClass.svn + ")")
    + (vClass.folder == "" ? "" : " [" + vClass.folder + "]");
};

/**
 * Initialize class members
 */
qx.Class._init = function()
{
  var vClass = qx.core.Version;

  var vSplit = qx.VERSION.split(" ");
  var vVersion = vSplit.shift();
  var vInfos = vSplit.join(" ");

  if (/([0-9]+)\.([0-9]+)(\.([0-9]))?(-([a-z]+))?/.test(vVersion))
  {
    vClass.major = (RegExp.$1 != "" ? parseInt(RegExp.$1) : 0);
    vClass.minor = (RegExp.$2 != "" ? parseInt(RegExp.$2) : 0);
    vClass.revision = (RegExp.$4 != "" ? parseInt(RegExp.$4) : 0);
    vClass.state = typeof RegExp.$6 == "string" ? RegExp.$6 : "";
  }

  if (/(\(r([0-9]+)\))?(\s\[(\w+)\])?/.test(vInfos))
  {
    vClass.svn = (RegExp.$2 != "" ? parseInt(RegExp.$2) : 0);
    vClass.folder = typeof RegExp.$4 == "string" ? RegExp.$4 : "";
  }
};

// Initialize at load time
qx.Class._init();
