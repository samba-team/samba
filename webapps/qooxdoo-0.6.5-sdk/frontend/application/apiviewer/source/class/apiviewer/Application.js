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
     * Til Schneider (til132)
     * Sebastian Werner (wpbasti)
     * Andreas Ecker (ecker)
     * Fabian Jakobs (fjakobs)

************************************************************************ */

/* ************************************************************************

#module(apiviewer)
#resource(css:css)
#resource(image:image)
#embed(apiviewer.css/*)

************************************************************************ */

/**
 * Your custom application
 */
qx.OO.defineClass("apiviewer.Application", qx.component.AbstractApplication,
function () {
  qx.component.AbstractApplication.call(this);
});

qx.Settings.setDefault("resourceUri", "./resource");





/*
---------------------------------------------------------------------------
  METHODS
---------------------------------------------------------------------------
*/

qx.Proto.initialize = function(e)
{
  // Define alias for custom resource path
  qx.manager.object.AliasManager.getInstance().add("api", qx.Settings.getValueOfClass("apiviewer.Application", "resourceUri"));

  // Reduce log level
  qx.log.Logger.ROOT_LOGGER.setMinLevel(qx.log.Logger.LEVEL_WARN);

  // Include CSS file
  qx.html.StyleSheet.includeFile(qx.manager.object.AliasManager.getInstance().resolvePath("api/css/apiviewer.css"));
};

qx.Proto.main = function(e)
{
  // Initialize the viewer
  this.viewer = new apiviewer.Viewer;
  this.viewer.addToDocument();
};

qx.Proto.finalize = function(e)
{
  // Finally load the data
  this.viewer.load("script/apidata.js");
};
