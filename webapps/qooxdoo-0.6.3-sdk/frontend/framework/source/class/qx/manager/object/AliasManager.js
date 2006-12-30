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

/**
 * This singleton manage global resource aliases
 *
 * @event change {qx.event.type.Event}
 */
qx.OO.defineClass("qx.manager.object.AliasManager", qx.core.Target,
function()
{
  qx.core.Target.call(this);

  // Contains defined aliases (like icons/, widgets/, application/, ...)
  this._aliases = {};

  // Containes computed paths
  this._uris = {};

  // Define static alias from setting
  this.add("static", this.getSetting("staticUri"));
});






/*
---------------------------------------------------------------------------
  DEFAULT SETTINGS
---------------------------------------------------------------------------
*/

qx.Settings.setDefault("resourceUri", "../../resource");
qx.Settings.setDefault("staticUri", qx.Settings.getValue("resourceUri") + "/static");





/*
---------------------------------------------------------------------------
  ALIAS MANAGMENT
---------------------------------------------------------------------------
*/

qx.Proto.add = function(vPrefix, vPath)
{
  this._aliases[vPrefix] = vPath;
  this.createDispatchEvent("change");
}

qx.Proto.remove = function(vPrefix)
{
  delete this._aliases[vPrefix];
  this.createDispatchEvent("change");
}

qx.Proto.resolve = function(vPrefix) {
  return this._aliases[vPrefix];
}






/*
---------------------------------------------------------------------------
  URI HANDLING
---------------------------------------------------------------------------
*/

qx.Proto.resolvePath = function(vPath, vForceUpdate)
{
  var vUri = this._uris[vPath];

  if (vForceUpdate || typeof vUri === "undefined")
  {
    vUri = this._uris[vPath] = this._computePath(vPath);
    // this.debug("URI: " + vPath + " => " + vUri);
  }

  return vUri;
}

qx.Proto._computePath = function(vPath, vForce)
{
  switch(vPath.charAt(0))
  {
    case "/":
    case ".":
      return vPath;

    default:
      if (qx.lang.String.startsWith(vPath, qx.net.Protocol.URI_HTTP) || qx.lang.String.startsWith(vPath, qx.net.Protocol.URI_HTTPS) || qx.lang.String.startsWith(vPath, qx.net.Protocol.URI_FILE)) {
        return vPath;
      }

      var vAlias = vPath.substring(0, vPath.indexOf("/"));
      var vResolved = this._aliases[vAlias];

      if (qx.util.Validation.isValidString(vResolved)) {
        return vResolved + vPath.substring(vAlias.length);
      }

      return vPath;
  }
}








/*
---------------------------------------------------------------------------
  DISPOSER
---------------------------------------------------------------------------
*/

qx.Proto.dispose = function()
{
  if (this.getDisposed()) {
    return;
  }

  this._aliases = null;
  this._uris = null;

  return qx.core.Target.prototype.dispose.call(this);
}






/*
---------------------------------------------------------------------------
  DEFER SINGLETON INSTANCE
---------------------------------------------------------------------------
*/

/**
 * Singleton Instance Getter
 */
qx.Class.getInstance = qx.util.Return.returnInstance;
