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

/**
 * Define an alias to a resource path
 *
 * @param vAlias {String} alias name for the resource path/url
 * @param vUriStart {String} first part of URI for all images which use this alias
 */
qx.Proto.add = function(vAlias, vUriStart)
{
  this._aliases[vAlias] = vUriStart;

  // Cleanup old uris which use this alias
  for (var vPath in this._uris)
  {
    if (vPath.substring(0, vPath.indexOf("/")) == vAlias) {
      this._uris[vPath] = null;
    }
  }

  // Fire change event (for ImageManager, etc.)
  this.createDispatchEvent("change");
}

/**
 * Remove a previously defined alias
 *
 * @param vAlias {String} alias name for the resource path/url
 */
qx.Proto.remove = function(vAlias)
{
  delete this._aliases[vAlias];

  // Cleanup old uris which use this alias
  for (var vPath in this._uris)
  {
    if (vPath.substring(0, vPath.indexOf("/")) == vAlias) {
      this._uris[vPath] = null;
    }
  }

  // Fire change event (for ImageManager, etc.)
  this.createDispatchEvent("change");
}

/**
 * Resolve an alias to the actual resource path/url
 *
 * @param vAlias {String} alias name for the resource path/url
 * @return {String} resource path/url
 */
qx.Proto.resolve = function(vAlias) {
  return this._aliases[vAlias];
}






/*
---------------------------------------------------------------------------
  URI HANDLING
---------------------------------------------------------------------------
*/

/**
 * Resolve a path name to a resource URI taking the defined aliases into account
 * and cache the result.
 *
 * If the first part of the path is a defined alias, the alias is resolved.
 * Otherwhise the path is returned unmodified.
 *
 * @param vPath {String} path name
 * @param vForceUpdate {Boolean} (default=false) wether the cached value should be ignored
 * @return {String} reolved path/url
 */
qx.Proto.resolvePath = function(vPath, vForceUpdate)
{
  var vUri = this._uris[vPath];

  if (vUri == null) {
    vUri = this._uris[vPath] = this._computePath(vPath);
  }

  // this.debug("URI: " + vPath + " => " + vUri);

  return vUri;
}


/**
 * Resolve a path name to a resource URI taking the defined aliases into account.
 *
 * If the first part of the path is a defined alias, the alias is resolved.
 * Otherwhise the path is returned unmodified.
 *
 * @param vPath {String} path name
 * @return {String} reolved path/url
 */
qx.Proto._computePath = function(vPath)
{
  switch(vPath.charAt(0))
  {
    case "/":
    case ".":
      return vPath;

    default:
      if (
        qx.lang.String.startsWith(vPath, qx.net.Protocol.URI_HTTP) ||
        qx.lang.String.startsWith(vPath, qx.net.Protocol.URI_HTTPS) ||
        qx.lang.String.startsWith(vPath, qx.net.Protocol.URI_FILE)
      ) {
        return vPath;
      }

      var vAlias = vPath.substring(0, vPath.indexOf("/"));
      var vResolved = this._aliases[vAlias];

      if (vResolved != null) {
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

/**
 * Disposer
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
qx.Class.getInstance = qx.lang.Function.returnInstance;
