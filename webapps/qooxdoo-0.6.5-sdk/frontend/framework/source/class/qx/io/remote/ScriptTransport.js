/* ************************************************************************

   qooxdoo - the new era of web development

   http://qooxdoo.org

   Copyright:
     2004-2007 1&1 Internet AG, Germany, http://www.1and1.org
     2006 Derrell Lipman
     2006 STZ-IDA, Germany, http://www.stz-ida.de

   License:
     LGPL: http://www.gnu.org/licenses/lgpl.html
     EPL: http://www.eclipse.org/org/documents/epl-v10.php
     See the LICENSE file in the project's top-level directory for details.

   Authors:
     * Sebastian Werner (wpbasti)
     * Andreas Ecker (ecker)
     * Derrell Lipman (derrell)
     * Andreas Junghans (lucidcake)

************************************************************************ */

/* ************************************************************************

#module(io_remote)
#require(qx.io.remote.Exchange)

************************************************************************ */

/*!
  Transports requests to a server using dynamic script tags.

  This class should not be used directly by client programmers.
 */
qx.OO.defineClass("qx.io.remote.ScriptTransport", qx.io.remote.AbstractRemoteTransport,
function()
{
  qx.io.remote.AbstractRemoteTransport.call(this);

  var vUniqueId = ++qx.io.remote.ScriptTransport._uniqueId;
  if (vUniqueId >= 2000000000) {
    qx.io.remote.ScriptTransport._uniqueId = vUniqueId = 1;
  }

  this._element = null;
  this._uniqueId = vUniqueId;
});

qx.Class._uniqueId = 0;
qx.Class._instanceRegistry = {};
qx.Class.ScriptTransport_PREFIX = "_ScriptTransport_";
qx.Class.ScriptTransport_ID_PARAM = qx.Class.ScriptTransport_PREFIX + "id";
qx.Class.ScriptTransport_DATA_PARAM = qx.Class.ScriptTransport_PREFIX + "data";
qx.Proto._lastReadyState = 0;





/*
---------------------------------------------------------------------------
  CLASS PROPERTIES AND METHODS
---------------------------------------------------------------------------
*/

// basic registration to qx.io.remote.Exchange
// the real availability check (activeX stuff and so on) follows at the first real request
qx.io.remote.Exchange.registerType(qx.io.remote.ScriptTransport, "qx.io.remote.ScriptTransport");

qx.io.remote.ScriptTransport.handles =
{
  synchronous : false,
  asynchronous : true,
  crossDomain : true,
  fileUpload: false,
  responseTypes : [ qx.util.Mime.TEXT, qx.util.Mime.JAVASCRIPT, qx.util.Mime.JSON ]
}

qx.io.remote.ScriptTransport.isSupported = function() {
  return true;
}






/*
---------------------------------------------------------------------------
  USER METHODS
---------------------------------------------------------------------------
*/

qx.Proto.send = function()
{
  var vUrl = this.getUrl();



  // --------------------------------------
  //   Adding parameters
  // --------------------------------------

  vUrl += (vUrl.indexOf("?") >= 0 ? "&" : "?") + qx.io.remote.ScriptTransport.ScriptTransport_ID_PARAM + "=" + this._uniqueId;

  var vParameters = this.getParameters();
  var vParametersList = [];
  for (var vId in vParameters) {
    if (vId.indexOf(qx.io.remote.ScriptTransport.ScriptTransport_PREFIX) == 0) {
      this.error("Illegal parameter name. The following prefix is used internally by qooxdoo): " +
        qx.io.remote.ScriptTransport.ScriptTransport_PREFIX);
    }
    var value = vParameters[vId];
    if (value instanceof Array) {
      for (var i = 0; i < value.length; i++) {
        vParametersList.push(encodeURIComponent(vId) + "=" +
                             encodeURIComponent(value[i]));
      }
    } else {
      vParametersList.push(encodeURIComponent(vId) + "=" +
                           encodeURIComponent(value));
    }
  }

  if (vParametersList.length > 0) {
    vUrl += "&" + vParametersList.join("&");
  }



  // --------------------------------------
  //   Sending data
  // --------------------------------------

  vData = this.getData();
  if (vData != null) {
    vUrl += "&" + qx.io.remote.ScriptTransport.ScriptTransport_DATA_PARAM + "=" + encodeURIComponent(vData);
  }

  qx.io.remote.ScriptTransport._instanceRegistry[this._uniqueId] = this;
  this._element = document.createElement("script");
  this._element.charset = "utf-8";  // IE needs this (it ignores the
                                    // encoding from the header sent by the
                                    // server for dynamic script tags)
  this._element.src = vUrl;

  document.body.appendChild(this._element);
}





/*
---------------------------------------------------------------------------
  EVENT LISTENER
---------------------------------------------------------------------------
*/

// For reference:
// http://msdn.microsoft.com/workshop/author/dhtml/reference/properties/readyState_1.asp
qx.io.remote.ScriptTransport._numericMap =
{
  "uninitialized" : 1,
  "loading" : 2,
  "loaded" : 2,
  "interactive" : 3,
  "complete" : 4
}

qx.Proto._switchReadyState = function(vReadyState)
{
  // Ignoring already stopped requests
  switch(this.getState())
  {
    case "completed":
    case "aborted":
    case "failed":
    case "timeout":
      this.warn("Ignore Ready State Change");
      return;
  }

  // Updating internal state
  while (this._lastReadyState < vReadyState) {
    this.setState(qx.io.remote.Exchange._nativeMap[++this._lastReadyState]);
  }
}
qx.Class._requestFinished = function(id, content) {
  var vInstance = qx.io.remote.ScriptTransport._instanceRegistry[id];
  if (vInstance == null) {
    if (qx.Settings.getValueOfClass("qx.io.remote.Exchange", "enableDebug")) {
      this.warn("Request finished for an unknown instance (probably aborted or timed out before)");
    }
  } else {
    vInstance._responseContent = content;
    vInstance._switchReadyState(qx.io.remote.ScriptTransport._numericMap.complete);
  }
}





/*
---------------------------------------------------------------------------
  REQUEST HEADER SUPPORT
---------------------------------------------------------------------------
*/

qx.Proto.setRequestHeader = function(vLabel, vValue)
{
  // TODO
  // throw new Error("setRequestHeader is abstract");
}






/*
---------------------------------------------------------------------------
  RESPONSE HEADER SUPPORT
---------------------------------------------------------------------------
*/

qx.Proto.getResponseHeader = function(vLabel)
{
  return null;

  // TODO
  // this.error("Need implementation", "getResponseHeader");
}

/*!
  Provides an hash of all response headers.
*/
qx.Proto.getResponseHeaders = function()
{
  return {}

  // TODO
  // throw new Error("getResponseHeaders is abstract");
}







/*
---------------------------------------------------------------------------
  STATUS SUPPORT
---------------------------------------------------------------------------
*/

/*!
  Returns the current status code of the request if available or -1 if not.
*/
qx.Proto.getStatusCode = function()
{
  return 200;

  // TODO
  // this.error("Need implementation", "getStatusCode");
}

/*!
  Provides the status text for the current request if available and null otherwise.
*/
qx.Proto.getStatusText = function()
{
  return "";

  // TODO
  // this.error("Need implementation", "getStatusText");
}







/*
---------------------------------------------------------------------------
  RESPONSE DATA SUPPORT
---------------------------------------------------------------------------
*/

/*!
  Returns the length of the content as fetched thus far
*/
qx.Proto.getFetchedLength = function()
{
  return 0;

  // TODO
  // throw new Error("getFetchedLength is abstract");
}

qx.Proto.getResponseContent = function()
{
  if (this.getState() !== "completed")
  {
    if (qx.Settings.getValueOfClass("qx.io.remote.Exchange", "enableDebug")) {
      this.warn("Transfer not complete, ignoring content!");
    }

    return null;
  }

  if (qx.Settings.getValueOfClass("qx.io.remote.Exchange", "enableDebug")) {
    this.debug("Returning content for responseType: " + this.getResponseType());
  }

  switch(this.getResponseType())
  {
    case qx.util.Mime.TEXT:
      // server is responsible for using a string as the response

    case qx.util.Mime.JSON:
    case qx.util.Mime.JAVASCRIPT:
      return this._responseContent;

    default:
      this.warn("No valid responseType specified (" + this.getResponseType() + ")!");
      return null;
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
    return true;
  }

  if (this._element != null)
  {
    delete qx.io.remote.ScriptTransport._instanceRegistry[this._uniqueId];
    document.body.removeChild(this._element);
    this._element = null;
  }

  return qx.io.remote.AbstractRemoteTransport.prototype.dispose.call(this);
}
