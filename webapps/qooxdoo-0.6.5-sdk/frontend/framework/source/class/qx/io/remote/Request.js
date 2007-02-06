/* ************************************************************************

   qooxdoo - the new era of web development

   http://qooxdoo.org

   Copyright:
     2004-2007 1&1 Internet AG, Germany, http://www.1and1.org
     2006 Derrell Lipman

   License:
     LGPL: http://www.gnu.org/licenses/lgpl.html
     EPL: http://www.eclipse.org/org/documents/epl-v10.php
     See the LICENSE file in the project's top-level directory for details.

   Authors:
     * Sebastian Werner (wpbasti)
     * Andreas Ecker (ecker)
     * Derrell Lipman (derrell)

************************************************************************ */

/* ************************************************************************

#module(io_remote)
#require(qx.net.Http)
#require(qx.util.Mime)

************************************************************************ */

/**
 * This class is used to send HTTP requests to the server.
 *
 * @event created {qx.event.type.Event}
 * @event configured {qx.event.type.Event}
 * @event sending {qx.event.type.Event}
 * @event receiving {qx.event.type.Event}
 * @event completed {qx.event.type.Event}
 * @event failed {qx.event.type.Event}
 * @event aborted {qx.event.type.Event}
 * @event timeout {qx.event.type.Event}
 *
 * @param vUrl {String} Target url to issue the request to.
 * @param vMethod {String} Determines that type of request to issue (GET or POST). Default is GET.
 * @param vResponseType {String} The mime type of the response. Default is text/plain {@link qx.util.Mime}.
 */
qx.OO.defineClass("qx.io.remote.Request", qx.core.Target,
function(vUrl, vMethod, vResponseType)
{
  qx.core.Target.call(this);

  this._requestHeaders = {};
  this._parameters = {};

  this.setUrl(vUrl);
  this.setMethod(vMethod || qx.net.Http.METHOD_GET);
  this.setResponseType(vResponseType || qx.util.Mime.TEXT);

  this.setProhibitCaching(true);

  // Prototype-Style Request Headers
  this.setRequestHeader("X-Requested-With", "qooxdoo");
  this.setRequestHeader("X-Qooxdoo-Version", qx.core.Version.toString());

  // Get the next sequence number for this request
  this._seqNum = ++qx.io.remote.Request._seqNum;
});




/*
---------------------------------------------------------------------------
  PROPERTIES
---------------------------------------------------------------------------
*/
/*!
  Target url to issue the request to.
*/
qx.OO.addProperty({ name : "url", type : "string" });
/*!
  Determines what type of request to issue (GET or POST).
*/
qx.OO.addProperty(
{
  name           : "method",
  type           : "string",
  possibleValues : [
                   qx.net.Http.METHOD_GET, qx.net.Http.METHOD_POST,
                   qx.net.Http.METHOD_PUT, qx.net.Http.METHOD_HEAD,
                   qx.net.Http.METHOD_DELETE
                   ]
});
/*!
  Set the request to asynchronous.
*/
qx.OO.addProperty({ name : "asynchronous", type : "boolean", defaultValue : true,
                    getAlias: "isAsynchronous" });
/*!
  Set the data to be sent via this request
*/
qx.OO.addProperty({ name : "data", type : "string" });
/*!
  Username to use for HTTP authentication. Null if HTTP authentication
  is not used.
*/
qx.OO.addProperty({ name : "username", type : "string" });
/*!
  Password to use for HTTP authentication. Null if HTTP authentication
  is not used.
*/
qx.OO.addProperty({ name : "password", type : "string" });
qx.OO.addProperty(
{
  name           : "state",
  type           : "string",
  possibleValues : [
                   "configured", "queued",
                   "sending", "receiving",
                   "completed", "aborted",
                   "timeout", "failed"
                   ],
  defaultValue   : "configured"
});
/*
  Response type of request.

  The response type is a MIME type, default is text/plain. Other
  supported MIME types are text/javascript, text/html, application/json,
  application/xml.

  @see qx.util.Mime
*/
qx.OO.addProperty({
  name           : "responseType",
  type           : "string",
  possibleValues : [
                   qx.util.Mime.TEXT,
                   qx.util.Mime.JAVASCRIPT, qx.util.Mime.JSON,
                   qx.util.Mime.XML, qx.util.Mime.HTML
                   ]
});
/*!
  Number of millieseconds before the request is being timed out.

  If this property is null, the timeout for the request comes is the
  qx.io.remote.RequestQueue's property defaultTimeout.
*/
qx.OO.addProperty({ name : "timeout", type : "number" });

/*!
  Prohibit request from being cached.

  Setting the value to true adds a parameter "nocache" to the request
  with a value of the current time. Setting the value to false removes
  the parameter.
*/
qx.OO.addProperty({ name : "prohibitCaching", type : "boolean" });
/*!
  Indicate that the request is cross domain.

  A request is cross domain if the request's URL points to a host other
  than the local host. This switches the concrete implementation that
  is used for sending the request from qx.io.remote.XmlHttpTransport to
  qx.io.remote.ScriptTransport, because only the latter can handle cross domain
  requests.
*/
qx.OO.addProperty({ name : "crossDomain", type : "boolean", defaultValue : false });
/*!
  Indicate that the request will be used for a file upload.

  The request will be used for a file upload.  This switches the concrete
  implementation that is used for sending the request from
  qx.io.remote.XmlHttpTransport to qx.io.remote.IFrameTransport, because only
  the latter can handle file uploads.
*/
qx.OO.addProperty({ name : "fileUpload", type : "boolean", defaultValue : false });
/*!
  The transport instance used for the request.

  This is necessary to be able to abort an asynchronous request.
*/
qx.OO.addProperty({ name : "transport", type : "object", instance : "qx.io.remote.Exchange" });
/*!
  Use Basic HTTP Authentication
*/
qx.OO.addProperty({ name : "useBasicHttpAuth", type : "boolean" });






/*
---------------------------------------------------------------------------
  CORE METHODS
---------------------------------------------------------------------------
*/
/*!
  Schedule this request for transport to server.

  The request is added to the singleton class qx.io.remote.RequestQueue's list of
  pending requests.
*/
qx.Proto.send = function() {
  qx.io.remote.RequestQueue.getInstance().add(this);
}

/*!
  Abort sending this request.

  The request is removed from the singleton class qx.io.remote.RequestQueue's
  list of pending events. If the request haven't been scheduled this
  method is a noop.
*/
qx.Proto.abort = function() {
  qx.io.remote.RequestQueue.getInstance().abort(this);
}

qx.Proto.reset = function()
{
  switch(this.getState())
  {
    case "sending":
    case "receiving":
      this.error("Aborting already sent request!");
      // no break

    case "queued":
      this.abort();
      break;
  }
}







/*
---------------------------------------------------------------------------
  STATE ALIASES
---------------------------------------------------------------------------
*/

qx.Proto.isConfigured = function() {
  return this.getState() === "configured";
}

qx.Proto.isQueued = function() {
  return this.getState() === "queued";
}

qx.Proto.isSending = function() {
  return this.getState() === "sending";
}

qx.Proto.isReceiving = function() {
  return this.getState() === "receiving";
}

qx.Proto.isCompleted = function() {
  return this.getState() === "completed";
}

qx.Proto.isAborted = function() {
  return this.getState() === "aborted";
}

qx.Proto.isTimeout = function() {
  return this.getState() === "timeout";
}

/*!
  Return true if the request is in the failed state
  ("failed").
*/
qx.Proto.isFailed = function() {
  return this.getState() === "failed";
}







/*
---------------------------------------------------------------------------
  EVENT HANDLER
---------------------------------------------------------------------------
*/

qx.Proto._onqueued = function(e)
{
  // Modify internal state
  this.setState("queued");

  // Bubbling up
  this.dispatchEvent(e);
}

qx.Proto._onsending = function(e)
{
  // Modify internal state
  this.setState("sending");

  // Bubbling up
  this.dispatchEvent(e);
}

qx.Proto._onreceiving = function(e)
{
  // Modify internal state
  this.setState("receiving");

  // Bubbling up
  this.dispatchEvent(e);
}

qx.Proto._oncompleted = function(e)
{
  // Modify internal state
  this.setState("completed");

  // Bubbling up
  this.dispatchEvent(e);

  // Automatically dispose after event completion
  this.dispose();
}

qx.Proto._onaborted = function(e)
{
  // Modify internal state
  this.setState("aborted");

  // Bubbling up
  this.dispatchEvent(e);

  // Automatically dispose after event completion
  this.dispose();
}

qx.Proto._ontimeout = function(e)
{
/*
  // User's handler can block until timeout.
  switch(this.getState())
  {
    // If we're no longer running...
    case "completed":
    case "timeout":
    case "aborted":
    case "failed":
      // then don't bubble up the timeout event
      return;
  }
*/

  // Modify internal state
  this.setState("timeout");

  // Bubbling up
  this.dispatchEvent(e);

  // Automatically dispose after event completion
  this.dispose();
}

qx.Proto._onfailed = function(e)
{
  // Modify internal state
  this.setState("failed");

  // Bubbling up
  this.dispatchEvent(e);

  // Automatically dispose after event completion
  this.dispose();
}








/*
---------------------------------------------------------------------------
  MODIFIER
---------------------------------------------------------------------------
*/

qx.Proto._modifyState = function(propValue, propOldValue, propData)
{
  if (qx.Settings.getValueOfClass("qx.io.remote.Exchange", "enableDebug")) {
    this.debug("State: " + propValue);
  }

  return true;
}

qx.Proto._modifyProhibitCaching = function(propValue, propOldValue, propData)
{
  propValue ? this.setParameter("nocache", new Date().valueOf()) : this.removeParameter("nocache");

  return true;
}

qx.Proto._modifyMethod = function(propValue, propOldValue, propData)
{
  if (propValue === qx.net.Http.METHOD_POST) {
    this.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
  }

  return true;
}

qx.Proto._modifyResponseType = function(propValue, propOldValue, propData)
{
  this.setRequestHeader("X-Qooxdoo-Response-Type", propValue);
  return true;
}







/*
---------------------------------------------------------------------------
  REQUEST HEADER
---------------------------------------------------------------------------
*/
/*!
  Add a request header to the request.

  Example: request.setRequestHeader("Content-Type", qx.util.Mime.HTML)
*/
qx.Proto.setRequestHeader = function(vId, vValue) {
  this._requestHeaders[vId] = vValue;
}

qx.Proto.removeRequestHeader = function(vId) {
  delete this._requestHeaders[vId];
}

qx.Proto.getRequestHeader = function(vId) {
  return this._requestHeaders[vId] || null;
}

qx.Proto.getRequestHeaders = function() {
  return this._requestHeaders;
}









/*
---------------------------------------------------------------------------
  PARAMETERS
---------------------------------------------------------------------------
*/
/*!
  Add a parameter to the request.

  @param vId String identifier of the parameter to add.
  @param vValue Value of parameter. May be a string (for one parameter) or an
         array of strings (for setting multiple parameter values with the same
         parameter name).
*/
qx.Proto.setParameter = function(vId, vValue) {
  this._parameters[vId] = vValue;
}

/*!
  Remove a parameter from the request.

  @param vId String identifier of the parameter to remove.
*/
qx.Proto.removeParameter = function(vId) {
  delete this._parameters[vId];
}

/*!
  Get a parameter in the request.

  @param vId String identifier of the parameter to get.
*/
qx.Proto.getParameter = function(vId) {
  return this._parameters[vId] || null;
}

/*!
  Returns an object containg all parameters for the request.
*/
qx.Proto.getParameters = function() {
  return this._parameters;
}








/*
---------------------------------------------------------------------------
  SEQUENCE NUMBER
---------------------------------------------------------------------------
*/

/*
 * Sequence (id) number of a request, used to associate a response or error
 * with its initiating request.
 */
qx.io.remote.Request._seqNum = 0;

/**
 * Obtain the sequence (id) number used for this request
 */
qx.Proto.getSequenceNumber = function() {
  return this._seqNum;
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

  this._requestHeaders = null;
  this._parameters = null;

  this.setTransport(null);

  return qx.core.Target.prototype.dispose.call(this);
}
