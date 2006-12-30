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

#module(io_remote)

************************************************************************ */

/**
 * @event created {qx.event.type.Event}
 * @event configured {qx.event.type.Event}
 * @event sending {qx.event.type.Event}
 * @event receiving {qx.event.type.Event}
 * @event completed {qx.event.type.Event}
 * @event aborted {qx.event.type.Event}
 * @event failed {qx.event.type.Event}
 * @event timeout {qx.event.type.Event}
 */
qx.OO.defineClass("qx.io.remote.AbstractRemoteTransport", qx.core.Target,
function() {
  qx.core.Target.call(this);
});






/*
---------------------------------------------------------------------------
  PROPERTIES
---------------------------------------------------------------------------
*/

/*!
  Target url to issue the request to
*/
qx.OO.addProperty({ name : "url", type : "string" });

/*!
  Determines what type of request to issue
*/
qx.OO.addProperty({ name : "method", type : "string" });

/*!
  Set the request to asynchronous
*/
qx.OO.addProperty({ name : "asynchronous", type : "boolean" });

/*!
  Set the data to be sent via this request
*/
qx.OO.addProperty({ name : "data", type : "string" });

/*!
  Username to use for HTTP authentication
*/
qx.OO.addProperty({ name : "username", type : "string" });

/*!
  Password to use for HTTP authentication
*/
qx.OO.addProperty({ name : "password", type : "string" });

/*!
  The state of the current request
*/
qx.OO.addProperty(
{
  name           : "state",
  type           : "string",
  possibleValues : [
                   "created", "configured",
                   "sending", "receiving",
                   "completed", "aborted",
                   "timeout", "failed"
                   ],
  defaultValue   : "created"
});

/*!
  Request headers
*/
qx.OO.addProperty({ name : "requestHeaders", type: "object" });

/*!
  Request parameters to send.
*/
qx.OO.addProperty({ name : "parameters", type: "object" });

/*!
  Response Type
*/
qx.OO.addProperty({ name : "responseType", type: "string" });

/*!
  Use Basic HTTP Authentication
*/
qx.OO.addProperty({ name : "useBasicHttpAuth", type : "boolean" });







/*
---------------------------------------------------------------------------
  USER METHODS
---------------------------------------------------------------------------
*/

qx.Proto.send = function() {
  throw new Error("send is abstract");
}

qx.Proto.abort = function()
{
  if (qx.Settings.getValueOfClass("qx.io.remote.Exchange", "enableDebug")) {
    this.warn("Aborting...");
  }

  this.setState("aborted");
}

/*!

*/
qx.Proto.timeout = function()
{
  if (qx.Settings.getValueOfClass("qx.io.remote.Exchange", "enableDebug")) {
    this.warn("Timeout...");
  }

  this.setState("timeout");
}

/*!

  Force the transport into the failed state ("failed").

  Listeners of the "failed" signal are notified about the event.
*/
qx.Proto.failed = function()
{
  if (qx.Settings.getValueOfClass("qx.io.remote.Exchange", "enableDebug")) {
    this.warn("Failed...");
  }

  this.setState("failed");
}







/*
---------------------------------------------------------------------------
  REQUEST HEADER SUPPORT
---------------------------------------------------------------------------
*/
/*!
  Add a request header to this transports qx.io.remote.Request.

  This method is virtual and concrete subclasses are supposed to
  implement it.
*/
qx.Proto.setRequestHeader = function(vLabel, vValue) {
  throw new Error("setRequestHeader is abstract");
}






/*
---------------------------------------------------------------------------
  RESPONSE HEADER SUPPORT
---------------------------------------------------------------------------
*/

qx.Proto.getResponseHeader = function(vLabel) {
  throw new Error("getResponseHeader is abstract");
}

/*!
  Provides an hash of all response headers.
*/
qx.Proto.getResponseHeaders = function() {
  throw new Error("getResponseHeaders is abstract");
}







/*
---------------------------------------------------------------------------
  STATUS SUPPORT
---------------------------------------------------------------------------
*/

/*!
  Returns the current status code of the request if available or -1 if not.
*/
qx.Proto.getStatusCode = function() {
  throw new Error("getStatusCode is abstract");
}

/*!
  Provides the status text for the current request if available and null otherwise.
*/
qx.Proto.getStatusText = function() {
  throw new Error("getStatusText is abstract");
}






/*
---------------------------------------------------------------------------
  RESPONSE DATA SUPPORT
---------------------------------------------------------------------------
*/

/*!
  Provides the response text from the request when available and null otherwise.
  By passing true as the "partial" parameter of this method, incomplete data will
  be made available to the caller.
*/
qx.Proto.getResponseText = function() {
  throw new Error("getResponseText is abstract");
}

/*!
  Provides the XML provided by the response if any and null otherwise.
  By passing true as the "partial" parameter of this method, incomplete data will
  be made available to the caller.
*/
qx.Proto.getResponseXml = function() {
  throw new Error("getResponseXml is abstract");
}

/*!
  Returns the length of the content as fetched thus far
*/
qx.Proto.getFetchedLength = function() {
  throw new Error("getFetchedLength is abstract");
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

  switch(propValue)
  {
    case "created":
      this.createDispatchEvent("created");
      break;

    case "configured":
      this.createDispatchEvent("configured");
      break;

    case "sending":
      this.createDispatchEvent("sending");
      break;

    case "receiving":
      this.createDispatchEvent("receiving");
      break;

    case "completed":
      this.createDispatchEvent("completed");
      break;

    case "aborted":
      this.createDispatchEvent("aborted");
      break;

    case "failed":
      this.createDispatchEvent("failed");
      break;

    case "timeout":
      this.createDispatchEvent("timeout");
      break;
  }

  return true;
}
