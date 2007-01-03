/* ************************************************************************

   qooxdoo - the new era of web development

   http://qooxdoo.org

   Copyright:
     2006 by STZ-IDA, Germany, http://www.stz-ida.de
     2006 by Derrell Lipman

   License:
     LGPL 2.1: http://www.gnu.org/licenses/lgpl.html

   Authors:
     * Andreas Junghans (lucidcake)
     * Derrell Lipman (derrell)

************************************************************************ */

/* ************************************************************************

#module(io_remote)

************************************************************************ */


/**
 * Provides a Remote Procedure Call (RPC) implementation.
 *
 * Each instance of this class represents a "Service". These services can
 * correspond to various concepts on the server side (depending on the
 * programming language/environment being used), but usually, a service means
 * a class on the server.
 *
 * In case multiple instances of the same service are needed, they can be
 * distinguished by ids. If such an id is specified, the server routes all
 * calls to a service that have the same id to the same server-side instance.
 *
 * When calling a server-side method, the parameters and return values are
 * converted automatically. Supported types are int (and Integer), double
 * (and Double), String, Date, Map, and JavaBeans. Beans must habe a default
 * constructor on the server side and are represented by simple JavaScript
 * objects on the client side (used as associative arrays with keys matching
 * the server-side properties). Beans can also be nested, but be careful to not
 * create circular references! There are no checks to detect these (which would
 * be expensive), so you as the user are responsible for avoiding them.
 *
 * @param       url {string}            identifies the url where the service
 *                                      is found.  Note that if the url is to
 *                                      a domain (server) other than where the
 *                                      qooxdoo script came from, i.e. it is
 *                                      cross-domain, then you must also call
 *                                      the setCrossDomain(true) method to
 *                                      enable the IframeTrannsport instead of
 *                                      the XmlHttpTransport, since the latter
 *                                      can not handle cross-domain requests.
 *
 * @param       serviceName {string}    identifies the service. For the Java
 *                                      implementation, this is the fully
 *                                      qualified name of the class that offers
 *                                      the service methods
 *                                      (e.g. "my.pkg.MyService").
 *
 * @event completed (qx.event.type.DataEvent)
 * @event failed (qx.event.type.DataEvent)
 * @event timeout (qx.event.type.DataEvent)
 * @event aborted (qx.event.type.DataEvent)
 */

qx.OO.defineClass("qx.io.remote.Rpc", qx.core.Target,
function(url, serviceName)
{
  qx.core.Target.call(this);

  this.setUrl(url);
  if (serviceName != null) {
    this.setServiceName(serviceName);
  }
  this._previousServerSuffix = null;
  this._currentServerSuffix = null;
  if (qx.core.ServerSettings) {
    this._currentServerSuffix = qx.core.ServerSettings.serverPathSuffix;
  }
});






/*
---------------------------------------------------------------------------
  PROPERTIES
---------------------------------------------------------------------------
*/

/**
  The timeout for asynchronous calls in milliseconds.
 */
qx.OO.addProperty({ name : "timeout", type : "number" });

/**
  Indicate that the request is cross domain.

  A request is cross domain if the request's URL points to a host other
  than the local host. This switches the concrete implementation that
  is used for sending the request from qx.io.remote.XmlHttpTransport to
  qx.io.remote.ScriptTransport because only the latter can handle cross domain
  requests.
*/
qx.OO.addProperty({ name : "crossDomain", type : "boolean", defaultValue : false });

/**
  The URL at which the service is located.
*/
qx.OO.addProperty({ name : "url", type : "string", defaultValue : null });

/**
  The service name.
*/
qx.OO.addProperty({ name : "serviceName", type : "string", defaultValue : null });

/**
  Data sent as "out of band" data in the request to the server.  The format of
  the data is opaque to RPC and may be recognized only by particular servers
  It is up to the server to decide what to do with it: whether to ignore it,
  handle it locally before calling the specified method, or pass it on to the
  method.  This server data is not sent to the server if it has been set to
  'undefined'.
*/
qx.OO.addProperty({ name : "serverData", type : "object", defaultValue : undefined });

/**
  Username to use for HTTP authentication. Null if HTTP authentication
  is not used.
*/
qx.OO.addProperty({ name : "username", type : "string" });

/**
  Password to use for HTTP authentication. Null if HTTP authentication
  is not used.
*/
qx.OO.addProperty({ name : "password", type : "string" });

/**
  Use Basic HTTP Authentication
*/
qx.OO.addProperty({ name : "useBasicHttpAuth", type : "boolean" });

/**
   Origins of errors
*/
qx.io.remote.Rpc.origin =
{
  server      : 1,
  application : 2,
  transport   : 3,
  local       : 4
}

/**
   Locally-detected errors
*/
qx.io.remote.Rpc.localError =
{
  timeout     : 1,
  abort       : 2
}


/*
---------------------------------------------------------------------------
  CORE METHODS
---------------------------------------------------------------------------
*/

/* callType: 0 = sync, 1 = async with handler, 2 = async event listeners */
qx.Proto._callInternal = function(args, callType, refreshSession) {
  var self = this;
  var offset = (callType == 0 ? 0 : 1)
  var whichMethod = (refreshSession ? "refreshSession" : args[offset]);
  var handler = args[0];
  var argsArray = [];
  var eventTarget = this;

  for (var i = offset + 1; i < args.length; ++i) {
    argsArray.push(args[i]);
  }
  var req = new qx.io.remote.Request(this.getUrl(),
                                           qx.net.Http.METHOD_POST,
                                           "text/json");
  var requestObject = {
    "service": (refreshSession ? null : this.getServiceName()),
    "method": whichMethod,
    "id": req.getSequenceNumber(),
    "params": argsArray
    // additional field 'server_data' optionally included, below
  }

  // See if there's any out-of-band data to be sent to the server
  var serverData = this.getServerData();
  if (serverData !== undefined) {
    // There is.  Send it.
    requestObject.server_data = serverData;
  }

  req.setCrossDomain(this.getCrossDomain());

  if (this.getUsername()) {
    req.setUseBasicHttpAuth(this.getUseBasicHttpAuth());
    req.setUsername(this.getUsername());
    req.setPassword(this.getPassword());
  }

  req.setTimeout(this.getTimeout());
  var ex = null;
  var id = null;
  var result = null;

  var handleRequestFinished = function(eventType, eventTarget) {
    switch(callType)
    {
    case 0:                     // sync
      break;

    case 1:                     // async with handler function
      handler(result, ex, id);
      break;

    case 2:                     // async with event listeners
      // Dispatch the event to our listeners.
      if (! ex) {
        eventTarget.createDispatchDataEvent(eventType, result);
      } else {
        // Add the id to the exception
        ex.id = id;

        if (args[0]) {          // coalesce
          // They requested that we coalesce all failure types to "failed"
          eventTarget.createDispatchDataEvent("failed", ex);
        } else {
          // No coalese so use original event type
          eventTarget.createDispatchDataEvent(eventType, ex);
        }
      }
    }
  }

  var addToStringToObject = function(obj) {
    obj.toString = function() {
      switch(obj.origin)
      {
      case qx.io.remote.Rpc.origin.server:
        return "Server error " + obj.code + ": " + obj.message;
      case qx.io.remote.Rpc.origin.application:
        return "Application error " + obj.code + ": " + obj.message;
      case qx.io.remote.Rpc.origin.transport:
        return "Transport error " + obj.code + ": " + obj.message;
      case qx.io.remote.Rpc.origin.local:
        return "Local error " + obj.code + ": " + obj.message;
      default:
        return "UNEXPECTED origin " + obj.origin + " error " + obj.code + ": " + obj.message;
      }
    }
  }

  var makeException = function(origin, code, message) {
    var ex = new Object();

    ex.origin = origin;
    ex.code = code;
    ex.message = message;
    addToStringToObject(ex);

    return ex;
  }

  req.addEventListener("failed", function(evt) {
    var code = evt.getData().getStatusCode();
    ex = makeException(qx.io.remote.Rpc.origin.transport,
                       code,
                       qx.io.remote.Exchange.statusCodeToString(code));
    id = this.getSequenceNumber();
    handleRequestFinished("failed", eventTarget);
  });
  req.addEventListener("timeout", function(evt) {
    ex = makeException(qx.io.remote.Rpc.origin.local,
                       qx.io.remote.Rpc.localError.timeout,
                       "Local time-out expired");
    id = this.getSequenceNumber();
    handleRequestFinished("timeout", eventTarget);
  });
  req.addEventListener("aborted", function(evt) {
    ex = makeException(qx.io.remote.Rpc.origin.local,
                       qx.io.remote.Rpc.localError.abort,
                       "Aborted");
    id = this.getSequenceNumber();
    handleRequestFinished("aborted", eventTarget);
  });
  req.addEventListener("completed", function(evt) {
    result = evt.getData().getContent();
    id = result["id"];
    if (id != this.getSequenceNumber()) {
      this.warn("Received id (" + id + ") does not match requested id (" + this.getSequenceNumber() + ")!");
    }
    var exTest = result["error"];
    if (exTest != null) {
      result = null;
      addToStringToObject(exTest);
      ex = exTest;
    } else {
      result = result["result"];
      if (refreshSession) {
        result = eval("(" + result + ")");
        var newSuffix = qx.core.ServerSettings.serverPathSuffix;
        if (self._currentServerSuffix != newSuffix) {
          self._previousServerSuffix = self._currentServerSuffix;
          self._currentServerSuffix = newSuffix;
        }
        self.setUrl(self.fixUrl(self.getUrl()));
      }
    }
    handleRequestFinished("completed", eventTarget);
  });
  req.setData(qx.io.Json.stringify(requestObject));
  req.setAsynchronous(callType > 0);

  if (req.getCrossDomain()) {
    // Our choice here has no effect anyway.  This is purely informational.
    req.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
  } else {
    // When not cross-domain, set type to text/json
    req.setRequestHeader("Content-Type", "text/json");
  }

  req.send();

  if (callType == 0) {
      if (ex != null) {
        var error = new Error(ex.toString());
        error.rpcdetails = ex;
        throw error;
      }
      return result;
  } else {
    return req;
  }
}


/**
 * Helper method to rewrite a URL with a stale session id (so that it includes
 * the correct session id afterwards).
 *
 * @param url {string}        the URL to examine.
 *
 * @return {string}            the (possibly re-written) URL.
 */

qx.Proto.fixUrl = function(url) {
  if (this._previousServerSuffix == null || this._currentServerSuffix == null ||
    this._previousServerSuffix == "" ||
    this._previousServerSuffix == this._currentServerSuffix) {
    return url;
  }
  var index = url.indexOf(this._previousServerSuffix);
  if (index == -1) {
    return url;
  }
  return url.substring(0, index) + this._currentServerSuffix +
         url.substring(index + this._previousServerSuffix.length);
};


/**
 * Makes a synchronous server call. The method arguments (if any) follow
 * after the method name (as normal JavaScript arguments, separated by commas,
 * not as an array).
 * <p>
 * If a problem occurs when making the call, an exception is thrown.
 * </p>
 * <p>
 * WARNING.  With some browsers, the synchronous interface
 * causes the browser to hang while awaiting a response!  If the server
 * decides to pause for a minute or two, your browser may do nothing
 * (including refreshing following window changes) until the response is
 * received.  Instead, use the asynchronous interface.
 * </p>
 * <p>
 * YOU HAVE BEEN WARNED.
 * </p>
 *
 * @param       methodName {string}   the name of the method to call.
 *
 * @return      {var}                 the result returned by the server.
 */

qx.Proto.callSync = function(methodName) {
  return this._callInternal(arguments, 0);
}


/**
 * Makes an asynchronous server call. The method arguments (if any) follow
 * after the method name (as normal JavaScript arguments, separated by commas,
 * not as an array).
 * <p>
 * When an answer from the server arrives, the <code>handler</code> function
 * is called with the result of the call as the first,  an exception as the
 * second parameter, and the id (aka sequence number) of the invoking request
 * as the third parameter. If the call was successful, the second parameter is
 * <code>null</code>. If there was a problem, the second parameter contains an
 * exception, and the first one is <code>null</code>.
 * </p>
 * <p>
 * The return value of this method is a call reference that you can store if
 * you want to abort the request later on. This value should be treated as
 * opaque and can change completely in the future! The only thing you can rely
 * on is that the <code>abort</code> method will accept this reference and
 * that you can retrieve the sequence number of the request by invoking the
 * getSequenceNumber() method (see below).
 * </p>
 * <p>
 * If a specific method is being called, asynchronously, a number of times in
 * succession, the getSequenceNumber() method may be used to disambiguate
 * which request a response corresponds to.  The sequence number value is a
 * value which increments with each request.)
 * </p>
 *
 * @param       handler {Function}    the callback function.
 *
 * @param       methodName {string}   the name of the method to call.
 *
 * @return      {var}                 the method call reference.
 */

qx.Proto.callAsync = function(handler, methodName) {
  return this._callInternal(arguments, 1);
}


/**
 * Makes an asynchronous server call and dispatch an event upon completion or
 * failure. The method arguments (if any) follow after the method name (as
 * normal JavaScript arguments, separated by commas, not as an array).
 * <p>
 * When an answer from the server arrives (or fails to arrive on time), if an
 * exception occurred, a "failed", "timeout" or "aborted" event, as
 * appropriate, is dispatched to any waiting event listeners.  If no exception
 * occurred, a "completed" event is dispatched.
 * </p>
 * <p>
 * When a "failed", "timeout" or "aborted" event is dispatched, the event data
 * contains an object with the properties 'origin', 'code', 'message' and
 * 'id'.  The object has a toString() function which may be called to convert
 * the exception to a string.
 * </p>
 * <p>
 * When a "completed" event is dispatched, the event data contains the
 * JSON-RPC result.
 * </p>
 * <p>
 * The return value of this method is a call reference that you can store if
 * you want to abort the request later on. This value should be treated as
 * opaque and can change completely in the future! The only thing you can rely
 * on is that the <code>abort</code> method will accept this reference and
 * that you can retrieve the sequence number of the request by invoking the
 * getSequenceNumber() method (see below).
 * </p>
 * <p>
 * If a specific method is being called, asynchronously, a number of times in
 * succession, the getSequenceNumber() method may be used to disambiguate
 * which request a response corresponds to.  The sequence number value is a
 * value which increments with each request.)
 * </p>
 *
 * @param       coalesce (boolean)    coalesce all failure types ("failed",
 *                                    "timeout", and "aborted") to "failed".
 *                                    This is reasonable in many cases, as
 *                                    the provided exception contains adequate
 *                                    disambiguating information.
 *
 * @param       methodName (string)   the name of the method to call.
 *
 * @return      (var)                 the method call reference.
 */

qx.Proto.callAsyncListeners = function(coalesce, methodName) {
  return this._callInternal(arguments, 2);
}


/**
 * Refreshes a server session by retrieving the session id again from the
 * server.
 * <p>
 * The specified handler function is called when the refresh is complete. The
 * first parameter can be <code>true</code> (indicating that a refresh either
 * wasn't necessary at this time or it was successful) or <code>false</code>
 * (indicating that a refresh would have been necessary but can't be performed
 * because the server backend doesn't support it). If there is a non-null
 * second parameter, it's an exception indicating that there was an error when
 * refreshing the session.
 * </p>
 *
 * @param   handler {Function}      a callback function that is called when the
 *                                  refresh is complete (or failed).
 */

qx.Proto.refreshSession = function(handler) {
  if (this.getCrossDomain()) {
    if (qx.core.ServerSettings && qx.core.ServerSettings.serverPathSuffix) {
      var timeDiff = (new Date()).getTime() - qx.core.ServerSettings.lastSessionRefresh;
      if (timeDiff/1000 > (qx.core.ServerSettings.sessionTimeoutInSeconds - 30)) {
        //this.info("refreshing session");
        this._callInternal([handler], 1, true);
      } else {
        handler(true);    // session refresh was OK (in this case: not needed)
      }
    } else {
      handler(false);   // no refresh possible, but would be necessary
    }
  } else {
    handler(true);  // session refresh was OK (in this case: not needed)
  }
}


/**
 * Aborts an asynchronous server call. Consequently, the callback function
 * provided to <code>callAsync</code> or <code>callAsyncListeners</code> will
 * be called with an exception.
 *
 * @param       opaqueCallRef {var}     the call reference as returned by
 *                                      <code>callAsync</code> or
 *                                      <code>callAsyncListeners</code>
 */

qx.Proto.abort = function(opaqueCallRef) {
  opaqueCallRef.abort();
}


/**
 * Creates an URL for talking to a local service. A local service is one that
 * lives in the same application as the page calling the service. For backends
 * that don't support this auto-generation, this method returns null.
 *
 * @param       instanceId {string ? null}    an optional identifier for the
 *                                          server side instance that should be
 *                                          used. All calls to the same service
 *                                          with the same instance id are
 *                                          routed to the same object instance
 *                                          on the server. The instance id can
 *                                          also be used to provide additional
 *                                          data for the service instantiation
 *                                          on the server.
 *
 * @return      {string}                    the url.
 */

qx.Class.makeServerURL = function(instanceId) {
  var retVal = null;
  if (qx.core.ServerSettings) {
    retVal = qx.core.ServerSettings.serverPathPrefix + "/.qxrpc" +
             qx.core.ServerSettings.serverPathSuffix;
    if (instanceId != null) {
      retVal += "?instanceId=" + instanceId;
    }
  }
  return retVal;
}
