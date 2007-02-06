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

************************************************************************ */

/**
 * Handles scheduling of requests to be sent to a server.
 *
 * This class is a singleton and is used by qx.io.remote.Request to schedule its
 * requests. It should not be used directly.
 */
qx.OO.defineClass("qx.io.remote.RequestQueue", qx.core.Target,
function()
{
  qx.core.Target.call(this);

  this._queue = [];
  this._active = [];

  this._totalRequests = 0;

  // timeout handling
  this._timer = new qx.client.Timer(500);
  this._timer.addEventListener("interval", this._oninterval, this);
});




/*
---------------------------------------------------------------------------
  PROPERTIES
---------------------------------------------------------------------------
*/

/**
 * @deprecated
 */
qx.OO.addProperty({ name : "maxTotalRequests", type : "number" });

/**
 * Maximum number of parallel requests.
 */
qx.OO.addProperty({ name : "maxConcurrentRequests", type : "number", defaultValue : 3 });

/**
 * Default timeout for remote requests in milliseconds.
 */
qx.OO.addProperty({ name : "defaultTimeout", type : "number", defaultValue : 5000 });






/*
---------------------------------------------------------------------------
  QUEUE HANDLING
---------------------------------------------------------------------------
*/

qx.Proto._debug = function()
{
  // Debug output
  var vText = this._active.length + "/" + (this._queue.length+this._active.length);

  if (qx.Settings.getValueOfClass("qx.io.remote.Exchange", "enableDebug"))
  {
    this.debug("Progress: " + vText);
    window.status = "Request-Queue Progress: " + vText;
  }
}

qx.Proto._check = function()
{
  // Debug output
  this._debug();

  // Check queues and stop timer if not needed anymore
  if (this._active.length == 0 && this._queue.length == 0) {
    this._timer.stop();
  }

  // Checking if enabled
  if (!this.getEnabled()) {
    return;
  }

  // Checking active queue fill
  if (this._active.length >= this.getMaxConcurrentRequests() || this._queue.length == 0) {
    return;
  }

  // Checking number of total requests
  if (this.getMaxTotalRequests() != null && this._totalRequests >= this.getMaxTotalRequests()) {
    return;
  }

  var vRequest = this._queue.shift();
  var vTransport = new qx.io.remote.Exchange(vRequest);

  // Increment counter
  this._totalRequests++;

  // Add to active queue
  this._active.push(vTransport);

  // Debug output
  this._debug();

  // Establish event connection between qx.io.remote.Exchange instance and qx.io.remote.Request
  vTransport.addEventListener("sending", vRequest._onsending, vRequest);
  vTransport.addEventListener("receiving", vRequest._onreceiving, vRequest);
  vTransport.addEventListener("completed", vRequest._oncompleted, vRequest);
  vTransport.addEventListener("aborted", vRequest._onaborted, vRequest);
  vTransport.addEventListener("timeout", vRequest._ontimeout, vRequest);
  vTransport.addEventListener("failed", vRequest._onfailed, vRequest);

  // Establish event connection between qx.io.remote.Exchange and me.
  vTransport.addEventListener("sending", this._onsending, this);
  vTransport.addEventListener("completed", this._oncompleted, this);
  vTransport.addEventListener("aborted", this._oncompleted, this);
  vTransport.addEventListener("timeout", this._oncompleted, this);
  vTransport.addEventListener("failed", this._oncompleted, this);

  // Store send timestamp
  vTransport._start = (new Date).valueOf();

  // Send
  vTransport.send();

  // Retry
  if (this._queue.length > 0) {
    this._check();
  }
}

qx.Proto._remove = function(vTransport)
{
  var vRequest = vTransport.getRequest();

  // Destruct event connection between qx.io.remote.Exchange instance and qx.io.remote.Request
  vTransport.removeEventListener("sending", vRequest._onsending, vRequest);
  vTransport.removeEventListener("receiving", vRequest._onreceiving, vRequest);
  vTransport.removeEventListener("completed", vRequest._oncompleted, vRequest);
  vTransport.removeEventListener("aborted", vRequest._onaborted, vRequest);
  vTransport.removeEventListener("timeout", vRequest._ontimeout, vRequest);
  vTransport.removeEventListener("failed", vRequest._onfailed, vRequest);

  // Destruct event connection between qx.io.remote.Exchange and me.
  vTransport.removeEventListener("sending", this._onsending, this);
  vTransport.removeEventListener("completed", this._oncompleted, this);
  vTransport.removeEventListener("aborted", this._oncompleted, this);
  vTransport.removeEventListener("timeout", this._oncompleted, this);
  vTransport.removeEventListener("failed", this._oncompleted, this);

  // Remove from active transports
  qx.lang.Array.remove(this._active, vTransport);

  // Dispose transport object
  vTransport.dispose();

  // Check again
  this._check();
}







/*
---------------------------------------------------------------------------
  EVENT HANDLING
---------------------------------------------------------------------------
*/

qx.Proto._activeCount = 0;

qx.Proto._onsending = function(e)
{
  if (qx.Settings.getValueOfClass("qx.io.remote.Exchange", "enableDebug"))
  {
    this._activeCount++;
    e.getTarget()._counted = true;

    this.debug("ActiveCount: " + this._activeCount);
  }
}

qx.Proto._oncompleted = function(e)
{
  if (qx.Settings.getValueOfClass("qx.io.remote.Exchange", "enableDebug"))
  {
    if (e.getTarget()._counted)
    {
      this._activeCount--;
      this.debug("ActiveCount: " + this._activeCount);
    }
  }

  this._remove(e.getTarget());
}







/*
---------------------------------------------------------------------------
  TIMEOUT HANDLING
---------------------------------------------------------------------------
*/

qx.Proto._oninterval = function(e)
{
  var vActive = this._active;

  if (vActive.length == 0) {
    return;
  }

  var vCurrent = (new Date).valueOf();
  var vTransport;
  var vRequest;
  var vDefaultTimeout = this.getDefaultTimeout();
  var vTimeout;
  var vTime;

  for (var i=vActive.length-1; i>=0; i--)
  {
    vTransport = vActive[i];
    vRequest = vTransport.getRequest();
    if (vRequest.isAsynchronous()) {
      vTimeout = vRequest.getTimeout();

      // if timer is disabled...
      if (vTimeout == 0) {
        // then ignore it.
        continue;
      }

      if (vTimeout == null) {
        vTimeout = vDefaultTimeout;
      }

      vTime = vCurrent - vTransport._start;

      if (vTime > vTimeout)
      {
        this.warn("Timeout: transport " + vTransport.toHashCode());
        this.warn(vTime + "ms > " + vTimeout + "ms");
        vTransport.timeout();
      }
    }
  }
}




/*
---------------------------------------------------------------------------
  MODIFIERS
---------------------------------------------------------------------------
*/

qx.Proto._modifyEnabled = function(propValue, propOldValue, propData)
{
  if (propValue) {
    this._check();
  }

  this._timer.setEnabled(propValue);

  return true;
}







/*
---------------------------------------------------------------------------
  CORE METHODS
---------------------------------------------------------------------------
*/
/*!
  Add the request to the pending requests queue.
*/
qx.Proto.add = function(vRequest)
{
  vRequest.setState("queued");

  this._queue.push(vRequest);
  this._check();

  if (this.getEnabled()) {
    this._timer.start();
  }
}

/*!
  Remove the request from the pending requests queue.

  The underlying transport of the request is forced into the aborted
  state ("aborted") and listeners of the "aborted"
  signal are notified about the event. If the request isn't in the
  pending requests queue, this method is a noop.
*/
qx.Proto.abort = function(vRequest)
{
  var vTransport = vRequest.getTransport();

  if (vTransport)
  {
    vTransport.abort();
  }
  else if (qx.lang.Array.contains(this._queue, vRequest))
  {
    qx.lang.Array.remove(this._queue, vRequest);
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
    return true;
  }

  if (this._active)
  {
    for (var i=0, a=this._active, l=a.length; i<l; i++) {
      this._remove(a[i]);
    }

    this._active = null;
  }

  if (this._timer)
  {
    this._timer.removeEventListener("interval", this._oninterval, this);
    this._timer = null;
  }

  this._queue = null;

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
