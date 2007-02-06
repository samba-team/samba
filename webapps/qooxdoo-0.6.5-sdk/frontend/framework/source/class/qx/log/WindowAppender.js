/* ************************************************************************

   qooxdoo - the new era of web development

   http://qooxdoo.org

   Copyright:
     2006 STZ-IDA, Germany, http://www.stz-ida.de

   License:
     LGPL: http://www.gnu.org/licenses/lgpl.html
     EPL: http://www.eclipse.org/org/documents/epl-v10.php
     See the LICENSE file in the project's top-level directory for details.

   Authors:
     * Til Schneider (til132)

************************************************************************ */

/* ************************************************************************

#module(core)
#module(log)

************************************************************************ */

/**
 * An appender that writes all messages to a log window.
 * <p>
 * This class does not depend on qooxdoo widgets, so it also works when there
 * are problems with widgets or when the widgets are not yet initialized.
 *
 * @param name {String ? "qx_log"} the name of the log window.
 */
qx.OO.defineClass("qx.log.WindowAppender", qx.log.Appender,
function(name) {
  qx.log.Appender.call(this);

  this._id = qx.log.WindowAppender.register(this);
  this._name = (name == null) ? "qx_log" : name;

  this._errorsPreventingAutoCloseCount = 0;

  this._logWindowOpened = false;
});


/**
 * The maximum number of messages to show. If null the number of messages is not
 * limited.
 */
qx.OO.addProperty({ name:"maxMessages", type:"number", defaultValue:500 });

/** Whether the window should appear under the main window. */
qx.OO.addProperty({ name:"popUnder", type:"boolean", defaultValue:false, allowNull:false });

/** Whether the window should automatically be closed when its creating page is unloaded and
 * errors have been logged. Note that errors that have been logged before this property has been
 * turned off will be ignored. Warning: Turning this off may create a memory hole because the disposer
 * of this class will auto-close the window, i. e. it may stay open after dispose(), still holding
 * memory. However, for diagnostics it is often more important to get information about errors
 * than to save memory.
 */
qx.OO.addProperty({ name:"autoCloseWithErrors", type:"boolean", defaultValue:true, allowNull:false });


/**
 * Creates and opens the log window if it doesn't alread exist.
 */
qx.Proto.openWindow = function() {
  if (this._logWindowOpened) {
    // The window is already open -> Nothing to do
    return;
  }

  // Open the logger window
  var winWidth = 600;
  var winHeight = 350;
  var winLeft = window.screen.width - winWidth;
  var winTop = window.screen.height - winHeight;
  var params = "toolbar=no,scrollbars=yes,resizable=yes,"
    + "width=" + winWidth + ",height=" + winHeight
    + ",left=" + winLeft + ",top=" + winTop;

  // NOTE: In window.open the browser will process the event queue.
  //     Which means that other log events may arrive during this time.
  //     The log window is then in an inconsistent state, because the
  //     this._logElem is not created yet. These events will be added to the
  //     this._logEventQueue and logged after this._logElem is created.
  this._logWindow = window.open("", this._name, params);

  if (!this._logWindow || this._logWindow.closed)
  {
    if (!this._popupBlockerWarning) {
      alert("Couldn't open debug window. Please disable your popup blocker!");
    }

    this._popupBlockerWarning = true;
    return;
  }

  // Seems to be OK now.
  this._popupBlockerWarning = false;

  // Store that window is open
  this._logWindowOpened = true;

  if (this.getPopUnder()) {
    this._logWindow.blur();
    window.focus();
  }

  var logDocument = this._logWindow.document;
  // NOTE: We have to use a static onunload handler, because an onunload
  //     that is set later using DOM is ignored completely.
  //     (at least in Firefox, but maybe in IE, too)
  logDocument.open();
  logDocument.write("<html><head><title>" + this._name + "</title></head>"
    + '<body onload="qx = opener.qx;" onunload="try{qx.log.WindowAppender._registeredAppenders[' + this._id + ']._autoCloseWindow()}catch(e){}">'
    + '<pre id="log" wrap="wrap" style="font-size:11"></pre></body></html>');
  logDocument.close();

  this._logElem = logDocument.getElementById("log");

  // Log the events from the queue
  if (this._logEventQueue != null) {
    for (var i = 0; i < this._logEventQueue.length; i++) {
      this.appendLogEvent(this._logEventQueue[i]);
    }
    this._logEventQueue = null;
  }
};


/**
 * Closes the log window.
 */
qx.Proto.closeWindow = function() {
  if (this._logWindow != null) {
    this._logWindow.close();
    this._logWindow = null;
    this._logElem = null;
    this._logWindowOpened = false;
  }
};

/**
 * Called when the window should be automatically closed (because the page that opened
 * is is unloaded). Will only close the window if the autoClose***-Properties allow it
 */
qx.Proto._autoCloseWindow = function() {
  if (this.getAutoCloseWithErrors() || this._errorsPreventingAutoCloseCount == 0){
    this.closeWindow();
  } else  {
    //Show message why auto-close has failed
    this._showMessageInLog("Log window message: <b>Note: " + this._errorsPreventingAutoCloseCount
                        + " errors have been recorded, keeping log window open.</b>");
  }
};

/**
 * Appends a line to the log showing the given text
 * @param msg {String} message to show, may be HTML
 */
qx.Proto._showMessageInLog = function(msg) {
  //Create dummy log event and use appendLogEvent()
  //Reason is that it is rather complicated to get something into the log
  //window when it is not already open -> reuse the existing code
  //which does event queuing in such a case
  var dummyEvent = {message: msg, isDummyEventForMessage : true};
  this.appendLogEvent(dummyEvent);
};


// overridden
qx.Proto.appendLogEvent = function(evt) {
  if (!this._logWindowOpened) {
    this._logEventQueue = [];
    this._logEventQueue.push(evt);

    this.openWindow();

    // Popup-Blocker was active!
    if (!this._logWindowOpened) {
      return;
    }
  } else if (this._logElem == null) {
    // The window is currenlty opening, but not yet finished
    // -> Put the event in the queue
    this._logEventQueue.push(evt);
  } else {
    var divElem = this._logWindow.document.createElement("div");
    if (evt.level >= qx.log.Logger.LEVEL_ERROR) {
      divElem.style.backgroundColor = "#FFEEEE";
      if (!this.getAutoCloseWithErrors()){
        this._errorsPreventingAutoCloseCount += 1;
      }
    } else if (evt.level == qx.log.Logger.LEVEL_DEBUG) {
      divElem.style.color = "gray";
    }
    if (evt.isDummyEventForMessage){
      divElem.innerHTML = evt.message;
    } else {
      divElem.innerHTML = qx.html.String.fromText(this.formatLogEvent(evt));
    }
    this._logElem.appendChild(divElem);

    while (this._logElem.childNodes.length > this.getMaxMessages()) {
      this._logElem.removeChild(this._logElem.firstChild);

      if (this._removedMessageCount == null) {
        this._removedMessageCount = 1;
      } else {
        this._removedMessageCount++;
      }
    }

    if (this._removedMessageCount != null) {
      this._logElem.firstChild.innerHTML = "(" + this._removedMessageCount
        + " messages removed)";
    }

    // Scroll to bottom
    this._logWindow.scrollTo(0, this._logElem.offsetHeight);
  }
}

qx.Proto._modifyAutoCloseWithErrors = function(propValue, propOldValue, propData){
  if (!propValue && propOldValue){
    this._errorsPreventingAutoCloseCount = 0;

    //Show message in log so user can see which errors have been counted
    this._showMessageInLog("Log window message: Starting error recording, any errors below this line will prevent the log window from closing");

  } else if (propValue && !propOldValue){
    //Show message in log so user can see which errors have been counted
    this._showMessageInLog("Log window message: Stopping error recording, discarding " + this._errorsPreventingAutoCloseCount + " errors.");
  }
  return true;
}



// overridden
qx.Proto.dispose = function() {
  if (this.getDisposed()) {
    return true;
  }

  this._autoCloseWindow();

  return qx.log.Appender.prototype.dispose.call(this);
}


qx.Class._nextId = 1;
qx.Class._registeredAppenders = {};


/**
 * Registers a WindowAppender. This is used by the WindowAppender internally.
 * You don't have to call this.
 *
 * @param appender {WindowAppender} the WindowAppender to register.
 * @return {Integer} the ID.
 */
qx.Class.register = function(appender) {
  var WindowAppender = qx.log.WindowAppender;

  var id = WindowAppender._nextId++;
  WindowAppender._registeredAppenders[id] = appender;

  return id;
}


/**
 * Returns a prviously registered WindowAppender.
 *
 * @param id {Integer} the ID of the wanted WindowAppender.
 * @return {WindowAppender} the WindowAppender or null if no
 *     WindowAppender with this ID is registered.
 */
qx.Class.getAppender = function(id) {
  return qx.log.WindowAppender._registeredAppenders[id];
}
