/* ************************************************************************

   qooxdoo - the new era of web development

   http://qooxdoo.org

   Copyright:
     2006 by STZ-IDA, Germany, http://www.stz-ida.de

   License:
     LGPL 2.1: http://www.gnu.org/licenses/lgpl.html

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
 * @param name {string ? "qx_log"} the name of the log window.
 */
qx.OO.defineClass("qx.dev.log.WindowAppender", qx.dev.log.Appender,
function(name) {
  qx.dev.log.Appender.call(this);

  this._id = qx.dev.log.WindowAppender.register(this);
  this._name = (name == null) ? "qx_log" : name;

  this._logWindowOpened = false;
});


/**
 * The maximum number of messages to show. If null the number of messages is not
 * limited.
 */
qx.OO.addProperty({ name:"maxMessages", type:"number", defaultValue:500 });

/** Whether the window should appear under the main window. */
qx.OO.addProperty({ name:"popUnder", type:"boolean", defaultValue:false, allowNull:false });


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
    + '<body onload="qx = opener.qx;" onunload="try{qx.dev.log.WindowAppender._registeredAppenders[' + this._id + '].closeWindow()}catch(e){}">'
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
}


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
}


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
    if (evt.level == qx.dev.log.Logger.LEVEL_ERROR) {
      divElem.style.backgroundColor = "#FFEEEE";
    } else if (evt.level == qx.dev.log.Logger.LEVEL_DEBUG) {
      divElem.style.color = "gray";
    }
    divElem.innerHTML = this.formatLogEvent(evt).replace(/&/g, "&amp;")
      .replace(/</g, "&lt;").replace(/  /g, " &#160;").replace(/[\n]/g, "<br>");
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


// overridden
qx.Proto.dispose = function() {
  if (this.getDisposed()) {
    return true;
  }

  this.closeWindow();

  return qx.dev.log.Appender.prototype.dispose.call(this);
}


qx.Class._nextId = 1;
qx.Class._registeredAppenders = {};


/**
 * Registers a WindowAppender. This is used by the WindowAppender internally.
 * You don't have to call this.
 *
 * @param appender {WindowAppender} the WindowAppender to register.
 * @return {int} the ID.
 */
qx.Class.register = function(appender) {
  var WindowAppender = qx.dev.log.WindowAppender;

  var id = WindowAppender._nextId++;
  WindowAppender._registeredAppenders[id] = appender;

  return id;
}


/**
 * Returns a prviously registered WindowAppender.
 *
 * @param id {int} the ID of the wanted WindowAppender.
 * @return {WindowAppender} the WindowAppender or null if no
 *     WindowAppender with this ID is registered.
 */
qx.Class.getAppender = function(id) {
  return qx.dev.log.WindowAppender._registeredAppenders[id];
}
