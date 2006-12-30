/* ************************************************************************

   qooxdoo - the new era of web development

   http://qooxdoo.org

   Copyright:
     2006 by STZ-IDA, Germany, http://www.stz-ida.de

   License:
     LGPL 2.1: http://www.gnu.org/licenses/lgpl.html

   Authors:
     * Carsten Lergenmueller (carstenl)

************************************************************************ */

/* ************************************************************************

#module(log)

************************************************************************ */

/**
 * An appender that writes all messages to a memory container. The messages
 * can be retrieved later, f. i. when an error dialog pops up and the question
 * arises what actions have caused the error.
 *
 */
qx.OO.defineClass("qx.dev.log.RingBufferAppender", qx.dev.log.Appender,
function() {
  qx.dev.log.Appender.call(this);

  this._history = [];
  this._nextIndexToStoreTo = 0;
  this._appenderToFormatStrings = null;
});


/**
 * The maximum number of messages to hold. If null the number of messages is not
 * limited. Warning: Changing this property will clear the events logged so far.
 */
qx.OO.addProperty({ name:"maxMessages", type:"number", defaultValue:50 });

qx.Proto._modifyMaxMessages = function(propValue, propOldValue, propData){
  this._history = [];
  this._nextIndexToStoreTo = 0;
};

// overridden
qx.Proto.appendLogEvent = function(evt) {
  var maxMessages = this.getMaxMessages();
  if (this._history.length < maxMessages){
    this._history.push(evt);
  } else {
    this._history[this._nextIndexToStoreTo++] = evt;
    if (this._nextIndexToStoreTo >= maxMessages){
      this._nextIndexToStoreTo = 0;
    }
  }
};

/**
 * Returns log events which have been logged previously.
 *
 * @param count {int} The number of events to retreive. If there are more events than the
 *                    given count, the oldest ones will not be returned.
 * @return {array} array of stored log events
 */
qx.Proto.retrieveLogEvents = function(count) {
  if (count > this._history.length){
    count = this._history.length;
  }

  var indexOfYoungestElementInHistory
    = this._history.length == this.getMaxMessages() ? this._nextIndexToStoreTo - 1
                                                    : this._history.length - 1;
  var startIndex = indexOfYoungestElementInHistory - count + 1;
  if (startIndex < 0){
    startIndex += this._history.length;
  }

  var result;
  if (startIndex <= indexOfYoungestElementInHistory){
    result = this._history.slice(startIndex, indexOfYoungestElementInHistory + 1);
  } else {
    result = this._history.slice(startIndex, this._history.length).concat(
                this._history.slice(0, indexOfYoungestElementInHistory + 1)
              );
  }
  return result;
};

/**
 * Returns a string holding the information of log events which have been logged previously.
 *
 * @param count {int} The number of events to retreive. If there are more events than the
 *                    given count, the oldest ones will not be returned.
 * @return {string} string
 */
qx.Proto.formatLogEvents = function(count) {
  if (this._appenderToFormatStrings == null){
    this._appenderToFormatStrings = new qx.dev.log.Appender();
  }

  var events = this.retrieveLogEvents(count);
  var string = "";
  for(var idx=0; idx < events.length; idx++) {
    string += this._appenderToFormatStrings.formatLogEvent(events[idx]) + "\n";
  }
  return string;
};

// overridden
qx.Proto.dispose = function() {
  if (this.getDisposed()) {
    return true;
  }

  return qx.dev.log.Appender.prototype.dispose.call(this);
};
