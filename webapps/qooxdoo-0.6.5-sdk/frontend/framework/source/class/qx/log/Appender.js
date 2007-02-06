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
 * An appender. Does the actual logging.
 */
qx.OO.defineClass("qx.log.Appender", qx.log.LogEventProcessor,
function() {
  qx.log.LogEventProcessor.call(this);
});


/** Whether the logger name and log level should be included in the formatted log message. */
qx.OO.addProperty({ name:"useLongFormat", type:"boolean", defaultValue:true, allowNull:false });


// overridden
qx.Proto.handleLogEvent = function(evt) {
  if (this.decideLogEvent(evt) != qx.log.Filter.DENY) {
    this.appendLogEvent(evt);
  }
}


/**
 * Appends a log event to the log.
 *
 * @param evt {Map} The event to append.
 */
qx.Proto.appendLogEvent = function(evt) {
  throw new Error("appendLogEvent is abstract");
}


/**
 * Formats a log event.
 *
 * @param evt {Map} The log event to format.
 * @return {String} The formatted event.
 */
qx.Proto.formatLogEvent = function(evt) {
  var Logger = qx.log.Logger;

  var text = "";

  // Append the time stamp
  var time = new String(new Date().getTime() - qx._LOADSTART);
  while (time.length < 6) {
    time = "0" + time;
  }
  text += time;

  // Append the level
  if (this.getUseLongFormat()) {
    switch (evt.level) {
      case Logger.LEVEL_DEBUG: text += " DEBUG: "; break;
      case Logger.LEVEL_INFO:  text += " INFO:  "; break;
      case Logger.LEVEL_WARN:  text += " WARN:  "; break;
      case Logger.LEVEL_ERROR: text += " ERROR: "; break;
      case Logger.LEVEL_FATAL: text += " FATAL: "; break;
    }
  } else {
    text += ": ";
  }

  // Append the indent
  var indent = "";
  for (var i = 0; i < evt.indent; i++) {
    indent += "  ";
  }
  text += indent;

  // Append the logger name and instance
  if (this.getUseLongFormat()) {
    text += evt.logger.getName();
    if (evt.instanceId != null) {
      text += "[" + evt.instanceId + "]";
    }
    text += ": ";
  }

  // Append the message
  if (typeof evt.message == "string") {
    text += evt.message;
  } else {
    // The message is an object -> Log a dump of the object
    var obj = evt.message;
    if (obj == null) {
      text += "Object is null";
    } else {
      text += "--- Object: " + obj + " ---\n";
      var attrArr = new Array();
      try {
        for (var attr in obj) {
          attrArr.push(attr);
        }
      } catch (exc) {
        text += indent + "  [not readable: " + exc + "]\n";
      }
      attrArr.sort();
      for (var i = 0; i < attrArr.length; i++) {
        try {
          text += indent + "  " + attrArr[i] + "=" + obj[attrArr[i]] + "\n";
        }
        catch (exc) {
          text += indent + "  " + attrArr[i] + "=[not readable: " + exc + "]\n";
        }
      }
      text += indent + "--- End of object ---";
    }
  }

  // Append the throwable
  if (evt.throwable != null) {
    var thr = evt.throwable;

    if (thr.name == null) {
      text += ": " + thr;
    } else {
      text += ": " + thr.name;
    }
    if (thr.message != null) {
      text += " - " + thr.message;
    }
    if (thr.number != null) {
      text += " (#" + thr.number + ")";
    }

    if (thr.stack != null) {
      text += "\n" + this._beautyStackTrace(thr.stack);
    }
  }

  return text;
}


/**
 * Beautifies a stack trace.
 *
 * @param stack {String} the stack trace to beautify.
 * @return {String} the beautified stack trace.
 */
qx.Proto._beautyStackTrace = function(stack) {
  // e.g. "()@http://localhost:8080/webcomponent-test-SNAPSHOT/webcomponent/js/com/ptvag/webcomponent/common/log/Logger:253"
  var lineRe = /@(.+):(\d+)$/gm;
  var hit;
  var out = "";
  var scriptDir = "/script/";
  while ((hit = lineRe.exec(stack)) != null) {
    var url = hit[1];

    var jsPos = url.indexOf(scriptDir);
    var className = (jsPos == -1) ? url : url.substring(jsPos + scriptDir.length).replace(/\//g, ".");

    var lineNumber = hit[2];
    out += "  at " + className + ":" + lineNumber + "\n";
  }
  return out;
}
