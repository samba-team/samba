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
#require(qx.dev.log.WindowAppender)

************************************************************************ */

/**
 * A logger. Logs messages of one log category.
 *
 * @param name {string} The category name of this logger. (Normally a class or
 *    package name)
 * @param parentLogger {Logger} The parent logger.
 */
qx.OO.defineClass("qx.dev.log.Logger", qx.dev.log.LogEventProcessor,
function(name, parentLogger) {
  qx.dev.log.LogEventProcessor.call(this);

  this._name = name;
  this._parentLogger = parentLogger;
});


/**
 * Returns the name of this logger. (Normally a class or package name)
 *
 * @return {string} the name.
 */
qx.Proto.getName = function() {
  return this._name;
}


/**
 * Returns the parent logger.
 *
 * @return {Logger} the parent logger.
 */
qx.Proto.getParentLogger = function() {
  return this._parentLogger;
}


/**
 * Indents all following log messages by one.
 * <p>
 * This affects all log messages. Even those of other loggers.
 */
qx.Proto.indent = function() {
  qx.dev.log.Logger._indent++;
}


/**
 * Unindents all following log messages by one.
 * <p>
 * This affects all log messages. Even those of other loggers.
 */
qx.Proto.unindent = function() {
  qx.dev.log.Logger._indent--;
}


/**
 * Adds an appender.
 * <p>
 * If a logger has an appender, log events will not be passed to the
 * appenders of parent loggers. If you want this behaviour, also append a
 * {@link ForwardAppender}.
 *
 * @param appender {Appender} the appender to add.
 */
qx.Proto.addAppender = function(appender) {
  if (this._appenderArr == null) {
    this._appenderArr = [];
  }

  this._appenderArr.push(appender);
}


/**
 * Removes an appender.
 *
 * @param appender {Appender} the appender to remove.
 */
qx.Proto.removeAppender = function(appender) {
  if (this._appenderArr != null) {
    this._appenderArr.remove(appender);
  }
}


/**
 * Removes all appenders.
 */
qx.Proto.removeAllAppenders = function() {
  this._appenderArr = null;
}


// overridden
qx.Proto.handleLogEvent = function(evt) {
  var Filter = qx.dev.log.Filter;

  var decision = Filter.NEUTRAL;
  var logger = this;
  while (decision == Filter.NEUTRAL && logger != null) {
    decision = logger.decideLogEvent(evt);
    logger = logger.getParentLogger();
  }

  if (decision != Filter.DENY) {
    this.appendLogEvent(evt);
  }
}


/**
 * Passes a log event to the appenders. If the logger has no appenders the
 * event will be passed to the appenders of the parent logger, and so on.
 *
 * @param evt {Map} The event to append.
 */
qx.Proto.appendLogEvent = function(evt) {
  if (this._appenderArr != null && this._appenderArr.length != 0) {
    for (var i = 0; i < this._appenderArr.length; i++) {
      this._appenderArr[i].handleLogEvent(evt);
    }
  } else if (this._parentLogger != null) {
    this._parentLogger.appendLogEvent(evt);
  }
}


/**
 * Logs a message.
 *
 * @param level {int} the log level.
 * @param msg {var} the message to log. If this is not a string, the
 *    object dump will be logged.
 * @param instanceId {var ? null} the ID of the instance the log message comes from.
 * @param exc {var ? null} the exception to log.
 */
qx.Proto.log = function(level, msg, instanceId, exc) {
  var evt = { logger:this, level:level, message:msg, throwable:exc,
              indent:qx.dev.log.Logger._indent, instanceId:instanceId }
  this.handleLogEvent(evt);
}


/**
 * Logs a debug message.
 *
 * @param msg {var} the message to log. If this is not a string, the
 *    object dump will be logged.
 * @param instanceId {var ? null} the ID of the instance the log message comes from.
 * @param exc {var ? null} the exception to log.
 */
qx.Proto.debug = function(msg, instanceId, exc) {
  this.log(qx.dev.log.Logger.LEVEL_DEBUG, msg, instanceId, exc);
}


/**
 * Logs an info message.
 *
 * @param msg {var} the message to log. If this is not a string, the
 *    object dump will be logged.
 * @param instanceId {var ? null} the ID of the instance the log message comes from.
 * @param exc {var ? null} the exception to log.
 */
qx.Proto.info = function(msg, instanceId, exc) {
  this.log(qx.dev.log.Logger.LEVEL_INFO, msg, instanceId, exc);
}


/**
 * Logs a warning message.
 *
 * @param msg {var} the message to log. If this is not a string, the
 *    object dump will be logged.
 * @param instanceId {var ? null} the ID of the instance the log message comes from.
 * @param exc {var ? null} the exception to log.
 */
qx.Proto.warn = function(msg, instanceId, exc) {
  this.log(qx.dev.log.Logger.LEVEL_WARN, msg, instanceId, exc);
}


/**
 * Logs an error message.
 *
 * @param msg {var} the message to log. If this is not a string, the
 *    object dump will be logged.
 * @param instanceId {var ? null} the ID of the instance the log message comes from.
 * @param exc {var ? null} the exception to log.
 */
qx.Proto.error = function(msg, instanceId, exc) {
  this.log(qx.dev.log.Logger.LEVEL_ERROR, msg, instanceId, exc);
}


/**
 * Logs a fatal message.
 *
 * @param msg {var} the message to log. If this is not a string, its
 *    object dump will be logged.
 * @param instanceId {var ? null} the ID of the instance the log message comes from.
 * @param exc {var ? null} the exception to log.
 */
qx.Proto.fatal = function(msg, instanceId, exc) {
  this.log(qx.dev.log.Logger.LEVEL_FATAL, msg, instanceId, exc);
}


/**
 * Resets the measure timer.
 *
 * @see #measure{}
 */
qx.Proto.measureReset = function() {
  if (this._totalMeasureTime != null) {
    this.debug("Measure reset. Total measure time: " + this._totalMeasureTime + " ms");
  }

  this._lastMeasureTime = null;
  this._totalMeasureTime = null;
}


/**
 * Logs a debug message and measures the time since the last call of measure.
 *
 * @param msg {string} the message to log.
 * @param instanceId {var ? null} the ID of the instance the log message comes from.
 * @param exc {var ? null} the exception to log.
 */
qx.Proto.measure = function(msg, instanceId, exc) {
  if (this._lastMeasureTime == null) {
    msg = "(measure start) " + msg;
  } else {
    var delta = new Date().getTime() - this._lastMeasureTime;

    if (this._totalMeasureTime == null) {
      this._totalMeasureTime = 0;
    }

    this._totalMeasureTime += delta;
    msg = "(passed time: " + delta + " ms) " + msg;
  }

  this.debug(msg, instanceId, exc);

  this._lastMeasureTime = new Date().getTime();
}


/**
 * Logs the current stack trace as a debug message.
 */
qx.Proto.printStackTrace = function() {
  try {
    forced_exception.go;
  } catch (exc) {
    this.debug("Current stack trace", "", exc);
  }
}


/**
 * Returns the logger of a class.
 *
 * @param clazz {Function} The class of which to return the logger.
 */
qx.Class.getClassLogger = function(clazz) {
  var logger = clazz._logger;
  if (logger == null) {
    // Get the parent logger
    var classname = clazz.classname;
    var splits = classname.split(".");
    var currPackage = window;
    var currPackageName = "";
    var parentLogger = qx.dev.log.Logger.ROOT_LOGGER;
    for (var i = 0; i < splits.length - 1; i++) {
      currPackage = currPackage[splits[i]];
      currPackageName += ((i != 0) ? "." : "") + splits[i];

      if (currPackage._logger == null) {
        // This package has no logger -> Create one
        currPackage._logger = new qx.dev.log.Logger(currPackageName, parentLogger);
      }
      parentLogger = currPackage._logger;
    }

    // Create the class logger
    logger = new qx.dev.log.Logger(classname, parentLogger);
    clazz._logger = logger;
  }
  return logger;
}


/** {int} The current indent. */
qx.Class._indent = 0;

/**
 * (int) The ALL level has the lowest possible rank and is intended to turn on
 * all logging.
 */
qx.Class.LEVEL_ALL = 0;

/**
 * (int) The DEBUG Level designates fine-grained informational events that are
 * most useful to debug an application.
 */
qx.Class.LEVEL_DEBUG = 200;

/**
 * (int) The INFO level designates informational messages that highlight the
 * progress of the application at coarse-grained level.
 */
qx.Class.LEVEL_INFO = 500;

/** {int} The WARN level designates potentially harmful situations. */
qx.Class.LEVEL_WARN = 600;

/**
 * (int) The ERROR level designates error events that might still allow the
 * application to continue running.
 */
qx.Class.LEVEL_ERROR = 700;

/**
 * (int) The FATAL level designates very severe error events that will
 * presumably lead the application to abort.
 */
qx.Class.LEVEL_FATAL = 800;

/**
 * (int) The OFF has the highest possible rank and is intended to turn off
 * logging.
 */
qx.Class.LEVEL_OFF = 1000;


/**
 * {Logger} The root logger. This is the root of the logger tree. All loggers
 * should be a child or grand child of this root logger.
 * <p>
 * This logger logs by default everything greater than level INFO to a log
 * window.
 */
qx.Class.ROOT_LOGGER = new qx.dev.log.Logger("root", null);
qx.Class.ROOT_LOGGER.setMinLevel(qx.dev.log.Logger.LEVEL_DEBUG);
qx.Class.ROOT_LOGGER.addAppender(new qx.dev.log.WindowAppender);
