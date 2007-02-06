/* ************************************************************************

   qooxdoo - the new era of web development

   http://qooxdoo.org

   Copyright:
     2004-2007 1&1 Internet AG, Germany, http://www.1and1.org
     2006 STZ-IDA, Germany, http://www.stz-ida.de

   License:
     LGPL: http://www.gnu.org/licenses/lgpl.html
     EPL: http://www.eclipse.org/org/documents/epl-v10.php
     See the LICENSE file in the project's top-level directory for details.

   Authors:
     * Andreas Ecker (ecker)
     * Til Schneider (til132)

************************************************************************ */

/* ************************************************************************

#module(log)

************************************************************************ */

/**
 * An appender that writes each message to a native alert().
 * <p>
 * This class does not depend on qooxdoo widgets, so it also works when there
 * are problems with widgets or when the widgets are not yet initialized.
 * <p>
 * It allows to go through the log messages step-by-step, since the alert
 * window temporarily halts the regular program execution. That way even
 * the dispose process can easily be debugged.
 */
qx.OO.defineClass("qx.log.AlertAppender", qx.log.Appender,
function() {
  qx.log.Appender.call(this);
});


// overridden
qx.OO.changeProperty({ name:"useLongFormat", type:"boolean", defaultValue:false, allowNull:false });

// overridden
qx.Proto.appendLogEvent = function(evt) {

  // Append the message
  var text = evt.logger.getName();
  if (evt.instanceId != null) {
     text += " (" + evt.instanceId + ")";
  }

  alert("\n" + text + "\n" + this.formatLogEvent(evt));
}


// overridden
qx.Proto.dispose = function() {
  if (this.getDisposed()) {
      return true;
  }

  return qx.log.Appender.prototype.dispose.call(this);
}
