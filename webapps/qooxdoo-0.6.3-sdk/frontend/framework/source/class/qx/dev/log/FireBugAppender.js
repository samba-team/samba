/* ************************************************************************

   qooxdoo - the new era of web development

   http://qooxdoo.org

   Copyright:
     2006 by David Perez

   License:
     LGPL 2.1: http://www.gnu.org/licenses/lgpl.html

   Authors:
     * David Perez (david-perez)

************************************************************************ */

/* ************************************************************************

#module(core)
#module(log)

************************************************************************ */

/**
 * An appender that writes all messages to FireBug, a nice extension for debugging and developing under Firefox.
 * <p>
 * This class does not depend on qooxdoo widgets, so it also works when there
 * are problems with widgets or when the widgets are not yet initialized.
 * </p>
 */
qx.OO.defineClass('qx.dev.log.FireBugAppender', qx.dev.log.Appender, function() {
  qx.dev.log.Appender.call(this);
});

qx.Proto.appendLogEvent = function(evt)
{
  if (typeof console != 'undefined')
  {
    var log = qx.dev.log.Logger;
    var msg = this.formatLogEvent(evt);

    switch (evt.level)
    {
      case log.LEVEL_DEBUG:
        if (console.debug) {
          console.debug(msg);
        }
        break;
      case log.LEVEL_INFO:
        if (console.info) {
          console.info(msg);
        }
        break;
      case log.LEVEL_WARN:
        if (console.warn) {
          console.warn(msg);
        }
        break;
      default:
        if (console.error) {
          console.error(msg);
        }
        break;
    }
    // Force a stack dump, for helping locating the error
    if (evt.level > log.LEVEL_WARN && (!evt.throwable || !evt.throwable.stack) && console.trace)
    {
        console.trace();
    }
  }
}
