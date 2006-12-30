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
 * A filter for log events.
 */
qx.OO.defineClass("qx.dev.log.Filter", qx.core.Object,
function() {
  qx.core.Object.call(this);
});

/**
 * Decidies whether a log event is accepted.
 *
 * @param evt {Map} The event to check.
 * @return {int} {@link #ACCEPT}, {@link #DENY} or {@link #NEUTRAL}.
 */
qx.Proto.decide = function(evt) {
  throw new Error("decide is abstract");
}


/** {int} Specifies that the log event is accepted. */
qx.Class.ACCEPT = 1;

/** {int} Specifies that the log event is denied. */
qx.Class.DENY = 2;

/** {int} Specifies that the filter is neutral to the log event. */
qx.Class.NEUTRAL = 3;
