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

************************************************************************ */

/**
 * Processes log events. May be configured with filters in order to specify
 * which log events should be processed.
 */
qx.OO.defineClass("qx.log.LogEventProcessor", qx.core.Object,
function() {
  qx.core.Object.call(this);
});


/**
 * Appends a filter to the filter chain.
 *
 * @param filter {Filter} The filter to append.
 */
qx.Proto.addFilter = function(filter) {
  if (this._filterArr == null) {
    this._filterArr = []
  }
  this._filterArr.push(filter);
}


/**
 * Clears the filter chain.
 */
qx.Proto.clearFilters = function() {
  this._filterArr = null;
}


/**
 * Returns the head filter from the chain. Returns null if there are no filters.
 *
 * @return {Filter} the head filter from the chain.
 */
qx.Proto.getHeadFilter = function() {
  return (this._filterArr == null || this._filterArr.length == 0) ? null : this._filterArr[0];
}


/**
 * Returns the default filter from the chain. If the head filter is no default
 * filter, the chain will be cleared and a default filter will be created.
 *
 * @return {Filter} the default filter.
 */
qx.Proto._getDefaultFilter = function() {
  var headFilter = this.getHeadFilter();
  if (! (headFilter instanceof qx.log.DefaultFilter)) {
    // The head filter of the appender is no DefaultFilter
    // (or the appender has no filters at all)
    // -> Create a default handler and append it
    this.clearFilters();
    headFilter = new qx.log.DefaultFilter();
    this.addFilter(headFilter);
  }

  return headFilter;
}


/**
 * Sets whether event processing should be enabled.
 * <p>
 * Note: This will clear all custom filters.
 *
 * @param enabled {Boolean} whether event processing should be enabled.
 */
qx.Proto.setEnabled = function(enabled) {
  this._getDefaultFilter().setEnabled(enabled);
}


/**
 * Sets the min level an event must have in order to be processed.
 * <p>
 * Note: This will clear all custom filters.
 *
 * @param minLevel {Integer} the new min level.
 */
qx.Proto.setMinLevel = function(minLevel) {
  this._getDefaultFilter().setMinLevel(minLevel);
}


/**
 * Decides whether a log event is processed.
 *
 * @param evt {Map} the event to check.
 * @return {Integer} {@link Filter#ACCEPT}, {@link Filter#DENY} or
 *     {@link Filter#NEUTRAL}.
 */
qx.Proto.decideLogEvent = function(evt) {
  var NEUTRAL = qx.log.Filter.NEUTRAL;

  if (this._filterArr != null) {
    for (var i = 0; i < this._filterArr.length; i++) {
      var decision = this._filterArr[i].decide(evt);
      if (decision != NEUTRAL) {
        return decision;
      }
    }
  }

  // All filters are neutral, so are we
  return NEUTRAL;
}


/**
 * Processes a log event.
 *
 * @param evt {Map} The log event to process.
 */
qx.Proto.handleLogEvent = function(evt) {
  throw new Error("handleLogEvent is abstract");
}
