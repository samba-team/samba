/* ************************************************************************

   qooxdoo - the new era of web development

   http://qooxdoo.org

   Copyright:
     2004-2007 1&1 Internet AG, Germany, http://www.1and1.org

   License:
     LGPL: http://www.gnu.org/licenses/lgpl.html
     EPL: http://www.eclipse.org/org/documents/epl-v10.php
     See the LICENSE file in the project's top-level directory for details.

   Authors:
     * Sebastian Werner (wpbasti)
     * Andreas Ecker (ecker)

************************************************************************ */

/* ************************************************************************


************************************************************************ */

/**
 * This manager is used by all objects which needs ranges like qx.ui.form.Spinner, ...
 *
 * @event change {qx.event.type.Event}
 */
qx.OO.defineClass("qx.type.Range", qx.core.Target,
function() {
  qx.core.Target.call(this);
});

/** current value of the Range object */
qx.OO.addProperty({ name : "value", type : "number", defaultValue : 0 });

/** minimal value of the Range object */
qx.OO.addProperty({ name : "min", type : "number", defaultValue : 0 });

/** maximal value of the Range object */
qx.OO.addProperty({ name : "max", type : "number", defaultValue : 100 });

/** Step size for increments/decrements of the value property */
qx.OO.addProperty({ name : "step", type : "number", defaultValue : 1 });

qx.Proto._checkValue = function(propValue) {
  return Math.max(this.getMin(), Math.min(this.getMax(), Math.floor(propValue)));
}

qx.Proto._modifyValue = function(propValue, propOldValue, propData)
{
  if (this.hasEventListeners("change")) {
    this.dispatchEvent(new qx.event.type.Event("change"), true);
  }

  return true;
}

qx.Proto._checkMax = function(propValue) {
  return Math.floor(propValue);
}

qx.Proto._modifyMax = function(propValue, propOldValue, propData)
{
  this.setValue(Math.min(this.getValue(), propValue));

  if (this.hasEventListeners("change")) {
    this.dispatchEvent(new qx.event.type.Event("change"), true);
  }

  return true;
}

qx.Proto._checkMin = function(propValue) {
  return Math.floor(propValue);
}

qx.Proto._modifyMin = function(propValue, propOldValue, propData)
{
  this.setValue(Math.max(this.getValue(), propValue));

  if (this.hasEventListeners("change")) {
    this.dispatchEvent(new qx.event.type.Event("change"), true);
  }

  return true;
}
