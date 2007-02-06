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

#module(core)

************************************************************************ */

/*!
  Event object for property changes.
*/
qx.OO.defineClass("qx.event.type.DataEvent", qx.event.type.Event,
function(vType, vData)
{
  qx.event.type.Event.call(this, vType);

  this.setData(vData);
});

qx.OO.addFastProperty({ name : "propagationStopped", defaultValue : false });
qx.OO.addFastProperty({ name : "data" });

qx.Proto.dispose = function()
{
  if(this.getDisposed()) {
    return;
  }

  this._valueData = null;

  return qx.event.type.Event.prototype.dispose.call(this);
}
