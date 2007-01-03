/* ************************************************************************

   qooxdoo - the new era of web development

   http://qooxdoo.org

   Copyright:
     2004-2006 by 1&1 Internet AG, Germany, http://www.1and1.org

   License:
     LGPL 2.1: http://www.gnu.org/licenses/lgpl.html

   Authors:
     * Sebastian Werner (wpbasti)
     * Andreas Ecker (ecker)

************************************************************************ */

/* ************************************************************************

#module(io_remote)

************************************************************************ */

qx.OO.defineClass("qx.io.remote.Response", qx.core.Target,
function() {
  qx.core.Target.call(this);
});




/*
---------------------------------------------------------------------------
  PROPERTIES
---------------------------------------------------------------------------
*/

qx.OO.addProperty({ name : "state", type : "number" });
/*!
  Status code of the response.
*/
qx.OO.addProperty({ name : "statusCode", type : "number" });
qx.OO.addProperty({ name : "content" });
qx.OO.addProperty({ name : "responseHeaders", type : "object" });







/*
---------------------------------------------------------------------------
  MODIFIERS
---------------------------------------------------------------------------
*/

/*
qx.Proto._modifyResponseHeaders = function(propValue, propOldValue, propData)
{
  for (vKey in propValue) {
    this.debug("R-Header: " + vKey + "=" + propValue[vKey]);
  }

  return true;
}
*/







/*
---------------------------------------------------------------------------
  USER METHODS
---------------------------------------------------------------------------
*/

qx.Proto.getResponseHeader = function(vHeader)
{
  var vAll = this.getResponseHeaders();
  if (vAll) {
    return vAll[vHeader] || null;
  }

  return null;
}






/*
---------------------------------------------------------------------------
  DISPOSER
---------------------------------------------------------------------------
*/

qx.Proto.dispose = function()
{
  if (this.getDisposed()) {
    return;
  }

  return qx.core.Target.prototype.dispose.call(this);
}
