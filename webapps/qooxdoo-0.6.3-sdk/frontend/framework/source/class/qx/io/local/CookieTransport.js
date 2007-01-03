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


************************************************************************ */

qx.OO.defineClass("qx.io.local.CookieTransport",
{
  BASENAME : "qx",
  ITEMSEPARATOR : "&",
  KEYVALUESEPARATOR : "=",
  MAXCOOKIES : 20,
  MAXSIZE : 4096
});





/*
---------------------------------------------------------------------------
  USER APPLICATION METHODS
---------------------------------------------------------------------------
*/

qx.Class.set = function(vName, vValue)
{
  if (!qx.util.Validation.isValid(vValue)) {
    return qx.io.local.CookieTransport.del(vName);
  }

  var vAll = qx.io.local.CookieTransport._getAll();
  vAll[vName] = vValue;
  this._setAll(vAll);
}

qx.Class.get = function(vName)
{
  var vAll = qx.io.local.CookieTransport._getAll();

  var vValue = qx.io.local.CookieTransport._getAll()[vName];
  if (qx.util.Validation.isValidString(vValue)) {
    return vValue;
  }

  return "";
}

qx.Class.del = function(vName)
{
  var vAll = qx.io.local.CookieTransport._getAll();
  delete vAll[vName];
  this._setAll(vAll);
}

qx.Class.setAll = function(vHash)
{
  var vAll = qx.io.local.CookieTransport._getAll();
  vAll = qx.lang.Object.mergeWith(vAll, vHash);
  qx.io.local.CookieTransport._setAll(vAll);
}

qx.Class.getAll = function() {
  return qx.io.local.CookieTransport._getAll();
}

qx.Class.replaceAll = function(vHash) {
  qx.io.local.CookieTransport._setAll(vHash);
}

qx.Class.delAll = function() {
  qx.io.local.CookieTransport.replaceAll({});
}





/*
---------------------------------------------------------------------------
  LOW LEVEL INTERNAL METHODS
---------------------------------------------------------------------------
*/

qx.Class._getAll = function()
{
  var vHash = {};
  var vCookie, vItems, vItem;

  for (var i=0; i<qx.io.local.CookieTransport.MAXCOOKIES; i++)
  {
    vCookie = qx.io.local.CookieApi.get(qx.io.local.CookieTransport.BASENAME + i);
    if (vCookie)
    {
      vItems = vCookie.split(qx.io.local.CookieTransport.ITEMSEPARATOR);
      for (var j=0, l=vItems.length; j<l; j++)
      {
        vItem = vItems[j].split(qx.io.local.CookieTransport.KEYVALUESEPARATOR);
        vHash[vItem[0]] = vItem[1];
      }
    }
  }

  return vHash;
}

qx.Class._setAll = function(vHash)
{
  var vString = "";
  var vTemp;
  var vIndex = 0;

  for (var vName in vHash)
  {
    vTemp = vName + qx.io.local.CookieTransport.KEYVALUESEPARATOR + vHash[vName];

    if (vTemp.length > qx.io.local.CookieTransport.MAXSIZE)
    {
      qx.dev.log.Logger.getClassLogger(qx.io.local.CookieTransport).debug("Could not store value of name '" + vName + "': Maximum size of " + qx.io.local.CookieTransport.MAXSIZE + "reached!");
      continue;
    }

    if ((qx.io.local.CookieTransport.ITEMSEPARATOR.length + vString.length + vTemp.length) > qx.io.local.CookieTransport.MAXSIZE)
    {
      qx.io.local.CookieTransport._setCookie(vIndex++, vString);

      if (vIndex == qx.io.local.CookieTransport.MAXCOOKIES)
      {
        qx.dev.log.Logger.getClassLogger(qx.io.local.CookieTransport).debug("Failed to store cookie. Max cookie amount reached!", "error");
        return false;
      }

      vString = vTemp;
    }
    else
    {
      if (vString != "") {
        vString += qx.io.local.CookieTransport.ITEMSEPARATOR;
      }

      vString += vTemp;
    }
  }

  if (vString != "") {
    qx.io.local.CookieTransport._setCookie(vIndex++, vString);
  }

  while (vIndex < qx.io.local.CookieTransport.MAXCOOKIES) {
    qx.io.local.CookieTransport._delCookie(vIndex++);
  }
}

qx.Class._setCookie = function(vIndex, vString)
{
  // qx.dev.log.Logger.getClassLogger(qx.io.local.CookieTransport).debug("Store: " + vIndex + " = " + vString);
  qx.io.local.CookieApi.set(qx.io.local.CookieTransport.BASENAME + vIndex, vString);
}

qx.Class._delCookie = function(vIndex)
{
  // qx.dev.log.Logger.getClassLogger(qx.io.local.CookieTransport).debug("Delete: " + vIndex);
  qx.io.local.CookieApi.del(qx.io.local.CookieTransport.BASENAME + vIndex);
}
