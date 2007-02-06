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

qx.OO.defineClass("qx.io.local.CookieApi",
{
  STR_EXPIRES : "expires",
  STR_PATH : "path",
  STR_DOMAIN : "domain",
  STR_SECURE : "secure",
  STR_DELDATA : "Thu, 01-Jan-1970 00:00:01 GMT"
});





/*
---------------------------------------------------------------------------
  USER APPLICATION METHODS
---------------------------------------------------------------------------
*/

qx.Class.get = function(vName)
{
  var start = document.cookie.indexOf(vName + "=");
  var len = start + vName.length + 1;

  if ((!start) && (vName != document.cookie.substring(0, vName.length))) {
    return null;
  }

  if (start == -1) {
    return null;
  }

  var end = document.cookie.indexOf(";", len);

  if (end == -1) {
    end = document.cookie.length;
  }

  return unescape(document.cookie.substring(len, end));
}

qx.Class.set = function(vName, vValue, vExpires, vPath, vDomain, vSecure)
{
  var today = new Date();
  today.setTime(today.getTime());

  // Generate cookie
  var vCookie = [ vName, "=", escape(vValue) ];

  if (vExpires)
  {
    vCookie.push(";");
    vCookie.push(qx.io.local.CookieApi.STR_EXPIRES);
    vCookie.push("=");
    vCookie.push(new Date(today.getTime() + (vExpires * 1000 * 60 * 60 * 24)).toGMTString());
  }

  if (vPath)
  {
    vCookie.push(";");
    vCookie.push(qx.io.local.CookieApi.STR_PATH);
    vCookie.push("=");
    vCookie.push(vPath);
  }

  if (vDomain)
  {
    vCookie.push(";");
    vCookie.push(qx.io.local.CookieApi.STR_DOMAIN);
    vCookie.push("=");
    vCookie.push(vDomain);
  }

  if (vSecure)
  {
    vCookie.push(";");
    vCookie.push(qx.io.local.CookieApi.STR_SECURE);
  }

  // Store cookie
  document.cookie = vCookie.join("");
}

qx.Class.del = function(vName, vPath, vDomain)
{
  if (!qx.io.local.CookieApi.get(vName)) {
    return;
  }

  // Generate cookie
  var vCookie = [ vName, "=" ];

  if (vPath)
  {
    vCookie.push(";");
    vCookie.push(qx.io.local.CookieApi.STR_PATH);
    vCookie.push("=");
    vCookie.push(vPath);
  }

  if (vDomain)
  {
    vCookie.push(";");
    vCookie.push(qx.io.local.CookieApi.STR_DOMAIN);
    vCookie.push("=");
    vCookie.push(vDomain);
  }

  vCookie.push(";");
  vCookie.push(qx.io.local.CookieApi.STR_EXPIRES);
  vCookie.push("=");
  vCookie.push(qx.io.local.CookieApi.STR_DELDATA);

  // Store cookie
  document.cookie = vCookie.join("");
}
