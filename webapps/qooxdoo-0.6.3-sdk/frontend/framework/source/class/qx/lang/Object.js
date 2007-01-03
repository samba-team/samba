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

#module(core)

************************************************************************ */

qx.OO.defineClass("qx.lang.Object");

/*!
  Function to check if a hash has any keys
*/
qx.Class.isEmpty = function(h)
{
  for (var s in h) {
    return false;
  }

  return true;
}

qx.Class.hasMinLength = function(h, j)
{
  var i=0;

  for (var s in h)
  {
    if ((++i)>=j) {
      return true;
    }
  }

  return false;
}

qx.Class.getLength = function(h)
{
  var i=0;

  for (var s in h) {
    i++;
  }

  return i;
}

qx.Class.getKeys = function(h)
{
  var r = [];
  for (var s in h) {
    r.push(s);
  }

  return r;
}

qx.Class.getKeysAsString = function(h) {
  return qx.lang.Object.getKeys(h).join(", ");
}

qx.Class.getValues = function(h)
{
  var r = [];
  for (var s in h) {
    r.push(h[s]);
  }

  return r;
}

qx.Class.mergeWith = function(vObjectA, vObjectB)
{
  for (var vKey in vObjectB) {
    vObjectA[vKey] = vObjectB[vKey];
  }

  return vObjectA;
}

qx.Class.carefullyMergeWith = function(vObjectA, vObjectB) {
  for (vKey in vObjectB)
  {
    if (typeof vObjectA[vKey] === "undefined") {
      vObjectA[vKey] = vObjectB[vKey];
    }
  }

  return vObjectA;
}

qx.Class.merge = function(vObjectA)
{
  var vLength = arguments.length;

  for (var i=1; i<vLength; i++) {
    qx.lang.Object.mergeWith(vObjectA, arguments[i]);
  }

  return vObjectA;
}

qx.Class.copy = function(vObject) {
  return qx.lang.Object.mergeWith({}, vObject);
}
