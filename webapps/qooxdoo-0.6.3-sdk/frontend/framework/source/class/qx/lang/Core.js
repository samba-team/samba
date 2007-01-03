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

qx.OO.defineClass("qx.lang.Core");


/*
---------------------------------------------------------------------------
  ADDITIONS FOR NATIVE ERROR OBJECT
---------------------------------------------------------------------------
*/

if (!Error.prototype.toString)
{
  Error.prototype.toString = function() {
    return this.message;
  }
}






/*
---------------------------------------------------------------------------
  ADDITIONS FOR NATIVE FUNCTION OBJECT
---------------------------------------------------------------------------
*/

/**
 * function apply for browsers that do not support it natively, e.g. IE 5.0
 * <p>
 * Based on code from youngpup.net licensed under
 * Creative Commons Attribution 2.0
 * </p>
 */
if (!Function.prototype.apply)
{
  Function.prototype.apply = function(oScope, args)
  {
    var sarg = [];
    var rtrn, call;

    if (!oScope) {
      oScope = window;
    }

    if (!args) {
      args = [];
    }

    for (var i = 0; i < args.length; i++) {
      sarg[i] = "args["+i+"]";
    }

    call = "oScope._applyTemp_(" + sarg.join(",") + ");";

    oScope._applyTemp_ = this;
    rtrn = eval(call);

    delete oScope._applyTemp_;

    return rtrn;
  }
}






/*
---------------------------------------------------------------------------
  ADDITIONS FOR NATIVE ARRAY OBJECT
---------------------------------------------------------------------------
*/

// Add all JavaScript 1.5 Features if they are missing
// Mozilla 1.8 has support for indexOf, lastIndexOf, forEach, filter, map, some, every

// Some of them from Erik Arvidsson <http://erik.eae.net/>
// More documentation could be found here:
// http://www.webreference.com/programming/javascript/ncz/column4/
// An alternative implementation can be found here:
// http://www.nczonline.net/archive/2005/7/231

// http://developer-test.mozilla.org/docs/Core_JavaScript_1.5_Reference:Objects:Array:lastIndexOf
if (!Array.prototype.indexOf)
{
  Array.prototype.indexOf = function(obj, fromIndex)
  {
    if (fromIndex == null)
    {
      fromIndex = 0;
    }
    else if (fromIndex < 0)
    {
      fromIndex = Math.max(0, this.length + fromIndex);
    }

    for (var i=fromIndex; i<this.length; i++) {
      if (this[i] === obj) {
        return i;
      }
    }

    return -1;
  }
}

// http://developer-test.mozilla.org/docs/Core_JavaScript_1.5_Reference:Objects:Array:lastIndexOf
if (!Array.prototype.lastIndexOf)
{
  Array.prototype.lastIndexOf = function(obj, fromIndex)
  {
    if (fromIndex == null)
    {
      fromIndex = this.length-1;
    }
    else if (fromIndex < 0)
    {
      fromIndex = Math.max(0, this.length + fromIndex);
    }

    for (var i=fromIndex; i>=0; i--) {
      if (this[i] === obj) {
        return i;
      }
    }

    return -1;
  }
}

// http://developer-test.mozilla.org/docs/Core_JavaScript_1.5_Reference:Objects:Array:forEach
if (!Array.prototype.forEach)
{
  Array.prototype.forEach = function(f, obj)
  {
    // 'l' must be fixed during loop... see docs
    for (var i=0, l=this.length; i<l; i++) {
      f.call(obj, this[i], i, this);
    }
  }
}

// http://developer-test.mozilla.org/docs/Core_JavaScript_1.5_Reference:Objects:Array:filter
if (!Array.prototype.filter)
{
  Array.prototype.filter = function(f, obj)
  {
    // must be fixed during loop... see docs
    var l = this.length;
    var res = [];

    for (var i=0; i<l; i++)
    {
      if (f.call(obj, this[i], i, this)) {
        res.push(this[i]);
      }
    }

    return res;
  }
}

// http://developer-test.mozilla.org/docs/Core_JavaScript_1.5_Reference:Objects:Array:map
if (!Array.prototype.map)
{
  Array.prototype.map = function(f, obj)
  {
    var l = this.length;  // must be fixed during loop... see docs
    var res = [];

    for (var i=0; i<l; i++) {
      res.push(f.call(obj, this[i], i, this));
    }

    return res;
  }
}

// http://developer-test.mozilla.org/docs/Core_JavaScript_1.5_Reference:Objects:Array:some
if (!Array.prototype.some)
{
  Array.prototype.some = function(f, obj)
  {
    var l = this.length;  // must be fixed during loop... see docs

    for (var i=0; i<l; i++)
    {
      if (f.call(obj, this[i], i, this)) {
        return true;
      }
    }

    return false;
  }
}

// http://developer-test.mozilla.org/docs/Core_JavaScript_1.5_Reference:Objects:Array:every
if (!Array.prototype.every)
{
  Array.prototype.every = function (f, obj)
  {
    var l = this.length;  // must be fixed during loop... see docs
    for (var i=0; i<l; i++)
    {
      if (!f.call(obj, this[i], i, this)) {
        return false;
      }
    }

    return true;
  }
}
