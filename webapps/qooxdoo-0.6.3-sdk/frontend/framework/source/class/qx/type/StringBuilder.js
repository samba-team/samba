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

#require(qx.sys.Client)

************************************************************************ */

/**
 * A string builder class
 * <p>
 * += operator is faster in Firefox and Opera.
 * Array push/join is faster in Internet Explorer
 * </p><p>
 * Even with this wrapper, which costs some time, this is
 * faster in Firefox than the alternative Array concat in
 * all browsers (which is in relation to IE's performance issues
 * only marginal). The IE performance loss caused by this
 * wrapper is not relevant.
 * </p><p>
 * So this class seems to be the best compromise to handle
 * string concatination.</p>
 */
qx.OO.defineClass("qx.type.StringBuilder", qx.core.Object,
function()
{
  qx.core.Object.call(this);

  this.init();
  this.add.apply(this, arguments);
});


/**
 * Resets the contents of the Stringbuilder
 * equivalent to <pre>str = ""; </pre>
 */
qx.Proto.clear = function() {}

/**
 * Returns the contents of the concatenated string
 *
 * @return (string) string content
 */
qx.Proto.get = function() {}

/**
 * Append a variable number of string arguments
 *
 * @param varargs (string) variable number os strings to be added
 */
qx.Proto.add = function(varargs) {}

/**
 * Initializes the contents of the Stringbuilder
 * equivalent to <pre>str = ""; </pre>
 */
qx.Proto.init = function() {}

/** Destructor */
qx.Proto.dispose = function() {}

/**
 * Returns the contents of the concatenated string
 *
 * @return (string) string content
 */
qx.Proto.toString = function() {}


if (qx.sys.Client.getInstance().isMshtml())
{
  qx.Proto.clear = function() {
    this._array = [];
  }

  qx.Proto.get = function() {
    return this._array.join("");
  }

  qx.Proto.add = function() {
    this._array.push.apply(this._array, arguments);
  }

  qx.Proto.init = function() {
    this._array = [];
  }

  qx.Proto.dispose = function()
  {
    if (this.getDisposed()) {
      return;
    }

    this._array = null;

    qx.core.Object.prototype.dispose.call(this);
  }
}
else
{
  qx.Proto.clear = function() {
    this._string = "";
  }

  qx.Proto.get = function() {
    return this._string;
  }

  qx.Proto.add = function() {
    this._string += Array.prototype.join.call(arguments, "");
  }

  qx.Proto.init = function() {
    this._string = "";
  }

  qx.Proto.dispose = function()
  {
    if (this.getDisposed()) {
      return;
    }

    this._string = null;

    qx.core.Object.prototype.dispose.call(this);
  }
}

qx.Proto.toString = qx.Proto.get;
