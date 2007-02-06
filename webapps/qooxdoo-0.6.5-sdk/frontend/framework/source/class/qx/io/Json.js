/* ************************************************************************

   qooxdoo - the new era of web development

   http://qooxdoo.org

   Copyright:
     2004-2007 1&1 Internet AG, Germany, http://www.1and1.org
     2006 STZ-IDA, Germany, http://www.stz-ida.de
     2006 Derrell Lipman

   License:
     LGPL: http://www.gnu.org/licenses/lgpl.html
     EPL: http://www.eclipse.org/org/documents/epl-v10.php
     See the LICENSE file in the project's top-level directory for details.

   Authors:
     * Sebastian Werner (wpbasti)
     * Andreas Ecker (ecker)
     * Andreas Junghans (lucidcake)
     * Derrell Lipman (derrell)

************************************************************************ */

/* ************************************************************************

#module(io_remote)

************************************************************************ */


/*
Copyright (c) 2005 JSON.org

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The Software shall be used for Good, not Evil.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/


/**
 * This is a slightly modified JSON implementation that supports Dates and
 * treats undefined like null.
 */

qx.OO.defineClass("qx.io.Json");

/**
 * Stringify a JavaScript value, producing a JSON text.
 *
 * @param v {var} the object to serialize.
 * @param beautify {Boolean ? false} whether to beautify the serialized string
 *        by adding some white space that indents objects and arrays.
 * @return {String} the serialized object.
 */
qx.Class.stringify = function (v, beautify) {};

/**
 * Parse a JSON text, producing a JavaScript value.
 * It returns false if there is a syntax error.
 *
 * @param text {String} JSON string
 * @return {var} evaluated JSON string.
 */
qx.Class.parse = function (text) {};

/*
---------------------------------------------------------------------------
  DEFAULT SETTINGS
---------------------------------------------------------------------------
*/

qx.Settings.setDefault("encodeUndefined", true);
qx.Settings.setDefault("enableDebug", false);





/*
---------------------------------------------------------------------------
  IMPLEMENTATION
---------------------------------------------------------------------------
*/

qx.io.Json = function ()
{
  var m = {
      '\b': '\\b',
      '\t': '\\t',
      '\n': '\\n',
      '\f': '\\f',
      '\r': '\\r',
      '"' : '\\"',
      '\\': '\\\\'
    },
    s = {
      'boolean': function (x) {
        return String(x);
      },

      number: function (x) {
        return isFinite(x) ? String(x) : 'null';
      },

      string: function (x) {
        if (/["\\\x00-\x1f]/.test(x)) {
          x = x.replace(/([\x00-\x1f\\"])/g, function(a, b) {
            var c = m[b];
            if (c) {
              return c;
            }
            c = b.charCodeAt();
            return '\\u00' +
              Math.floor(c / 16).toString(16) +
              (c % 16).toString(16);
          });
        }
        return '"' + x + '"';
      },

      object: function (x) {
        if (x) {
          var a = [], b, f, i, l, v;
          if (x instanceof Array) {
            var beautify = qx.io.Json._beautify;
            a[0] = '[';
            if (beautify) {
              qx.io.Json._indent += qx.io.Json.BEAUTIFYING_INDENT;
              a.push(qx.io.Json._indent);
            }
            l = x.length;
            for (i = 0; i < l; i += 1) {
              v = x[i];
              f = s[typeof v];
              if (f) {
                v = f(v);
                if (typeof v == 'string') {
                  if (b) {
                    a[a.length] = ',';
                    if (beautify) {
                      a.push(qx.io.Json._indent);
                    }
                  }
                  a[a.length] = v;
                  b = true;
                }
              }
            }
            if (beautify) {
              qx.io.Json._indent = qx.io.Json._indent.substring(0, qx.io.Json._indent.length - qx.io.Json.BEAUTIFYING_INDENT.length);
              a.push(qx.io.Json._indent);
            }
            a[a.length] = ']';
          // AJ, DJL --
          } else if (x instanceof Date) {
            /*
             * The Date object is a primitive type in Javascript,
             * but the Javascript specification neglects to provide
             * a literal form for it.  The only way to generate a
             * Date object is with "new Date()".  For fast
             * processing by Javascript, we want to be able to
             * eval() a JSON response.  If Date objects are to be
             * passed to the client using JSON, about the only
             * reasonable way to do it is to have "new Date()"
             * in the JSON message.  See this page for a proposal to
             * add a Date literal syntax to Javascript which,
             * if/when implemented in Javascript, would eliminate
             * the need to pass "new Date() in JSON":
             *
             *   http://www.hikhilk.net/DateSyntaxForJSON.aspx
             *
             * Sending a JSON message from client to server, we have
             * no idea what language the server will be written in,
             * what size integers it supports, etc.  We do want to
             * be able to represent as large a range of dates as
             * possible, though.  If we were to send the number of
             * milliseconds since the beginning of the epoch, the
             * value would exceed, in many cases, what can fit in a
             * 32-bit integer.  Even if one were to simply strip off
             * the last three digits (milliseconds), the number of
             * seconds could exceed a 32-bit signed integer's range
             * with very distant past or distant future dates.  To
             * make it easier for any generic server to handle a
             * date without risk of loss of precision due to
             * automatic type casting, we'll send a UTC date with
             * separated fields, in the form:
             *
             *  new Date(Date.UTC(year,month,day,hour,min,sec,ms))
             *
             * The server can fairly easily parse this in its JSON
             * implementation by stripping off "new Date(Date.UTC("
             * from the beginning of the string, and "))" from the
             * end of the string.  What remains is the set of
             * comma-separated date components, which are also very
             * easy to parse.
             *
             * The server should send this same format to the
             * client, which can simply eval() it just as with the
             * remainder of JSON.
             *
             * A requirement of the implementation of the server is
             * that after a date has been sent from the client to
             * the server, converted by the server into whatever
             * native type the date will be stored or manipulated
             * in, convered back to JSON, and received back at the
             * client, a comparison of the sent and received Date
             * object should yield identity.  This means that even
             * if the server does not natively operate on
             * milliseconds, it must maintain milliseconds in dates
             * sent to it by the client.
             */
            var dateParams =
            x.getUTCFullYear() + "," +
            x.getUTCMonth() + "," +
            x.getUTCDate() + "," +
            x.getUTCHours() + "," +
            x.getUTCMinutes() + "," +
            x.getUTCSeconds() + "," +
            x.getUTCMilliseconds();
            return "new Date(Date.UTC(" + dateParams + "))";
          // -- AJ, DJL
          } else if (x instanceof Object) {
            var beautify = qx.io.Json._beautify;
            a[0] = '{';
            if (beautify) {
              qx.io.Json._indent += qx.io.Json.BEAUTIFYING_INDENT;
              a.push(qx.io.Json._indent);
            }
            for (i in x) {
              v = x[i];
              f = s[typeof v];
              if (f) {
                v = f(v);
                if (typeof v == 'string') {
                  if (b) {
                    a[a.length] = ',';
                    if (beautify) {
                      a.push(qx.io.Json._indent);
                    }
                  }
                  a.push(s.string(i), ':', v);
                  b = true;
                }
              }
            }
            if (beautify) {
              qx.io.Json._indent = qx.io.Json._indent.substring(0, qx.io.Json._indent.length - qx.io.Json.BEAUTIFYING_INDENT.length);
              a.push(qx.io.Json._indent);
            }
            a[a.length] = '}';
          } else {
            return;
          }
          return a.join('');
        }
        return 'null';
      },

      // AJ, DJL --
      undefined: function(x) {
        if (qx.Settings.getValueOfClass("qx.io.Json", "encodeUndefined"))
          return 'null';
      }
      // -- AJ, DJL
    }

  return {
    copyright: '(c)2005 JSON.org',
    license: 'http://www.JSON.org/license.html',

    /**
     * Stringify a JavaScript value, producing a JSON text.
     *
     * @param v {var} the object to serialize.
     * @param beautify {Boolean ? false} whether to beautify the serialized string
     *        by adding some white space that indents objects and arrays.
     * @return {String} the serialized object.
     */
    stringify: function (v, beautify) {
      this._beautify = beautify;
      this._indent = this.BEAUTIFYING_LINE_END;

      var f = s[typeof v];
      // AJ, DJL --
      var ret = null;
      // -- AJ, DJL
      if (f) {
        v = f(v);
        if (typeof v == 'string') {
          // DJL --
          ret = v;
          // -- DJL
        }
      }

      // DJL --
      if (qx.Settings.getValueOfClass("qx.io.Json", "enableDebug")) {
        var logger = qx.log.Logger.getClassLogger(qx.core.Object);
        logger.debug("JSON request: " + ret);
      }

      return ret;
      // -- DJL
    },
/*
  Parse a JSON text, producing a JavaScript value.
  It returns false if there is a syntax error.
*/
    parse: function (text) {
      try {
        return !(/[^,:{}\[\]0-9.\-+Eaeflnr-u \n\r\t]/.test(
            text.replace(/"(\\.|[^"\\])*"/g, ''))) &&
          eval('(' + text + ')');
      } catch (e) {
        return false;
      }
    }
  }
}();


///*
// * Recursively descend through an object looking for any class hints.  Right
// * now, the only class hint we support is 'Date' which can not be easily sent
// * from javascript to an arbitrary (e.g. PHP) JSON-RPC server and back again
// * without truncation or modification.
// */
//qx.io.Json._fixObj = function(obj) {
//  /* If there's a class hint... */
//  if (obj.__jsonclass__)
//  {
//  /* ... then check for supported classes.  We support only Date. */
//  if (obj.__jsonclass__ == "Date" && obj.secSinceEpoch && obj.msAdditional)
//  {
//    /* Found a Date.  Replace class hint object with a Date object. */
//    obj = new Date((obj.secSinceEpoch * 1000) + obj.msAdditional);
//    return obj;
//  }
//  }
//
//  /*
//   * It wasn't something with a supported class hint, so recursively descend
//   */
//  for (var member in obj) {
//  thisObj = obj[member];
//  if (typeof thisObj == 'object' && thisObj !== null) {
//    obj[member] = qx.io.Json._fixObj(thisObj);
//  }
//  }
//
//  return obj;
//}


/**
 * Parse a JSON text, producing a JavaScript value.
 * It triggers an exception if there is a syntax error.
 *
 * @param text {String} JSON string
 * @return {var} evaluated JSON string.
 */
qx.io.Json.parseQx = function(text) {
  /* Convert the result text into a result primitive or object */

  if (qx.Settings.getValueOfClass("qx.io.Json", "enableDebug")) {
  var logger = qx.log.Logger.getClassLogger(qx.core.Object);
  logger.debug("JSON response: " + text);
  }

  var obj = (text && text.length > 0) ? eval('(' + text + ')') : null;

//  /*
//   * Something like this fixObj() call may be used later when we want to
//   * support class hints.  For now, ignore that code
//   */
//
//  /* If it's an object, not null, and contains a "result" field.. */
//  if (typeof obj == 'object' && obj !== null && obj.result) {
//  /* ... then 'fix' the result by handling any supported class hints */
//  obj.result = qx.io.Json._fixObj(obj.result);
//  }

  return obj;
}

/** indent string for JSON pretty printing */
qx.io.Json.BEAUTIFYING_INDENT = "  ";

/** new line string for JSON pretty printing */
qx.io.Json.BEAUTIFYING_LINE_END = "\n";
