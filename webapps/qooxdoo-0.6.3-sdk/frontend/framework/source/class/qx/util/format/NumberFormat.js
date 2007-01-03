/* ************************************************************************

   qooxdoo - the new era of web development

   http://qooxdoo.org

   Copyright:
     2006 by STZ-IDA, Germany, http://www.stz-ida.de

   License:
     LGPL 2.1: http://www.gnu.org/licenses/lgpl.html

   Authors:
     * Til Schneider (til132)

************************************************************************ */

/* ************************************************************************


************************************************************************ */

/**
 * A formatter and parser for numbers.
 */
qx.OO.defineClass("qx.util.format.NumberFormat", qx.util.format.Format,
function() {
  qx.util.format.Format.call(this);
});


/**
 * The minimum number of integer digits (digits before the decimal separator).
 * Missing digits will be filled up with 0 ("19" -> "0019").
 */
qx.OO.addProperty({ name:"minimumIntegerDigits", type:"number", defaultValue:0, allowNull:false });

/**
 * The maximum number of integer digits (superfluos digits will be cut off
 * ("1923" -> "23").
 */
qx.OO.addProperty({ name:"maximumIntegerDigits", type:"number", defaultValue:null });

/**
 * The minimum number of fraction digits (digits after the decimal separator).
 * Missing digits will be filled up with 0 ("1.5" -> "1.500")
 */
qx.OO.addProperty({ name:"minimumFractionDigits", type:"number", defaultValue:0, allowNull:false });

/**
 * The maximum number of fraction digits (digits after the decimal separator).
 * Superflous digits will cause rounding ("1.8277" -> "1.83")
 */
qx.OO.addProperty({ name:"maximumFractionDigits", type:"number", defaultValue:null });

/** Whether thousand groupings should be used {e.g. "1,432,234.65"}. */
qx.OO.addProperty({ name:"groupingUsed", type:"boolean", defaultValue:true, allowNull:false });

/** The prefix to put before the number {"EUR " -> "EUR 12.31"}. */
qx.OO.addProperty({ name:"prefix", type:"string", defaultValue:"", allowNull:false });

/** Sets the postfix to put after the number {" %" -> "56.13 %"}. */
qx.OO.addProperty({ name:"postfix", type:"string", defaultValue:"", allowNull:false });


/**
 * Formats a number.
 *
 * @param num {number} the number to format.
 * @return {string} the formatted number as a string.
 */
qx.Proto.format = function(num) {
  var NumberFormat = qx.util.format.NumberFormat;

  var negative = (num < 0);
  if (negative) {
    num = -num;
  }
  if (this.getMaximumFractionDigits() != null) {
    // Do the rounding
    var mover = Math.pow(10, this.getMaximumFractionDigits());
    num = Math.round(num * mover) / mover;
  }

  if (num != 0) { // Math.log(0) = -Infinity
    var integerDigits = Math.max(parseInt(Math.log(num) / Math.LN10) + 1, 1);
  } else {
    integerDigits = 1;
  }

  var numStr = "" + num;

  // Prepare the integer part
  var integerStr = numStr.substring(0, integerDigits);
  while (integerStr.length < this.getMinimumIntegerDigits()) {
    integerStr = "0" + integerStr;
  }
  if (this.getMaximumIntegerDigits() != null && integerStr.length > this.getMaximumIntegerDigits()) {
    // NOTE: We cut off even though we did rounding before, because there
    //     may be rounding errors ("12.24000000000001" -> "12.24")
    integerStr = integerStr.substring(integerStr.length - this.getMaximumIntegerDigits());
  }

  // Prepare the fraction part
  var fractionStr = numStr.substring(integerDigits + 1);
  while (fractionStr.length < this.getMinimumFractionDigits()) {
    fractionStr += "0";
  }
  if (this.getMaximumFractionDigits() != -1 && fractionStr.length > this.getMaximumFractionDigits()) {
    // We have already rounded -> Just cut off the rest
    fractionStr = fractionStr.substring(0, this.getMaximumFractionDigits());
  }

  // Add the thousand groupings
  if (this.getGroupingUsed()) {
    var origIntegerStr = integerStr;
    integerStr = "";
    var groupPos;
    for (groupPos = origIntegerStr.length; groupPos > 3; groupPos -= 3) {
      integerStr = NumberFormat.GROUPING_SEPARATOR
        + origIntegerStr.substring(groupPos - 3, groupPos) + integerStr;
    }
    integerStr = origIntegerStr.substring(0, groupPos) + integerStr;
  }

  // Workaround: prefix and postfix are null even their defaultValue is "" and
  //             allowNull is set to false?!?
  var prefix  = this.getPrefix()  ? this.getPrefix()  : "";
  var postfix = this.getPostfix() ? this.getPostfix() : "";

  // Assemble the number
  var str = prefix + (negative ? "-" : "") + integerStr;
  if (fractionStr.length > 0) {
    str += NumberFormat.DECIMAL_SEPARATOR + fractionStr;
  }
  str += postfix;

  return str;
}


/**
 * Parses a number.
 *
 * @param str {string} the string to parse.
 *
 * @return {double} the number.
 */
qx.Proto.parse = function(str) {
  var NumberFormat = qx.util.format.NumberFormat;

  // use the escaped separators for regexp
  var groupSepEsc = qx.lang.String.escapeRegexpChars(NumberFormat.GROUPING_SEPARATOR);
  var decimalSepEsc = qx.lang.String.escapeRegexpChars(NumberFormat.DECIMAL_SEPARATOR);

  var regex = new RegExp(qx.lang.String.escapeRegexpChars(this.getPrefix())
    + '(-)?([0-9' + groupSepEsc + ']+)'
    + '(' + decimalSepEsc + '\\d+)?'
    + qx.lang.String.escapeRegexpChars(this.getPostfix()));

  var hit = regex.exec(str);
  if (hit == null) {
    throw new Error("Number string '" + str + "' does not match the number format");
  }

  var negative = (hit[1] == "-");
  var integerStr = hit[2];
  var fractionStr = hit[3];

  // Remove the thousand groupings
  integerStr = integerStr.replace(new RegExp(groupSepEsc), "");

  var asStr = (negative ? "-" : "") + integerStr;
  if (fractionStr != null && fractionStr.length != 0) {
    // Remove the leading decimal separator from the fractions string
    fractionStr = fractionStr.replace(new RegExp(decimalSepEsc),"");
    asStr += "." + fractionStr;
  }
  return parseFloat(asStr);
}


/**
 * Returns the default number format.
 *
 * @return {NumberFormat} the default number format.
 */
qx.Class.getInstance = function() {
  var NumberFormat = qx.util.format.NumberFormat;
  if (NumberFormat._instance == null) {
    NumberFormat._instance = new NumberFormat();
  }
  return NumberFormat._instance;
}


/**
 * Returns an integer number format.
 *
 * @return {NumberFormat} an integer number format.
 */
qx.Class.getIntegerInstance = function() {
  var NumberFormat = qx.util.format.NumberFormat;
  if (NumberFormat._integerInstance == null) {
    NumberFormat._integerInstance = new NumberFormat();
    NumberFormat._integerInstance.setMaximumFractionDigits(0);
  }
  return NumberFormat._integerInstance;
}


/** {string} The decimal separator. */
qx.Class.DECIMAL_SEPARATOR = ".";

/** {string} The thousand grouping separator. */
qx.Class.GROUPING_SEPARATOR = ",";
