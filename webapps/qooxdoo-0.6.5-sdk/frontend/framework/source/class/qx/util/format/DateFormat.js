/* ************************************************************************

   qooxdoo - the new era of web development

   http://qooxdoo.org

   Copyright:
     2006 STZ-IDA, Germany, http://www.stz-ida.de

   License:
     LGPL: http://www.gnu.org/licenses/lgpl.html
     EPL: http://www.eclipse.org/org/documents/epl-v10.php
     See the LICENSE file in the project's top-level directory for details.

   Authors:
     * Til Schneider (til132)
     * Fabian Jakobs (fjakobs)

************************************************************************ */

/* ************************************************************************

#require(qx.locale.Date)

************************************************************************ */

/**
 * A formatter and parser for dates
 *
 * @param format {String} The format to use. If null, the
 *    {@link #DEFAULT_DATE_TIME_FORMAT} is used.
 * @param locale {String} optional locale to be used
 */
qx.OO.defineClass("qx.util.format.DateFormat", qx.util.format.Format,
function(format, locale) {
  qx.util.format.Format.call(this);

  if (format != null) {
    this._format = format.toString()
  } else {
    this._format = qx.locale.Date.getDateFormat("long", locale) + " " + qx.locale.Date.getDateTimeFormat("HHmmss", "HH:mm:ss", locale);
  }
  this._locale = locale;
});


/**
 * Fills a number with leading zeros ("25" -> "0025").
 *
 * @param number {Integer} the number to fill.
 * @param minSize {Integer} the minimum size the returned string should have.
 * @return {String} the filled number as string.
 */
qx.Proto._fillNumber = function(number, minSize) {
  var str = "" + number;
  while (str.length < minSize) {
    str = "0" + str;
  }
  return str;
}


/**
 * Returns the day in year of a date.
 *
 * @param date {Date} the date.
 * @return {Integer} the day in year.
 */
qx.Proto._getDayInYear = function(date) {
  var helpDate = new Date(date.getTime());
  var day = helpDate.getDate();
  while (helpDate.getMonth() != 0) {
    // Set the date to the last day of the previous month
    helpDate.setDate(-1);
    day += helpDate.getDate() + 1;
  }
  return day;
}


/**
 * Returns the thursday in the same week as the date.
 *
 * @param date {Date} the date to get the thursday of.
 * @return {Date} the thursday in the same week as the date.
 */
qx.Proto._thursdayOfSameWeek = function(date) {
  return new Date(date.getTime() + (3 - ((date.getDay() + 6) % 7)) * 86400000);
}


/**
 * Returns the week in year of a date.
 *
 * @param date {Date} the date to get the week in year of.
 * @return {Integer} the week in year.
 */
qx.Proto._getWeekInYear = function(date) {
  // This algorithm gets the correct calendar week after ISO 8601.
  // This standard is used in almost all european countries.
  // TODO: In the US week in year is calculated different!
  // See http://www.merlyn.demon.co.uk/weekinfo.htm

  // The following algorithm comes from http://www.salesianer.de/util/kalwoch.html

  // Get the thursday of the week the date belongs to
  var thursdayDate = this._thursdayOfSameWeek(date);
  // Get the year the thursday (and therefor the week) belongs to
  var weekYear = thursdayDate.getFullYear();
  // Get the thursday of the week january 4th belongs to
  // (which defines week 1 of a year)
  var thursdayWeek1 = this._thursdayOfSameWeek(new Date(weekYear, 0, 4));
  // Calculate the calendar week
  return Math.floor(1.5 + (thursdayDate.getTime() - thursdayWeek1.getTime()) / 86400000 / 7)
}


/**
 * Formats a date.
 * <p>
 * Uses the same syntax as
 * <a href="http://java.sun.com/j2se/1.4.2/docs/api/java/text/SimpleDateFormat.html" target="_blank">
 * the SimpleDateFormat class in Java</a>.
 *
 * @param date {Date} The date to format.
 * @return {String} the formatted date.
 */
qx.Proto.format = function(date) {
  var DateFormat = qx.util.format.DateFormat;
  var locale = this._locale;

  var fullYear = date.getFullYear();
  var month = date.getMonth();
  var dayOfMonth = date.getDate();
  var dayOfWeek = date.getDay();
  var hours = date.getHours();
  var minutes = date.getMinutes();
  var seconds = date.getSeconds();
  var ms = date.getMilliseconds();
  var timezone = date.getTimezoneOffset() / 60;

  // Create the output
  this._initFormatTree();
  var output = "";
  for (var i = 0; i < this._formatTree.length; i++) {
    var currAtom = this._formatTree[i];

    if (currAtom.type == "literal") {
      output += currAtom.text;
    } else {
      // This is a wildcard
      var wildcardChar = currAtom.character;
      var wildcardSize = currAtom.size;

      // Get its replacement
      var replacement = "?";
      switch (wildcardChar) {
        // TODO: G - Era designator (e.g. AD). Problem: Not covered by JScript Date class
        // TODO: W - Week in month (e.g. 2)
        // TODO: F - Day of week in month (e.g.   2). Problem: What is this?

        case 'y': // Year
          if (wildcardSize == 2) {
            replacement = this._fillNumber(fullYear % 100, 2);
          } else if (wildcardSize == 4) {
            replacement = fullYear;
          }
          break;
        case 'D': // Day in year (e.g. 189)
          replacement = this._fillNumber(this._getDayInYear(date), wildcardSize); break;
        case 'd': // Day in month
          replacement = this._fillNumber(dayOfMonth, wildcardSize); break;
        case 'w': // Week in year (e.g. 27)
          replacement = this._fillNumber(this._getWeekInYear(date), wildcardSize); break;
        case 'E': // Day in week
          if (wildcardSize == 2) {
            replacement = qx.locale.Date.getDayName("narrow", dayOfWeek, locale);
          } else if (wildcardSize == 3) {
            replacement = qx.locale.Date.getDayName("abbreviated", dayOfWeek, locale);
          } else if (wildcardSize == 4) {
            replacement = qx.locale.Date.getDayName("wide", dayOfWeek, locale);
          }
          break;
        case 'M': // Month
          if (wildcardSize == 1 || wildcardSize == 2) {
            replacement = this._fillNumber(month + 1, wildcardSize);
          } else if (wildcardSize == 3) {
            replacement = qx.locale.Date.getMonthName("abbreviated",month, locale);
          } else if (wildcardSize == 4) {
            replacement = qx.locale.Date.getMonthName("wide", month, locale);
          }
          break;
        case 'a': // am/pm marker
          // NOTE: 0:00 is am, 12:00 is pm
          replacement = (hours < 12) ? qx.locale.Date.getAmMarker(locale) : qx.locale.Date.getPmMarker(locale); break;
        case 'H': // Hour in day (0-23)
          replacement = this._fillNumber(hours, wildcardSize); break;
        case 'k': // Hour in day (1-24)
          replacement = this._fillNumber((hours == 0) ? 24 : hours, wildcardSize); break;
        case 'K': // Hour in am/pm (0-11)
          replacement = this._fillNumber(hours % 12, wildcardSize); break;
        case 'h': // Hour in am/pm (1-12)
          replacement = this._fillNumber(((hours % 12) == 0) ? 12 : (hours % 12), wildcardSize); break;
        case 'm': // Minute in hour
          replacement = this._fillNumber(minutes, wildcardSize); break;
        case 's': // Second in minute
          replacement = this._fillNumber(seconds, wildcardSize); break;
        case 'S': // Millisecond
          replacement = this._fillNumber(ms, wildcardSize); break;
        case 'z': // Time zone
          if (wildcardSize == 1) {
            replacement = "GMT" + ((timezone < 0) ? "-" : "+") + this._fillNumber(timezone) + ":00";
          } else if (wildcardSize == 2) {
            replacement = DateFormat.MEDIUM_TIMEZONE_NAMES[timezone];
          } else if (wildcardSize == 3) {
            replacement = DateFormat.FULL_TIMEZONE_NAMES[timezone];
          }
          break;
        case 'Z': // RFC 822 time zone
          replacement = ((timezone < 0) ? "-" : "+") + this._fillNumber(timezone, 2) + "00";
      }
      output += replacement;
    }
  }

  return output;
}


/**
 * Parses a date.
 * <p>
 * Uses the same syntax as
 * <a href="http://java.sun.com/j2se/1.4.2/docs/api/java/text/SimpleDateFormat.html" target="_blank">
 * the SimpleDateFormat class in Java</a>.
 *
 * @param dateStr {String} the date to parse.
 * @return {Date} the parsed date.
 * @throws If the format is not well formed or if the date string does not
 *     match to the format.
 */
qx.Proto.parse = function(dateStr) {
  this._initParseFeed();

  // Apply the regex
  var hit = this._parseFeed.regex.exec(dateStr);
  if (hit == null) {
    throw new Error("Date string '" + dateStr + "' does not match the date format: " + this._format);
  }

  // Apply the rules
  var dateValues = { year:1970, month:0, day:1, hour:0, ispm:false, min:0, sec:0, ms:0 }
  var currGroup = 1;
  for (var i = 0; i < this._parseFeed.usedRules.length; i++) {
    var rule = this._parseFeed.usedRules[i];

    var value = hit[currGroup];
    if (rule.field != null) {
      dateValues[rule.field] = parseInt(value, 10);
    } else {
      rule.manipulator(dateValues, value);
    }

    currGroup += (rule.groups == null) ? 1 : rule.groups;
  }

  var date = new Date(dateValues.year, dateValues.month, dateValues.day,
    (dateValues.ispm) ? (dateValues.hour + 12) : dateValues.hour,
    dateValues.min, dateValues.sec, dateValues.ms);
  if (dateValues.month != date.getMonth() || dateValues.year != date.getFullYear()) {
    // TODO: check if this is also necessary for the time components
    throw new Error("Error parsing date '" + dateStr + "': the value for day or month is too large");
  }

  return date;
}



/**
 * Helper method for {@link #format()} and {@link #parse()}.
 * Parses the date format.
 */
qx.Proto._initFormatTree = function() {
  if (this._formatTree != null) {
    return;
  }

  this._formatTree = [];

  var currWildcardChar;
  var currWildcardSize = 0;
  var currLiteral = "";
  var format = this._format;

  var state = "default"

  var i = 0;
  while (i < format.length) {
    var currChar = format.charAt(i);

    switch (state) {
      case "quoted_literal":
        // We are now inside a quoted literal
        // Check whether the current character is an escaped "'" character
        if (currChar == "'") {
          if (i+1 >= format.length) {
            // this is the last character
            i++;
            break;
          }
          var lookAhead = format.charAt(i+1);
          if (lookAhead == "'") {
            currLiteral += currChar;
            i++;
          } else {
            // quoted literal ends
            i++;
            state = "unkown";
          }
        } else {
          currLiteral += currChar;
          i++;
        }
        break;
      case "wildcard":
        // Check whether the currChar belongs to that wildcard
        if (currChar == currWildcardChar) {
          // It does -> Raise the size
          currWildcardSize++;
          i++;
        } else {
          // It does not -> The current wildcard is done
          this._formatTree.push({ type:"wildcard", character:currWildcardChar, size:currWildcardSize });
          currWildcardChar = null;
          currWildcardSize = 0;
          state = "default";
        }
        break;
      default:
        // We are not (any more) in a wildcard or quoted literal -> Check what's starting here
        if ((currChar >= 'a' && currChar <= 'z') || (currChar >= 'A' && currChar <= 'Z')) {
          // This is a letter -> All letters are wildcards
          // Start a new wildcard
          currWildcardChar = currChar;
          state = "wildcard";
        } else if (currChar == "'") {
          if (i+1 >= format.length) {
            // this is the last character
            currLiteral += currChar;
            i++;
            break;
          }
          var lookAhead = format.charAt(i+1);
          if (lookAhead == "'") {
            currLiteral += currChar;
            i++;
          }
          i++;
          state = "quoted_literal";
        } else {
          state = "default"
        }
        if (state != "default") {
          // Add the literal
          if (currLiteral.length > 0) {
            this._formatTree.push({ type:"literal", text:currLiteral });
            currLiteral = "";
          }
        } else {
          // This is an unquoted literal -> Add it to the current literal
          currLiteral += currChar;
          i++;
        }
        break;
    }
  }

  // Add the last wildcard or literal
  if (currWildcardChar != null) {
    this._formatTree.push({ type:"wildcard", character:currWildcardChar, size:currWildcardSize });
  } else if (currLiteral.length > 0) {
    this._formatTree.push({ type:"literal", text:currLiteral });
  }
}


/**
 * Initializes the parse feed.
 * <p>
 * The parse contains everything needed for parsing: The regular expression
 * (in compiled and uncompiled form) and the used rules.
 *
 * @return {Map} the parse feed.
 */
qx.Proto._initParseFeed = function() {
  if (this._parseFeed != null) {
    // We already have the farse feed
    return;
  }

  var DateFormat = qx.util.format.DateFormat;
  var format = this._format;

  // Initialize the rules
  this._initParseRules();
  this._initFormatTree();

  // Get the used rules and construct the regex pattern
  var usedRules = [];
  var pattern = "^";
  for (var atomIdx = 0; atomIdx < this._formatTree.length; atomIdx++) {
    var currAtom = this._formatTree[atomIdx];

    if (currAtom.type == "literal") {
      pattern += qx.lang.String.escapeRegexpChars(currAtom.text);
    } else {
      // This is a wildcard
      var wildcardChar = currAtom.character;
      var wildcardSize = currAtom.size;

      // Get the rule for this wildcard
      var wildcardRule;
      for (var ruleIdx = 0; ruleIdx < DateFormat._parseRules.length; ruleIdx++) {
        var rule = DateFormat._parseRules[ruleIdx];
        if (wildcardChar == rule.pattern.charAt(0) && wildcardSize == rule.pattern.length) {
          // We found the right rule for the wildcard
          wildcardRule = rule;
          break;
        }
      }

      // Check the rule
      if (wildcardRule == null) {
        // We have no rule for that wildcard -> Malformed date format
        var wildcardStr = "";
        for (var i = 0; i < wildcardSize; i++) {
          wildcardStr += wildcardChar;
        }
        throw new Error("Malformed date format: " + format + ". Wildcard "
          + wildcardStr + " is not supported");
      } else {
        // Add the rule to the pattern
        usedRules.push(wildcardRule);
        pattern += wildcardRule.regex;
      }
    }
  }
  pattern += "$";

  // Create the regex
  var regex;
  try {
    regex = new RegExp(pattern);
  }
  catch (exc) {
    throw new Error("Malformed date format: " + format);
  }

  // Create the this._parseFeed
  this._parseFeed = { regex:regex, "usedRules":usedRules, pattern:pattern }
}


/**
 * Initializes the static parse rules.
 */
qx.Proto._initParseRules = function() {
  var DateFormat = qx.util.format.DateFormat;

  if (DateFormat._parseRules != null) {
    // The parse rules are already initialized
    return;
  }

  DateFormat._parseRules = [];

  var yearManipulator = function(dateValues, value) {
    value = parseInt(value, 10);
    if (value < DateFormat.ASSUME_YEAR_2000_THRESHOLD) {
      value += 2000;
    } else if (value < 100) {
      value += 1900;
    }

    dateValues.year = value;
  }

  var monthManipulator = function(dateValues, value) {
    dateValues.month = parseInt(value, 10) - 1;
  }

  var ampmManipulator = function(dateValues, value) {
    dateValues.ispm = (value == DateFormat.PM_MARKER);
  }

  var noZeroHourManipulator = function(dateValues, value) {
    dateValues.hour = parseInt(value, 10) % 24;
  }

  var noZeroAmPmHourManipulator = function(dateValues, value) {
    dateValues.hour = parseInt(value, 10) % 12;
  }

  // Unsupported: w (Week in year), W (Week in month), D (Day in year),
  // F (Day of week in month), z (time zone) reason: no setter in Date class,
  // Z (RFC 822 time zone) reason: no setter in Date class

  DateFormat._parseRules.push({ pattern:"yyyy", regex:"(\\d\\d(\\d\\d)?)",
    groups:2, manipulator:yearManipulator } );
  DateFormat._parseRules.push({ pattern:"yy",   regex:"(\\d\\d)",  manipulator:yearManipulator } );
  // TODO: "MMMM", "MMM" (Month names)
  DateFormat._parseRules.push({ pattern:"M",    regex:"(\\d\\d?)", manipulator:monthManipulator });
  DateFormat._parseRules.push({ pattern:"MM",   regex:"(\\d\\d?)", manipulator:monthManipulator });
  DateFormat._parseRules.push({ pattern:"dd",   regex:"(\\d\\d?)", field:"day" });
  DateFormat._parseRules.push({ pattern:"d",    regex:"(\\d\\d?)", field:"day" });
  // TODO: "EEEE", "EEE", "EE" (Day in week names)
  DateFormat._parseRules.push({ pattern:"a",
    regex:"(" + DateFormat.AM_MARKER + "|" + DateFormat.PM_MARKER + ")",
    manipulator:ampmManipulator });
  DateFormat._parseRules.push({ pattern:"HH",   regex:"(\\d\\d?)", field:"hour" });
  DateFormat._parseRules.push({ pattern:"H",    regex:"(\\d\\d?)", field:"hour" });
  DateFormat._parseRules.push({ pattern:"kk",   regex:"(\\d\\d?)", manipulator:noZeroHourManipulator });
  DateFormat._parseRules.push({ pattern:"k",    regex:"(\\d\\d?)", manipulator:noZeroHourManipulator });
  DateFormat._parseRules.push({ pattern:"KK",   regex:"(\\d\\d?)", field:"hour" });
  DateFormat._parseRules.push({ pattern:"K",    regex:"(\\d\\d?)", field:"hour" });
  DateFormat._parseRules.push({ pattern:"hh",   regex:"(\\d\\d?)", manipulator:noZeroAmPmHourManipulator });
  DateFormat._parseRules.push({ pattern:"h",    regex:"(\\d\\d?)", manipulator:noZeroAmPmHourManipulator });
  DateFormat._parseRules.push({ pattern:"mm",   regex:"(\\d\\d?)", field:"min" });
  DateFormat._parseRules.push({ pattern:"m",    regex:"(\\d\\d?)", field:"min" });
  DateFormat._parseRules.push({ pattern:"ss",   regex:"(\\d\\d?)", field:"sec" });
  DateFormat._parseRules.push({ pattern:"s",    regex:"(\\d\\d?)", field:"sec" });
  DateFormat._parseRules.push({ pattern:"SSS",  regex:"(\\d\\d?\\d?)", field:"ms" });
  DateFormat._parseRules.push({ pattern:"SS",   regex:"(\\d\\d?\\d?)", field:"ms" });
  DateFormat._parseRules.push({ pattern:"S",    regex:"(\\d\\d?\\d?)", field:"ms" });
}


/**
 * Returns a <code>DateFomat</code> instance that uses the
 * {@link #DEFAULT_DATE_TIME_FORMAT}.
 *
 * @return {String} the date/time instance.
 */
qx.Class.getDateTimeInstance = function() {
  var DateFormat = qx.util.format.DateFormat;

  var format = qx.locale.Date.getDateFormat("long") + " " + qx.locale.Date.getDateTimeFormat("HHmmss", "HH:mm:ss");
  if (
    DateFormat._dateInstance == null ||
    DateFormat._format != format
  ) {
    DateFormat._dateTimeInstance = new DateFormat();
  }
  return DateFormat._dateTimeInstance;
}


/**
 * Returns a <code>DateFomat</code> instance that uses the
 * {@link #DEFAULT_DATE_FORMAT}.
 *
 * @return {String} the date instance.
 */
qx.Class.getDateInstance = function() {
  var DateFormat = qx.util.format.DateFormat;

  var format = qx.locale.Date.getDateFormat("short") + "";
  if (
    DateFormat._dateInstance == null ||
    DateFormat._format != format
  ) {
    DateFormat._dateInstance = new DateFormat(format);
  }
  return DateFormat._dateInstance;
}


/**
 * (int) The threshold until when a year should be assumed to belong to the
 * 21st century (e.g. 12 -> 2012). Years over this threshold but below 100 will be
 * assumed to belong to the 20th century (e.g. 88 -> 1988). Years over 100 will be
 * used unchanged (e.g. 1792 -> 1792).
 */
qx.Class.ASSUME_YEAR_2000_THRESHOLD = 30;

/** {string} The date format used for logging. */
qx.Class.LOGGING_DATE_TIME_FORMAT = "yyyy-MM-dd HH:mm:ss";

/** {string} The am marker. */
qx.Class.AM_MARKER = "am"

/** {string} The pm marker. */
qx.Class.PM_MARKER = "pm";

/** {string[]} The medium (three letter) timezone names. */
qx.Class.MEDIUM_TIMEZONE_NAMES = [
  "GMT" // TODO: fill up
];

/** {string[]} The full timezone names. */
qx.Class.FULL_TIMEZONE_NAMES = [
  "Greenwich Mean Time" // TODO: fill up
];