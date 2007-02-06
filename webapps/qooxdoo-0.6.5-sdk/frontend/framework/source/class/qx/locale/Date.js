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
     * Fabian Jakobs (fjakobs)

************************************************************************ */

/**
 * Create a new instance of qx.nls.Date
 */
qx.OO.defineClass("qx.locale.Date");


/**
 * Get AM marker for time definitions
 *
 * @param locale {String} optional locale to be used
 * @return {qx.locale.LocalizedString} translated AM marker.
 */
qx.Class.getAmMarker = function(locale) {
  return new qx.locale.LocalizedString("cldr_am", [], locale);
};


/**
 * Get PM marker for time definitions
 *
 * @param locale {String} optional locale to be used
 * @return {qx.locale.LocalizedString} translated PM marker.
 */
qx.Class.getPmMarker = function(locale) {
  return new qx.locale.LocalizedString("cldr_pm", [], locale);
};


/**
 * Return localized names of day names
 *
 * @param length {String} format of the day names.
 *     Possible values: "abbreviated", "narrow", "wide"
 * @param locale {String} optional locale to be used
 * @return {qx.locale.LocalizedString[]} array of localized day names starting with sunday.
 */
qx.Class.getDayNames = function(length, locale) {
  if (
    length != "abbreviated" &&
    length != "narrow" &&
    length != "wide"
  ) {
    throw new Error('format must be one of "abbreviated", "narrow", "wide"');
  }
  var days = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"];
  var names = [];
  for (var i=0; i<days.length; i++) {
    var key = "cldr_day_" + length + "_" + days[i];
    names.push(new qx.locale.LocalizedString(key, [], locale));
  }
  return names;
};


/**
 * Return localized name of a week day name
 *
 * @param length {String} format of the day name.
 *     Possible values: "abbreviated", "narrow", "wide"
 * @param day {Integer} day number. 0=sunday, 1=monday, ...
 * @param locale {String} optional locale to be used
 * @return {qx.locale.LocalizedString} localized day name
 */
qx.Class.getDayName = function(length, day, locale) {
  if (
    length != "abbreviated" &&
    length != "narrow" &&
    length != "wide"
  ) {
    throw new Error('format must be one of "abbreviated", "narrow", "wide"');
  }
  var days = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"];
  var key = "cldr_day_" + length + "_" + days[day];
  return new qx.locale.LocalizedString(key, [], locale);
};


/**
 * Return localized names of month names
 *
 * @param length {String} format of the month names.
 *     Possible values: "abbreviated", "narrow", "wide"
 * @param locale {String} optional locale to be used
 * @return {qx.locale.LocalizedString[]} array of localized month names starting with january.
 */
qx.Class.getMonthNames = function(length, locale) {
  if (
    length != "abbreviated" &&
    length != "narrow" &&
    length != "wide"
  ) {
    throw new Error('format must be one of "abbreviated", "narrow", "wide"');
  }
  var names = [];
  for (var i=0; i<12; i++) {
    var key = "cldr_month_" + length + "_" + (i+1);
    names.push(new qx.locale.LocalizedString(key, [], locale));
  }
  return names;
};


/**
 * Return localized name of a month
 *
 * @param length {String} format of the month names.
 *     Possible values: "abbreviated", "narrow", "wide"
 * @param month {Integer} index of the month. 0=january, 1=februrary, ...
 * @param locale {String} optional locale to be used
 * @return {qx.locale.LocalizedString} localized month name
 */
qx.Class.getMonthName = function(length, month, locale) {
  if (
    length != "abbreviated" &&
    length != "narrow" &&
    length != "wide"
  ) {
    throw new Error('format must be one of "abbreviated", "narrow", "wide"');
  }
  var key = "cldr_month_" + length + "_" + (month+1);
  return new qx.locale.LocalizedString(key, [], locale);
};


/**
 * Return localized date format string to be used with @{link qx.util.format.DateFormat}.
 *
 * @param size {String} format of the date format.
 *    Possible values: "short", "medium", "long", "full"
 * @param locale {String} optional locale to be used
 * @return {qx.locale.LocalizedString} localized date format string
 */
qx.Class.getDateFormat = function(size, locale) {
  if (
    size != "short" &&
    size != "medium" &&
    size != "long" &&
    size != "full"
  ) {
    throw new Error('format must be one of "short", "medium", "long", "full"');
  }
  var key = "cldr_date_format_" + size;
  return new qx.locale.LocalizedString(key, [], locale)
};


/**
 * Try to localize a date/time format string.
 *
 * If now localization is availible take the fallback format string
 *
 * @param canonical {String} format string containing only field information, and in a canonical order.
 *     Examples are "yyyyMMMM" for year + full month, or "MMMd" for abbreviated month + day.
 * @param fallback {String} fallback format string if no localized version is found
 * @param locale {String} optional locale to be used
 * @return {String} best matching format string
 */
qx.Class.getDateTimeFormat = function(canonical, fallback, locale) {
  var key = "cldr_date_time_format_" + canonical;
  var localizedFormat = qx.locale.Manager.getInstance().translate(key, [], locale);
  if (localizedFormat == key) {
    localizedFormat = fallback;
  }
  return localizedFormat;
};


/**
 * Return localized time format string to be used with {@link qx.util.format.DateFormat}.
 *
 * @param size {String} format of the time pattern.
 *    Possible values: "short", "medium", "long", "full"
 * @param locale {String} optional locale to be used
 * @return {qx.locale.LocalizedString} localized time format string
 */
qx.Class.getTimeFormat = function(size, locale) {
  if (
    size != "short" &&
    size != "medium" &&
    size != "long" &&
    size != "full"
  ) {
    throw new Error('format must be one of "short", "medium", "long", "full"');
  }
  switch (size) {
    case "short":
    case "medium":
      return qx.locale.Date.getDateTimeFormat("HHmm", "HH:mm");

    case "long":
      return qx.locale.Date.getDateTimeFormat("HHmmss", "HH:mm:ss");

    case "full":
      return qx.locale.Date.getDateTimeFormat("HHmmsszz", "HH:mm:ss zz");

    default:
      throw new Error("This case should never happen.");
  }
};


/**
 * Return the day the week starts with
 *
 * Reference: Common Locale Data Repository (cldr) supplementalData.xml
 *
 * @param locale {String} optional locale to be used
 * @return {Integer} index of the first day of the week. 0=sunday, 1=monday, ...
 */
qx.Class.getWeekStart = function(locale) {
  var weekStart = {
    // default is monday

    "MV": 5, // friday

    "AE": 6, // saturday
    "AF": 6,
    "BH": 6,
    "DJ": 6,
    "DZ": 6,
    "EG": 6,
    "ER": 6,
    "ET": 6,
    "IQ": 6,
    "IR": 6,
    "JO": 6,
    "KE": 6,
    "KW": 6,
    "LB": 6,
    "LY": 6,
    "MA": 6,
    "OM": 6,
    "QA": 6,
    "SA": 6,
    "SD": 6,
    "SO": 6,
    "TN": 6,
    "YE": 6,

    "AS": 0, // sunday
    "AU": 0,
    "AZ": 0,
    "BW": 0,
    "CA": 0,
    "CN": 0,
    "FO": 0,
    "GE": 0,
    "GL": 0,
    "GU": 0,
    "HK": 0,
    "IE": 0,
    "IL": 0,
    "IS": 0,
    "JM": 0,
    "JP": 0,
    "KG": 0,
    "KR": 0,
    "LA": 0,
    "MH": 0,
    "MN": 0,
    "MO": 0,
    "MP": 0,
    "MT": 0,
    "NZ": 0,
    "PH": 0,
    "PK": 0,
    "SG": 0,
    "TH": 0,
    "TT": 0,
    "TW": 0,
    "UM": 0,
    "US": 0,
    "UZ": 0,
    "VI": 0,
    "ZA": 0,
    "ZW": 0,

    "ET": 0,
    "MW": 0,
    "NG": 0,
    "TJ": 0
  };
  var territory = qx.locale.Date._getTerritory(locale);
  // default is monday
  return weekStart[territory] != null ? weekStart[territory] : 1;
};


/**
 * Return the day the weekend starts with
 *
 * Reference: Common Locale Data Repository (cldr) supplementalData.xml
 *
 * @param locale {String} optional locale to be used
 * @return {Integer} index of the first day of the weekend. 0=sunday, 1=monday, ...
 */
qx.Class.getWeekendStart = function(locale) {
  var weekendStart = {
    // default is saturday

    "EG": 5, // friday
    "IL": 5,
    "SY": 5,

    "IN": 0, // sunday

    "AE": 4, // thursday
    "BH": 4,
    "DZ": 4,
    "IQ": 4,
    "JO": 4,
    "KW": 4,
    "LB": 4,
    "LY": 4,
    "MA": 4,
    "OM": 4,
    "QA": 4,
    "SA": 4,
    "SD": 4,
    "TN": 4,
    "YE": 4
  };
  var territory = qx.locale.Date._getTerritory(locale);
  // default is saturday
  return weekendStart[territory] != null ? weekendStart[territory] : 6;
};


/**
 * Return the day the weekend ends with
 *
 * Reference: Common Locale Data Repository (cldr) supplementalData.xml
 *
 * @param locale {String} optional locale to be used
 * @return {Integer} index of the last day of the weekend. 0=sunday, 1=monday, ...
 */
qx.Class.getWeekendEnd = function(locale) {
  var weekendEnd = {
    // default is sunday

    "AE": 5, // friday
    "BH": 5,
    "DZ": 5,
    "IQ": 5,
    "JO": 5,
    "KW": 5,
    "LB": 5,
    "LY": 5,
    "MA": 5,
    "OM": 5,
    "QA": 5,
    "SA": 5,
    "SD": 5,
    "TN": 5,
    "YE": 5,
    "AF": 5,
    "IR": 5,

    "EG": 6, // saturday
    "IL": 6,
    "SY": 6
  }
  var territory = qx.locale.Date._getTerritory(locale);
  // default is sunday
  return weekendEnd[territory] != null ? weekendEnd[territory] : 0;
};


/**
 * Returns whether a certain day of week belongs to the week end.
 *
 * @param day {Integer} index of the day. 0=sunday, 1=monday, ...
 * @param locale {String} optional locale to be used
 * @return {Boolean} whether the given day is a weekend day
 */
qx.Class.isWeekend = function(day, locale) {
  var weekendStart = qx.locale.Date.getWeekendStart(locale);
  var weekendEnd = qx.locale.Date.getWeekendEnd(locale);
  if (weekendEnd > weekendStart) {
    return (
      (day >= weekendStart) &&
      (day <= weekendEnd)
    );
  } else {
    return (
      (day >= weekendStart) ||
      (day <= weekendEnd)
    );
  }
};


/**
 * Extract the territory part from a locale
 *
 * @param locale {String} the locale
 * @return {String} territory
 */
qx.Class._getTerritory = function(locale) {
  if (locale) {
    var territory = locale.split("_")[1] || locale;
  } else {
    territory =
      qx.locale.Manager.getInstance().getTerritory() ||
      qx.locale.Manager.getInstance().getLanguage();
  };
  return territory.toUpperCase();
};