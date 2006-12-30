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
     * Fabian Jakobs (fjakobs)

************************************************************************ */

/* ************************************************************************

#module(ui_core)
#require(qx.event.type.KeyEvent)
#require(qx.util.Return);

************************************************************************ */

/**
 * This class provides unified key event handler for Internet Explorer,
 * Firefox, Opera and Safari
 */
qx.OO.defineClass("qx.event.handler.KeyEventHandler", qx.core.Target, function()
{
  qx.core.Target.call(this);

  // Object Wrapper to Events (Needed for DOM-Events)
  var o = this;

  this.__onkeypress = function(e) { o._onkeypress(e); };
  this.__onkeyupdown = function(e) { o._onkeyupdown(e); };
});








/*
---------------------------------------------------------------------------
  EVENT-MAPPING
---------------------------------------------------------------------------
*/

/** attach the key event handler to the DOM events */
qx.Proto._attachEvents = function()
{
  var el = qx.sys.Client.getInstance().isGecko() ? window : document.body;

  qx.dom.EventRegistration.addEventListener(el, "keypress", this.__onkeypress);
  qx.dom.EventRegistration.addEventListener(el, "keyup", this.__onkeyupdown);
  qx.dom.EventRegistration.addEventListener(el, "keydown", this.__onkeyupdown);
};

/** detach the key event handler from the DOM events */
qx.Proto._detachEvents = function()
{
  var el = qx.sys.Client.getInstance().isGecko() ? window : document.body;

  // Unregister dom events
  qx.dom.EventRegistration.removeEventListener(el, "keypress", this.__onkeypress);
  qx.dom.EventRegistration.removeEventListener(el, "keyup", this.__onkeyupdown);
  qx.dom.EventRegistration.removeEventListener(el, "keydown", this.__onkeyupdown);
};








/*
---------------------------------------------------------------------------
  KEY-MAPS
---------------------------------------------------------------------------
*/

/** maps the charcodes of special printable keys to key identifiers */
qx.Proto._specialCharCodeMap =
{
    8 : "Backspace",   // The Backspace (Back) key.
    9 : "Tab",         // The Horizontal Tabulation (Tab) key.
   32 : "Space"        // The Space (Spacebar) key.
};

/** maps the keycodes of non printable keys to key identifiers */
qx.Proto._keyCodeToIdentifierMap =
{
   13 : "Enter",       // The Enter key.
                       //   Note: This key identifier is also used for the
                       //   Return (Macintosh numpad) key.
   16 : "Shift",       // The Shift key.
   17 : "Control",     // The Control (Ctrl) key.
   18 : "Alt",         // The Alt (Menu) key.
   20 : "CapsLock",    // The CapsLock key
  224 : "Meta",        // The Meta key. (Apple Meta and Windows key)

   27 : "Escape",      // The Escape (Esc) key.

   37 : "Left",        // The Left Arrow key.
   38 : "Up",          // The Up Arrow key.
   39 : "Right",       // The Right Arrow key.
   40 : "Down",        // The Down Arrow key.

   33 : "PageUp",      // The Page Up key.
   34 : "PageDown",    // The Page Down (Next) key.

   35 : "End",         // The End key.
   36 : "Home",        // The Home key.
   45 : "Insert",      // The Insert (Ins) key. (Does not fire in Opera/Win)
   46 : "Delete",      // The Delete (Del) Key.

  112 : "F1",          // The F1 key.
  113 : "F2",          // The F2 key.
  114 : "F3",          // The F3 key.
  115 : "F4",          // The F4 key.
  116 : "F5",          // The F5 key.
  117 : "F6",          // The F6 key.
  118 : "F7",          // The F7 key.
  119 : "F8",          // The F8 key.
  120 : "F9",          // The F9 key.
  121 : "F10",         // The F10 key.
  122 : "F11",         // The F11 key.
  123 : "F12",         // The F12 key.

  144 : "NumLock",     // The Num Lock key.
   44 : "PrintScreen", // The Print Screen (PrintScrn, SnapShot) key.
  145 : "Scroll",      // The scroll lock key
   19 : "Pause",       // The pause/break key

   91 : "Win",         // The Windows Logo key
   93 : "Apps"         // The Application key (Windows Context Menu)
};

/** maps the keycodes of the numpad keys to the right charcodes */
qx.Proto._numpadToCharCode =
{
   96 : "0".charCodeAt(0),
   97 : "1".charCodeAt(0),
   98 : "2".charCodeAt(0),
   99 : "3".charCodeAt(0),
  100 : "4".charCodeAt(0),
  101 : "5".charCodeAt(0),
  102 : "6".charCodeAt(0),
  103 : "7".charCodeAt(0),
  104 : "8".charCodeAt(0),
  105 : "9".charCodeAt(0),

  106 : "*".charCodeAt(0),
  107 : "+".charCodeAt(0),
  109 : "-".charCodeAt(0),
  110 : ",".charCodeAt(0),
  111 : "/".charCodeAt(0)
};


// construct invers of keyCodeToIdentifierMap
if (!qx.Proto._identifierToKeyCodeMap)
{
  qx.Proto._identifierToKeyCodeMap = {};

  for (var key in qx.Proto._keyCodeToIdentifierMap) {
    qx.Proto._identifierToKeyCodeMap[qx.Proto._keyCodeToIdentifierMap[key]] = parseInt(key);
  }

  for (var key in qx.Proto._specialCharCodeMap) {
    qx.Proto._identifierToKeyCodeMap[qx.Proto._specialCharCodeMap[key]] = parseInt(key);
  }
}








/*
---------------------------------------------------------------------------
  HELPER-METHODS
---------------------------------------------------------------------------
*/

qx.Proto._charCodeA = "A".charCodeAt(0);
qx.Proto._charCodeZ = "Z".charCodeAt(0);
qx.Proto._charCode0 = "0".charCodeAt(0);
qx.Proto._charCode9 = "9".charCodeAt(0);

/**
 * Checks wether the keyCode represents a non printable key
 *
 * @param keyCode (string)
 * @return (boolean)
 */
qx.Proto._isNonPrintableKeyCode = function(keyCode) {
  return this._keyCodeToIdentifierMap[keyCode] ? true : false;
};


/**
 * Check wether the keycode can be reliably detected in keyup/keydown events
 *
 * @param keyCode (string)
 * @return (boolean)
 */
qx.Proto._isIdentifiableKeyCode = function(keyCode)
{
  // A-Z
  if (keyCode >= this._charCodeA && keyCode <= this._charCodeZ) {
    return true;
  }

  // 0-9
  if (keyCode >= this._charCode0 && keyCode <= this._charCode9) {
    return true;
  }

  // Enter, Space, Tab, Backspace
  if (this._specialCharCodeMap[keyCode]) {
    return true;
  }

  // Numpad
  if (this._numpadToCharCode[keyCode]) {
    return true;
  }

  // non printable keys
  if (this._isNonPrintableKeyCode(keyCode)) {
    return true;
  }

  return false;
};


/**
 * Checks wether a given string is a valid keyIdentifier
 *
 * @param keyIdentifier (string)
 * @return (boolean) wether the given string is a valid keyIdentifier
 */
qx.Proto.isValidKeyIdentifier = function(keyIdentifier)
{
  if (this._identifierToKeyCodeMap[keyIdentifier]) {
    return true;
  }

  if (keyIdentifier.length != 1) {
    return false;
  }

  if (keyIdentifier >= "0" && keyIdentifier <= "9") {
    return true;
  }

  if (keyIdentifier >= "A" && keyIdentifier <= "Z") {
    return true;
  }

  switch (keyIdentifier)
  {
    case "+":
    case "-":
    case "*":
    case "/":
      return true;

    default:
      return false;
  }
};


/**
 * converts a keyboard code to the corresponding identifier
 *
 * @param keyCode (int)
 * @return (string) key identifier
 */
qx.Proto._keyCodeToIdentifier = function(keyCode)
{
  if (this._isIdentifiableKeyCode(keyCode))
  {
    var numPadKeyCode = this._numpadToCharCode[keyCode];
    if (numPadKeyCode) {
      return String.fromCharCode(numPadKeyCode);
    }

    return (
      this._keyCodeToIdentifierMap[keyCode] ||
      this._specialCharCodeMap[keyCode] ||
      String.fromCharCode(keyCode)
    );
  }
  else
  {
    return "Unidentified";
  }
};


/**
 * converts a character code to the corresponding identifier
 *
 * @param charCode (string)
 * @return (string) key identifier
 */
qx.Proto._charCodeToIdentifier = function(charCode) {
  return this._specialCharCodeMap[charCode] || String.fromCharCode(charCode).toUpperCase();
};


/**
 * converts a key identifier back to a keycode
 *
 * @param keyIdentifier (string)
 * @return (int) keyboard code
 */
qx.Proto._identifierToKeyCode = function(keyIdentifier) {
  return this._identifierToKeyCodeMap[keyIdentifier] || keyIdentifier.charCodeAt(0);
};






/*
---------------------------------------------------------------------------
  COMPATIBILITY TO COMMAND
---------------------------------------------------------------------------
*/

qx.Proto._oldKeyNameToKeyIdentifierMap =
{
  // all other keys are converted by converting the first letter to uppercase

  esc      : "Escape",
  ctrl     : "Control",
  print    : "PrintScreen",
  del      : "Delete",
  pageup   : "PageUp",
  pagedown : "PageDown",
  numlock  : "NumLock",
  numpad_0 : "0",
  numpad_1 : "1",
  numpad_2 : "2",
  numpad_3 : "3",
  numpad_4 : "4",
  numpad_5 : "5",
  numpad_6 : "6",
  numpad_7 : "7",
  numpad_8 : "8",
  numpad_9 : "9",
  numpad_divide   : "/",
  numpad_multiply : "*",
  numpad_minus    : "-",
  numpad_plus     : "+"
};


/**
 * converts an old key name as found in @see(qx.event.type.KeyEvent.keys) to
 * the new keyIdentifier.
 *
 * @param keyName (string) old name of the key.
 * @return (string) corresponding keyIdentifier or "Unidentified" if a conversion was not possible
 */
qx.Proto.oldKeyNameToKeyIdentifier = function(keyName)
{
  var keyIdentifier = "Unidentified";

  if (this.isValidKeyIdentifier(keyName)) {
    return keyName;
  }

  if (keyName.length == 1 && keyName >= "a" && keyName <= "z") {
    return keyName.toUpperCase();
  }

  keyName = keyName.toLowerCase();

  // check wether its a valid old key name
  if (!qx.event.type.KeyEvent.keys[keyName]) {
    return "Unidentified";
  }

  var keyIdentifier = this._oldKeyNameToKeyIdentifierMap[keyName];
  if (keyIdentifier) {
    return keyIdentifier;
  } else {
    return qx.lang.String.toFirstUp(keyName);
  }
};









/*
---------------------------------------------------------------------------
  IDEALIZED-KEY-HANDLER
---------------------------------------------------------------------------
*/

/**
 * Key handler for an idealized browser.
 * Runs after the browser specific key handlers have normalized the key events.
 *
 * @param keyCode (string) keyboard code
 * @param charCode (string) character code
 * @param eventType (string) type of the event (keydown, keypress, keyup)
 * @param domEvent (Element) DomEvent
 */
qx.Proto._idealKeyHandler = function(keyCode, charCode, eventType, domEvent)
{
  if (!keyCode && !charCode) {
    return;
  }

  var keyIdentifier;

  // Use: keyCode
  if (keyCode)
  {
    keyIdentifier = this._keyCodeToIdentifier(keyCode);

    if (keyIdentifier != "Unidentified") {
      qx.event.handler.EventHandler.getInstance()._onkeyevent_post(domEvent, eventType, keyCode, charCode, keyIdentifier);
    }
  }

  // Use: charCode
  else
  {
    keyIdentifier = this._charCodeToIdentifier(charCode);

    if (keyIdentifier != "Unidentified")
    {
      qx.event.handler.EventHandler.getInstance()._onkeyevent_post(domEvent, "keypress", keyCode, charCode, keyIdentifier);
      qx.event.handler.EventHandler.getInstance()._onkeyevent_post(domEvent, "keyinput", keyCode, charCode, keyIdentifier);
    }
  }
};









/*
---------------------------------------------------------------------------
  BROWSER-SPECIFIC-KEY-HANDLER: MSHTML
---------------------------------------------------------------------------
*/

if (qx.sys.Client.getInstance().isMshtml())
{
  qx.Proto._lastUpDownType = {};

  qx.Proto._charCode2KeyCode =
  {
    13 : 13,
    27 : 27
  };

  qx.Proto._onkeyupdown = function(domEvent)
  {
    domEvent = window.event || domEvent;

    var keyCode = domEvent.keyCode;
    var charcode = 0;
    var type = domEvent.type;

    // Ignore the down in such sequences dp dp dp
    if (!(this._lastUpDownType[keyCode] == "keydown" && type == "keydown")) {
      this._idealKeyHandler(keyCode, charcode, type, domEvent);
    }

    // On non print-able character be sure to add a keypress event
    if (this._isNonPrintableKeyCode(keyCode) && type == "keydown") {
      this._idealKeyHandler(keyCode, charcode, "keypress", domEvent);
    }

    // Store last type
    this._lastUpDownType[keyCode] = type;
  };

  qx.Proto._onkeypress = function(domEvent)
  {
    domEvent = window.event || domEvent;

    if (this._charCode2KeyCode[domEvent.keyCode]) {
      this._idealKeyHandler(this._charCode2KeyCode[domEvent.keyCode], 0, domEvent.type, domEvent);
    } else {
      this._idealKeyHandler(0, domEvent.keyCode, domEvent.type, domEvent);
    }
  };
}






/*
---------------------------------------------------------------------------
  BROWSER-SPECIFIC-KEY-HANDLER: GECKO
---------------------------------------------------------------------------
*/

else if (qx.sys.Client.getInstance().isGecko())
{
  qx.Proto._lastUpDownType = {};

  qx.Proto._keyCodeFix = {
    12 : qx.Proto._identifierToKeyCode("NumLock")
  };

  /**
   * key handler for Gecko
   *
   * @param domEvent (Element) DomEvent
   */
  qx.Proto._onkeyupdown = qx.Proto._onkeypress = function(domEvent)
  {
    var keyCode = this._keyCodeFix[domEvent.keyCode] || domEvent.keyCode;
    var charCode = domEvent.charCode;
    var type = domEvent.type;

    // FF repeats under windows keydown events like IE
    if (qx.sys.Client.getInstance().runsOnWindows())
    {
      var keyIdentifier = keyCode ? this._keyCodeToIdentifier(keyCode) : this._charCodeToIdentifier(charCode)

      if (!(this._lastUpDownType[keyIdentifier] == "keypress" && type == "keydown")) {
        this._idealKeyHandler(keyCode, charCode, type, domEvent);
      }

      // Store last type
      this._lastUpDownType[keyIdentifier] = type;
    }

    // all other OSes
    else
    {
      this._idealKeyHandler(keyCode, charCode, type, domEvent);
    }
  };
}






/*
---------------------------------------------------------------------------
  BROWSER-SPECIFIC-KEY-HANDLER: WEBKIT
---------------------------------------------------------------------------
*/

else if (qx.sys.Client.getInstance().isWebkit())
{
  qx.Proto._charCode2KeyCode =
  {
    // Safari/Webkit Mappings
    63289 : qx.Proto._identifierToKeyCode("NumLock"),
    63276 : qx.Proto._identifierToKeyCode("PageUp"),
    63277 : qx.Proto._identifierToKeyCode("PageDown"),
    63275 : qx.Proto._identifierToKeyCode("End"),
    63273 : qx.Proto._identifierToKeyCode("Home"),
    63234 : qx.Proto._identifierToKeyCode("Left"),
    63232 : qx.Proto._identifierToKeyCode("Up"),
    63235 : qx.Proto._identifierToKeyCode("Right"),
    63233 : qx.Proto._identifierToKeyCode("Down"),
    63272 : qx.Proto._identifierToKeyCode("Delete"),
    63302 : qx.Proto._identifierToKeyCode("Insert"),
    63236 : qx.Proto._identifierToKeyCode("F1"),
    63237 : qx.Proto._identifierToKeyCode("F2"),
    63238 : qx.Proto._identifierToKeyCode("F3"),
    63239 : qx.Proto._identifierToKeyCode("F4"),
    63240 : qx.Proto._identifierToKeyCode("F5"),
    63241 : qx.Proto._identifierToKeyCode("F6"),
    63242 : qx.Proto._identifierToKeyCode("F7"),
    63243 : qx.Proto._identifierToKeyCode("F8"),
    63244 : qx.Proto._identifierToKeyCode("F9"),
    63245 : qx.Proto._identifierToKeyCode("F10"),
    63246 : qx.Proto._identifierToKeyCode("F11"),
    63247 : qx.Proto._identifierToKeyCode("F12"),
    63248 : qx.Proto._identifierToKeyCode("PrintScreen"),

        3 : qx.Proto._identifierToKeyCode("Enter"),
       12 : qx.Proto._identifierToKeyCode("NumLock"),
       13 : qx.Proto._identifierToKeyCode("Enter")
  };

  qx.Proto._onkeyupdown = qx.Proto._onkeypress = function(domEvent)
  {
    var keyCode = 0;
    var charCode = 0;
    var type = domEvent.type;

    // prevent Safari from sending key signals twice
    // This bug is fixed in recent Webkit builds so we need a revision check
    // see http://trac.mochikit.com/ticket/182 for details
    if (qx.sys.Client.getInstance().getVersion() < 420)
    {
      if (!this._lastCharCodeForType) {
        this._lastCharCodeForType = {};
      }

      var isSafariSpecialKey = this._lastCharCodeForType[type] > 63000;

      if (isSafariSpecialKey) {
        this._lastCharCodeForType[type] = null;
        return;
      }

      this._lastCharCodeForType[type] = domEvent.charCode;
    }

    if (type == "keyup" || type == "keydown") {
      keyCode = this._charCode2KeyCode[domEvent.charCode] || domEvent.keyCode;
    }
    else
    {
      if (this._charCode2KeyCode[domEvent.charCode]) {
        keyCode = this._charCode2KeyCode[domEvent.charCode];
      } else {
        charCode = domEvent.charCode;
      }
    }

    this._idealKeyHandler(keyCode, charCode, type, domEvent);
  };
}





/*
---------------------------------------------------------------------------
  BROWSER-SPECIFIC-KEY-HANDLER: OPERA
---------------------------------------------------------------------------
*/

else if (qx.sys.Client.getInstance().isOpera())
{
  qx.Proto._onkeyupdown = function(domEvent) {
    this._idealKeyHandler(domEvent.keyCode, 0, domEvent.type, domEvent);
  };

  qx.Proto._onkeypress = function(domEvent)
  {
    if (this._keyCodeToIdentifierMap[domEvent.keyCode]) {
      this._idealKeyHandler(domEvent.keyCode, 0, domEvent.type, domEvent);
    } else {
      this._idealKeyHandler(0, domEvent.keyCode, domEvent.type, domEvent);
    }
  };
}






/*
---------------------------------------------------------------------------
  DISPOSE
---------------------------------------------------------------------------
*/

/**
 * Destructor
 */
qx.Proto.dispose = function()
{
  if (this.getDisposed()) {
    return;
  }

  // Detach keyboard events
  this._detachEvents();

  return qx.core.Target.prototype.dispose.call(this);
};






/*
---------------------------------------------------------------------------
  DEFER SINGLETON INSTANCE
---------------------------------------------------------------------------
*/

/**
 * Singleton Instance Getter
 */
qx.Class.getInstance = qx.util.Return.returnInstance;
