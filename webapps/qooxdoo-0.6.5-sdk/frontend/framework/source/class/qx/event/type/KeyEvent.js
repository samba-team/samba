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

/* ************************************************************************

#module(ui_core)

************************************************************************ */

/**
 * A key event instance contains all data for each occured key event
 *
 * @param vType {String} event type (keydown, keypress, keyinput, keyup)
 * @param vDomEvent {Element} DOM event object
 * @param vDomTarget {Element} target element of the DOM event
 * @param vTarget
 * @param vOriginalTarget
 * @param vKeyCode {Integer} emulated key code for compatibility with older qoodoo applications
 * @param vCharCode {Integer} char code from the "keypress" event
 * @param vKeyIdentifier {String} the key identifier
 */
qx.OO.defineClass("qx.event.type.KeyEvent", qx.event.type.DomEvent,
function(vType, vDomEvent, vDomTarget, vTarget, vOriginalTarget, vKeyCode, vCharCode, vKeyIdentifier)
{
  qx.event.type.DomEvent.call(this, vType, vDomEvent, vDomTarget, vTarget, vOriginalTarget);

  this.setKeyCode(vKeyCode);
  this.setCharCode(vCharCode);
  this.setKeyIdentifier(vKeyIdentifier);
});

/**
 * Legacy keycode
 * @deprecated Will be removed with qooxdoo 0.7
 */
qx.OO.addFastProperty({ name : "keyCode", setOnlyOnce : true, noCompute : true });

/**
 * Unicode number of the pressed character.
 * Only valid in "keyinput" events
 */
qx.OO.addFastProperty({ name : "charCode", setOnlyOnce : true, noCompute : true });

/**
 * Identifier of the pressed key. This property is modeled after the <em>KeyboardEvent.keyIdentifier</em> property
 * of the W3C DOM 3 event specification (http://www.w3.org/TR/2003/NOTE-DOM-Level-3-Events-20031107/events.html#Events-KeyboardEvent-keyIdentifier).
 *
 * It is not valid in "keyinput" events"
 *
 * Printable keys are represented by a unicode string, non-printable keys have one of the following
 * values:
 * <br>
 * <table>
 * <tr><th>Backspace</th><td>The Backspace (Back) key.</td></tr>
 * <tr><th>Tab</th><td>The Horizontal Tabulation (Tab) key.</td></tr>
 * <tr><th>Space</th><td>The Space (Spacebar) key.</td></tr>
 * <tr><th>Enter</th><td>The Enter key. Note: This key identifier is also used for the Return (Macintosh numpad) key.</td></tr>
 * <tr><th>Shift</th><td>The Shift key.</td></tr>
 * <tr><th>Control</th><td>The Control (Ctrl) key.</td></tr>
 * <tr><th>Alt</th><td>The Alt (Menu) key.</td></tr>
 * <tr><th>CapsLock</th><td>The CapsLock key</td></tr>
 * <tr><th>Meta</th><td>The Meta key. (Apple Meta and Windows key)</td></tr>
 * <tr><th>Escape</th><td>The Escape (Esc) key.</td></tr>
 * <tr><th>Left</th><td>The Left Arrow key.</td></tr>
 * <tr><th>Up</th><td>The Up Arrow key.</td></tr>
 * <tr><th>Right</th><td>The Right Arrow key.</td></tr>
 * <tr><th>Down</th><td>The Down Arrow key.</td></tr>
 * <tr><th>PageUp</th><td>The Page Up key.</td></tr>
 * <tr><th>PageDown</th><td>The Page Down (Next) key.</td></tr>
 * <tr><th>End</th><td>The End key.</td></tr>
 * <tr><th>Home</th><td>The Home key.</td></tr>
 * <tr><th>Insert</th><td>The Insert (Ins) key. (Does not fire in Opera/Win)</td></tr>
 * <tr><th>Delete</th><td>The Delete (Del) Key.</td></tr>
 * <tr><th>F1</th><td>The F1 key.</td></tr>
 * <tr><th>F2</th><td>The F2 key.</td></tr>
 * <tr><th>F3</th><td>The F3 key.</td></tr>
 * <tr><th>F4</th><td>The F4 key.</td></tr>
 * <tr><th>F5</th><td>The F5 key.</td></tr>
 * <tr><th>F6</th><td>The F6 key.</td></tr>
 * <tr><th>F7</th><td>The F7 key.</td></tr>
 * <tr><th>F8</th><td>The F8 key.</td></tr>
 * <tr><th>F9</th><td>The F9 key.</td></tr>
 * <tr><th>F10</th><td>The F10 key.</td></tr>
 * <tr><th>F11</th><td>The F11 key.</td></tr>
 * <tr><th>F12</th><td>The F12 key.</td></tr>
 * <tr><th>NumLock</th><td>The Num Lock key.</td></tr>
 * <tr><th>PrintScreen</th><td>The Print Screen (PrintScrn, SnapShot) key.</td></tr>
 * <tr><th>Scroll</th><td>The scroll lock key</td></tr>
 * <tr><th>Pause</th><td>The pause/break key</td></tr>
 * <tr><th>Win</th><td>The Windows Logo key</td></tr>
 * <tr><th>Apps</th><td>The Application key (Windows Context Menu)</td></tr>
 * </table>
 */
qx.OO.addFastProperty({ name : "keyIdentifier", setOnlyOnce : true, noCompute : true });








/* ************************************************************************
   Class data, properties and methods
************************************************************************ */

/*
---------------------------------------------------------------------------
  CLASS PROPERTIES AND METHODS
---------------------------------------------------------------------------
*/

/**
 * Mapping of the old key identifiers to the key codes
 * @deprecated
 */
qx.event.type.KeyEvent.keys =
{
  esc : 27,
  enter : 13,
  tab : 9,
  space : 32,

  up : 38,
  down : 40,
  left : 37,
  right : 39,

  shift : 16,
  ctrl : 17,
  alt : 18,

  f1 : 112,
  f2 : 113,
  f3 : 114,
  f4 : 115,
  f5 : 116,
  f6 : 117,
  f7 : 118,
  f8 : 119,
  f9 : 120,
  f10 : 121,
  f11 : 122,
  f12 : 123,

  print : 124,

  del : 46,
  backspace : 8,
  insert : 45,
  home : 36,
  end : 35,

  pageup : 33,
  pagedown : 34,

  numlock : 144,

  numpad_0 : 96,
  numpad_1 : 97,
  numpad_2 : 98,
  numpad_3 : 99,
  numpad_4 : 100,
  numpad_5 : 101,
  numpad_6 : 102,
  numpad_7 : 103,
  numpad_8 : 104,
  numpad_9 : 105,

  numpad_divide : 111,
  numpad_multiply : 106,
  numpad_minus : 109,
  numpad_plus : 107
};

// create dynamic codes copy
(function() {
  qx.event.type.KeyEvent.codes = {};
  for (var i in qx.event.type.KeyEvent.keys) {
    qx.event.type.KeyEvent.codes[qx.event.type.KeyEvent.keys[i]] = i;
  }
})();
