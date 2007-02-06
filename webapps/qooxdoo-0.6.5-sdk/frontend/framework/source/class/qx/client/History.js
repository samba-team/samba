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

#require(qx.manager.object.AliasManager)
#embed(qx.static/history/historyHelper.html)

************************************************************************ */

/**
 * A helper for using the browser history in JavaScript Applications without
 * reloading the main page.
 * <p>
 * Adds entries to the browser history and fires a "request" event when one of
 * the entries was requested by the user (e.g. by clicking on the back button).
 * </p>
 *
 * @event request {qx.event.type.DataEvent} Fired when the user moved in the
 *        history. The data property of the event holds the command, which was
 *        passed to {@link #addToHistory}.
 */
qx.OO.defineClass("qx.client.History", qx.core.Target,
function() {
  qx.core.Target.call(this);

  this._pageFlag = true;
});


/**
 * Initializes the History. This method has to called by applications using this
 * class once during initialization. Subsequent calls have no (negative) effect.
 */
qx.Proto.init = function() {
  if (this._iframe == null) {
    this._iframe = document.createElement("iframe");
    this._iframe.style.visibility = "hidden";
    document.body.appendChild(this._iframe);
  }
}


/**
 * Adds an entry to the browser history.
 *
 * @param command {String} a string representing the old state of the
 *        application. This command will be delivered in the data property of
 *        the "request" event.
 * @param newTitle {String ? null} the page title to set after the history entry
 *        is done. This title should represent the new state of the application.
 */
qx.Proto.addToHistory = function(command, newTitle) {
  if (command == this._currentCommand) {
    document.title = newTitle;
  } else {
    if (this._iframe == null) {
      throw new Error("You have to call init first!");
    }

    this._pageFlag = !this._pageFlag;
    this._currentCommand = command;
    this._newTitle = newTitle;

    // NOTE: We need the command attribute to enforce a loading of the page
    //       (Otherwise we don't get an onload event).
    //       The browser will still cache commands loaded once.
    //       Without the onload-problem anchors would work, too.
    //       (Anchors would have the advantage that the helper is only loaded once)
    this._iframe.src = this.getSetting("helperFile") + "?c=" + command;
  }
}


/**
 * Event handler. Called when the history helper page was loaded.
 *
 * @param location {Map} the location property of the window object of the
 *        helper page.
 */
qx.Proto._onHistoryLoad = function(location)
{
  try {
    var equalsPos = location.search.indexOf("=");
    var command = location.search.substring(equalsPos + 1);

    if (this._newTitle) {
      document.title = this._newTitle;
      this._newTitle = null;
    }

    if (command != this._currentCommand) {
      this._currentCommand = command;

      this.createDispatchDataEvent("request", command);
    }
  } catch (exc) {
    this.error("Handling history load failed", exc);
  }

  qx.ui.core.Widget.flushGlobalQueues();
}


/** The URL to the helper page. */
qx.Settings.setDefault("helperFile", qx.Settings.getValueOfClass("qx.manager.object.AliasManager", "staticUri") + "/history/historyHelper.html");






/*
---------------------------------------------------------------------------
  DEFER SINGLETON INSTANCE
---------------------------------------------------------------------------
*/

/**
 * Singleton Instance Getter
 */
qx.Class.getInstance = qx.lang.Function.returnInstance;
