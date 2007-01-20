/*
 * Copyright:
 *   (C) 2006 by Derrell Lipman
 *       All rights reserved
 *
 * License:
 *   LGPL 2.1: http://creativecommons.org/licenses/LGPL/2.1/
 */

/**
 * Swat LDB Browser class finite state machine
 */
qx.OO.defineClass("swat.module.ldbbrowse.Fsm", swat.main.AbstractModuleFsm,
function()
{
  swat.main.AbstractModuleFsm.call(this);
});


qx.Proto.buildFsm = function(module)
{
  var fsm = module.fsm;
  var _this = this;

  /*
   * State: Idle
   *
   * Actions upon entry
   *   - if returning from RPC, display the result
   *
   * Transition on:
   *   "execute" on search button
   *   "treeopenwhileempty" on tree
   *   "changeselection" on tree
   */
  var state = new qx.util.fsm.State(
    "State_Idle",
    {
      "onentry" :
        function(fsm, event)
        {
          // Did we just return from an RPC request?
          if (fsm.getPreviousState() == "State_AwaitRpcResult")
          {
            // Yup.  Display the result.  We need to get the request object
            var rpcRequest = _this.popRpcRequest();

            // Display the result
            var gui = swat.module.ldbbrowse.Gui.getInstance();

            // Did we get a Resource Not Found error?  We'll get this after a
            // session timeout, because the request is retried but can't
            // succeed because the database has been closed by the session
            // timing out.
            var result = rpcRequest.getUserData("result");
            var origins = swat.main.AbstractModuleFsm.JsonRpc_Origin;
            var serverErrors = swat.main.AbstractModuleFsm.JsonRpc_ServerError;
            if (result.type == "failed" &&
                result.data.origin == origins.Server &&
                result.data.code == serverErrors.ResourceError)
            {
              // Yup.  Re-open the database
              var dbName = fsm.getObject("dbName");
              dbName.dispatchEvent(new qx.event.type.Event("changeSelection"),
                                   true);
            }
            else
            {
              // Otherwise, display the result
              gui.displayData(module, rpcRequest);
            }

            // Dispose of the request
            rpcRequest.request.dispose();
            rpcRequest.request = null;
          }
        },

      "events" :
        {
          // If the search button is activated, issue a seacrh request
          "execute" :
          {
            "search" :
              "Transition_Idle_to_AwaitRpcResult_via_search"
          },

          // If a previously unexpanded tree node is expanded, issue a request
          // to retrieve its contents.
          "treeOpenWhileEmpty":
          {
            "tree" :
              "Transition_Idle_to_AwaitRpcResult_via_tree_open"
          },

          // If the selection changes, issue a request to retrieve contents to
          // populate the attribute/value table.
          "changeSelection":
          {
            "tree:manager" :
              "Transition_Idle_to_AwaitRpcResult_via_tree_selection_changed",

            "dbName":
              "Transition_Idle_to_AwaitRpcResult_via_db_changed"
          }
        }
    });

  // Replace the initial Idle state with this one
  fsm.replaceState(state, true);
  
  /*
   * Transition: Idle to AwaitRpcResult
   *
   * Cause: "execute" on search button
   *
   * Action:
   *  Issue a search request
   */
  var trans = new qx.util.fsm.Transition(
    "Transition_Idle_to_AwaitRpcResult_via_search",
    {
      "nextState" :
        "State_AwaitRpcResult",

      "ontransition" :
        function(fsm, event)
        {
          // Get our module descriptor
          var module = fsm.getObject("swat.main.module");

          // Retrieve the database handle
          var dbHandle = module.dbHandle;

          // Retrieve the search expression
          var searchExpr = fsm.getObject("searchExpr").getValue();

          // Retrieve the base DN
          var baseDN = fsm.getObject("baseDN").getValue();

          // Retrieve the selected scope
          var scope = fsm.getObject("scope").getValue();

          // We want all attributes
          var attributes = [ "*" ];

          // Issue a Search call
          var request = _this.callRpc(fsm,
                                      "samba.ldb",
                                      "search",
                                      [
                                       dbHandle,
                                       searchExpr,
                                       baseDN,
                                       scope,
                                       attributes
                                      ]);

          // When we get the result, we'll need to know what type of request
          // we made.
          request.setUserData("requestType", "search");
        }
    });
  state.addTransition(trans);

  /*
   * Transition: Idle to AwaitRpcResult
   *
   * Cause: "treeOpenWhileEmpty" on tree
   *
   * Action:
   *  Issue a search request
   */
  var trans = new qx.util.fsm.Transition(
    "Transition_Idle_to_AwaitRpcResult_via_tree_open",
    {
      "nextState" :
        "State_AwaitRpcResult",

      "ontransition" :
        function(fsm, event)
        {
          var parent = event.getData();
          var hierarchy = parent.getHierarchy(new Array());

          parent.debug("Requesting children...");

          // Strip off the root node
          hierarchy.shift();

          // Get the tree object
          var tree = fsm.getObject("tree");

          // Determine the children.  Differs depending on root or otherwise
          var attributes;
          var scope;
          var baseDN;
            
          // If parent is the root...
          if (parent == tree)
          {
            // ... then we want the defaultNamingContext, ...
            attributes = [ "defaultNamingContext" ];

            // ... and we want only base scope
            scope = "base";

            // ... and an empty base DN
            baseDN = "";
          }
          else
          {
            // otherwise, retrieve the DN,
            attributes = [ "dn" ];

            // ... and we want one level of scope
            scope = "one";

            // ... and base DN is the parent
            baseDN = hierarchy.reverse().join(",");
          }

          // Build the search expression
          var searchExpr = "(objectclass=*)";

          // Get our module descriptor
          var module = fsm.getObject("swat.main.module");

          // Retrieve the database handle
          var dbHandle = module.dbHandle;

          // Issue a Get Statistics call
          var request = _this.callRpc(fsm,
                                      "samba.ldb",
                                      "search",
                                      [
                                       dbHandle,
                                       searchExpr,
                                       baseDN,
                                       scope,
                                       attributes
                                      ]);

          // When we get the result, we'll need to know what type of request
          // we made.
          request.setUserData("requestType", "tree_open");

          // We'll also need some of our parameters
          request.setUserData("parent", parent);
          request.setUserData("attributes", attributes);
        }
    });
  state.addTransition(trans);

  /*
   * Transition: Idle to AwaitRpcResult
   *
   * Cause: "changeSelection" on tree
   *
   * Action:
   *  Issue a search request
   */
  var trans = new qx.util.fsm.Transition(
    "Transition_Idle_to_AwaitRpcResult_via_tree_selection_changed",
    {
      "nextState" :
        "State_AwaitRpcResult",

      "predicate" :
        function(fsm, event)
        {
          var element = event.getData()[0];
          var hierarchy = element.getHierarchy(new Array());

          // Strip off the root node
          hierarchy.shift();

          // Get the tree object
          var tree = fsm.getObject("tree");

          // If element is the root...
          if (element == tree)
          {
            // ... then just clear out the attribute/value table.
            var tableModel = fsm.getObject("tableModel:browse");
            tableModel.setData([]);
            return null;        // don't search additional transitionis
          }

          return true;
        },

      "ontransition" :
        function(fsm, event)
        {
          var element = event.getData()[0];
          var hierarchy = element.getHierarchy(new Array());

          // Strip off the root node
          hierarchy.shift();

          // Get the tree object
          var tree = fsm.getObject("tree");

          // Determine the children.  Differs depending on root or otherwise
          var attributes;
          var scope;
          var baseDN;
            
          // We want all attributes
          attributes = [ "*" ];

          // We want the attributes only for the current element
          scope = "base";

          // Base DN is the current element
          baseDN = hierarchy.reverse().join(",");

          // Build the search expression
          var searchExpr = "(objectclass=*)";

          // Get our module descriptor
          var module = fsm.getObject("swat.main.module");

          // Retrieve the database handle
          var dbHandle = module.dbHandle;

          // Issue a Get Statistics call
          var request = _this.callRpc(fsm,
                                      "samba.ldb",
                                      "search",
                                      [
                                       dbHandle,
                                       searchExpr,
                                       baseDN,
                                       scope,
                                       attributes
                                      ]);

          // When we get the result, we'll need to know what type of request
          // we made.
          request.setUserData("requestType", "tree_selection_changed");
        }
    });
  state.addTransition(trans);

  /*
   * Transition: Idle to AwaitRpcResult
   *
   * Cause: "changeSelection" on dbName
   *
   * Action:
   *  Issue a connect request
   */
  var trans = new qx.util.fsm.Transition(
    "Transition_Idle_to_AwaitRpcResult_via_db_changed",
    {
      "nextState" :
        "State_AwaitRpcResult",

      "ontransition" :
        function(fsm, event)
        {
          // Obtain the name of the database to be connected to
          var dbName = fsm.getObject("dbName").getValue();

          // Issue a Get Statistics call
          var request = _this.callRpc(fsm,
                                      "samba.ldb",
                                      "connect",
                                      [ dbName ]);

          // When we get the result, we'll need to know what type of request
          // we made.
          request.setUserData("requestType", "database_name_changed");
        }
    });
  state.addTransition(trans);

  // Add the AwaitRpcResult state and all of its transitions
  this.addAwaitRpcResultState(module);
};


/**
 * Singleton Instance Getter
 */
qx.Class.getInstance = qx.util.Return.returnInstance;
