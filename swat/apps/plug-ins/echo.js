
// This function takes the main pane widget and jams its widget in the right
// sub-pane.

function _asyncEchoHandler(result, ex, id, paneWidget) {
	var replyTextArea = null;
	var refreshButton = null;
	var echoTextField = null;

	if (ex == null) {
		// We need to remove anything previously drawn in this area.
		paneWidget.removeAll();

		echoTextField = new qx.ui.form.TextField();
		echoTextField.setTop(0);
		echoTextField.setLeft(0);

		refreshButton = new qx.ui.form.Button("Refresh");
		refreshButton.setTop(0);
		refreshButton.setLeft(150);

		replyTextArea = new
			qx.ui.form.TextArea(result);
		replyTextArea.setWrap(true);
		replyTextArea.setWidth("100%");
		replyTextArea.setHeight("50%");
		replyTextArea.setTop(30);
		replyTextArea.setBottom(50);
		replyTextArea.setLeft(0);
		replyTextArea.setRight(20);
	} else {
		alert("Async(" + id + ") exception: " + ex);
	}
	paneWidget.add(replyTextArea);
	paneWidget.add(refreshButton);
	paneWidget.add(echoTextField);

	// Provide a handler for the button.
	with (refreshButton) {
		addEventListener("execute", function(e) {
			this.debug("executed: " + this.getLabel());
			this.debug("echoTextField.getValue(): " + echoTextField.getValue());
			_echoPlugInDisplay(paneWidget, echoTextField.getValue());
		});
	};
}

function _echoPlugInDisplay(paneWidget, echoText) {
	if (echoText == null) {
		echoText = "Hello World!";
	}

        var rpc = new qx.io.remote.Rpc();
        rpc.setTimeout(60000);
        rpc.setUrl("/services/");
        rpc.setServiceName("samba.adm");
        rpc.setCrossDomain(false);

        mycall = rpc.callAsync(
                function(result, ex, id) {
			_asyncEchoHandler(result, ex, id, paneWidget);
                },
                "echo",
		echoText);
}

function EchoPlugIn() {
	var o = new Object();
	o.display = _echoPlugInDisplay;
	return o;
}
