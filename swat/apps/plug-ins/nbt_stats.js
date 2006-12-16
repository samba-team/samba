
// This function takes the main pane widget and jams its widget in the right
// sub-pane.

function _asyncNBTStatsHandler(result, ex, id, paneWidget) {
	var statusTextArea = null;

	var listData = [];
	listData.push({
		server_status : { text : result.server_status },
		total_received : { text : result.total_received.toString() },
		total_sent : { text : result.total_sent.toString() },
		query_count : { text : result.query_count.toString() },
		release_count : { text : result.release_count.toString() },
		register_count : { text : result.register_count.toString() }
	});

	if (ex == null) {
		// We need to remove anything previously drawn in this area.
		paneWidget.removeAll();

		statusTextArea = new
			qx.ui.form.TextArea("Server Status: " +
				result.server_status.toString() + "\n" +
				"Total Received: " +
				result.total_received.toString() + "\n" +
				"Total Sent: " +
				result.total_sent.toString() + "\n" +
				"Query Count: " +
				result.query_count.toString() + "\n" +
				"Release Count: " +
				result.release_count.toString() + "\n" +
				"Register Count: " +
				result.register_count.toString() + "\n");
		statusTextArea.setWrap(true);
		statusTextArea.setWidth("100%");
		statusTextArea.setHeight("100%");
	} else {
		alert("Async(" + id + ") exception: " + ex);
	}
	paneWidget.add(statusTextArea);
}

function _NBTStatsPlugInDisplay(paneWidget) {
        var rpc = new qx.io.remote.Rpc();
        rpc.setTimeout(60000);
        rpc.setUrl("/services/");
        rpc.setServiceName("samba.adm");
        rpc.setCrossDomain(false);

        mycall = rpc.callAsync(
                function(result, ex, id) {
			_asyncNBTStatsHandler(result, ex, id, paneWidget);
                },
                "NBTPacketStats");
}

function NBTStatsPlugIn() {
	var o = new Object();
	o.display = _NBTStatsPlugInDisplay;
	return o;
}
