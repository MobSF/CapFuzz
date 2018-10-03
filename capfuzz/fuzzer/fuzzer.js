$( document ).ready(function() {
		// Store Active Fuzzers state
  		var storage = window.localStorage;
  		$("input[type='checkbox']").change(function(){
  			if (this.id.startsWith("fuzz_")){
  				if (!this.checked) {
  					storage.setItem(this.id, "off");
  				} else{
  					storage.setItem(this.id, "on");
  				}
  			}
  		});
});

function fuzzers(){
  	//Restore Active Fuzzers State
  	var storage = window.localStorage;
	var active_fuzzers = $("input[type='checkbox']").map(function(){
		if (this.id.startsWith("fuzz_")){
	    	return this.id
	    }
	}).get()
	for (var i = 0; i < active_fuzzers.length; i++) {
		if (storage.getItem(active_fuzzers[i]) === "off"){
			$('#' + active_fuzzers[i]).prop('checked', false);
	
		}
	}
    $("#fuzz").modal("show");
}


function start_fuzz(){
    //Start Fuzzing
    var storage = window.localStorage;
    var include_scope = JSON.parse(storage.getItem("scope"));
    var exclude_scope = JSON.parse(storage.getItem("exclude_scope"));

    var exclude_url_match = storage.getItem("exclude_url_match") === "off" ? "off" : "on";
    var exclude_extensions = storage.getItem("exclude_extensions") === "off" ? "off" : "on";
    var exclude_response_code = storage.getItem("exclude_response_code") === "off" ? "off" : "on";

    var api_login = "";
    var api_register = "";
    var api_pin = "";
    var login_o = JSON.parse(storage.getItem("api_login"));
    var pin_o = JSON.parse(storage.getItem("api_pin"));
    var reg_o = JSON.parse(storage.getItem("api_register"));
    if (login_o) {api_login = login_o.id}
    if (pin_o) {api_pin = pin_o.id}
    if (reg_o) {api_register = reg_o.id}

    var active_fuzzers = [];
    
    
    var all_fuzzers = $("input[type='checkbox']").map(function(){
    if (this.id.startsWith("fuzz_")){
        return this.id
        }
    }).get()
   
    for (var i in all_fuzzers){
        if (storage.getItem(all_fuzzers[i]) !== "off"){
          active_fuzzers.push(all_fuzzers[i]);
        }
    }
      $.ajax({
          type: 'POST',
          url: "/start_fuzz",
          data : {
              api_login: api_login,
              api_pin: api_pin,
              api_register: api_register,
              include_scope: include_scope,
              exclude_scope: exclude_scope,
              active_fuzzers: active_fuzzers,
              exclude_url_match: exclude_url_match,
              exclude_extensions: exclude_extensions,
              exclude_response_code: exclude_response_code,
              project:  $('meta[name=project]').attr("content"),
          },
          headers: {
              'X-Operation': 'Start-Fuzz',
          },
          error: function(xhr, status, error) {
            console.log("[ERROR]")
            console.log(status);
            console.log(xhr.responseText);
          },
          success: function(resp) { 
          	$.growl({ title: "Fuzzer", message: "Fuzzing Started!", style: "notice"});
            console.log(resp);
            $('#fuzz_progress').text("");
            $("#progress").modal("show");
            if (location.protocol === "https:") {
                new_uri = "wss:";
            } else {
                new_uri = "ws:";
            }
            new_uri += "//" + location.host + "/progress"

            var ws = new WebSocket(new_uri);
            ws.onopen = function() {
               ws.send("CONNECT");
            };
            ws.onmessage = function (evt) {
               //alert(evt.data);
               $('#fuzz_progress').append("\n" + html_encode(evt.data));
               $('#fuzz_progress').scrollTop($('#fuzz_progress')[0].scrollHeight);

               if (evt.data === "Fuzzing Completed!"){
                  setTimeout(
                    function() {
                      location.href="/report/" + $('meta[name=project]').attr("content");
                    }, 5000);
               }
            };
            
          }
        });
  }