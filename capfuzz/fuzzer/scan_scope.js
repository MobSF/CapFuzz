function add_inc_scope(value) {
  // Add to Scope - Context menu
  var storage = window.localStorage;
  if (storage.getItem("scope")){
    var data = JSON.parse(storage.getItem("scope"));
    if (data.indexOf(value) === -1) {
      data.push(value);
      storage.setItem("scope", JSON.stringify(data));
      $.growl({ title: "Scope", message: "اضافه کردن به محدوده!", style: "notice"});
    }
  } else {
    var new_data = [];
    new_data.push(value);
    storage.setItem("scope", JSON.stringify(new_data));
    $.growl({ title: "Scope", message: "اضافه کردن به محدوده!", style: "notice"});
  }
}
function remove_inc_scope(value) {
  // Remove from Scope - Context menu
  var storage = window.localStorage;
  if (storage.getItem("scope") && storage.getItem("scope").length > 2){
    var data = JSON.parse(storage.getItem("scope"));
    if (data.indexOf(value) !== -1) {
       data = data.filter(e => e !== value);
      storage.setItem("scope", JSON.stringify(data));
      $.growl({ title: "Scope", message: "حذف از محدوده!", style: "error"});
    }
  }
}

function remove_from_inc_model(iden){
  // Scan Includes Tab Scope
  remove_inc_scope($(iden).data('url'));
  $(iden).parents('tr').remove();
  if ($('#add_s tr').length === 1) {
     $('#add_s').hide();
     $('#sp_txt').text("همه چیز در حوزه است.");
  }
}

function exclude_scope (value){
  //Exclude from Scan Scope
  var storage = window.localStorage;
  if (storage.getItem("exclude_scope")){
    var data = JSON.parse(storage.getItem("exclude_scope"));
    if (data.indexOf(value) === -1) {
      data.push(value);
      storage.setItem("exclude_scope", JSON.stringify(data));
      $.growl({ title: "Scope", message: "خارج کردن از محدوده!", style: "warning"});
    }
  } else {
    var new_data = [];
    new_data.push(value);
    storage.setItem("exclude_scope", JSON.stringify(new_data));
    $.growl({ title: "Scope", message: "خارج کردن از محدوده!", style: "warning"});
  }
}

function remove_exc_scope(value) {
  // Remove from Exclude Scope
  var storage = window.localStorage;
  if (storage.getItem("exclude_scope") && storage.getItem("exclude_scope").length > 2){
    var data = JSON.parse(storage.getItem("exclude_scope"));
    if (data.indexOf(value) !== -1) {
       data = data.filter(e => e !== value);
      storage.setItem("exclude_scope", JSON.stringify(data));
      $.growl({ title: "Scope", message: "حذف کردن محدوده های خارج شده!", style: "error"});
    }
  }
}

function remove_from_exc_model(iden){
  // Scan Exclude Tab Scope
  remove_exc_scope($(iden).data('url'));
  $(iden).parents('tr').remove();
  if ($('#exc_s tr').length === 1) {
     $('#exc_s').hide();
  }
}

function scope_options() {
	// Scan Oprions
    var storage = window.localStorage;
    // For Scan Include Tab
    if (storage.getItem("scope") && storage.getItem("scope").length > 2){
      $('#add_s').show();
      $('#sp_txt').text("");
      var data = JSON.parse(storage.getItem("scope"));
      $("#add_s").find("tr:not(:first)").remove();
      for (var i = 0; i < data.length; i++) {
            $('#add_s tr:last').after('<tr><td>' + (i + 1) + '</td><td>' + data[i] + '</td><td><button type="button" data-url="'+ data[i] +'" class="btn btn-danger btn-xs" onclick="remove_from_inc_model(this)">X</button></td></tr>');
      } 
    } else {
         $('#add_s').hide();
         $('#sp_txt').text("همه چیز در حوزه است.");
    }

    //Excluded from Scope
    if (storage.getItem("exclude_scope") && storage.getItem("exclude_scope").length > 2){
      $('#exc_s').show();
      var data = JSON.parse(storage.getItem("exclude_scope"));
      $("#exc_s").find("tr:not(:first)").remove();
      for (var i = 0; i < data.length; i++) {
            $('#exc_s tr:last').after('<tr><td>' + (i + 1) + '</td><td>' + data[i] + '</td><td><button type="button" data-url="'+ data[i] +'" class="btn btn-danger btn-xs" onclick="remove_from_exc_model(this)">X</button></td></tr>');
      } 
    } else {
         $('#exc_s').hide();
    }

    //Excluded by default
	if (storage.getItem("exclude_url_match") === "off"){
		$('#exclude_url_match').prop('checked', false);
	}
	if (storage.getItem("exclude_extensions") === "off"){
		$('#exclude_extensions').prop('checked', false);
	}
	if (storage.getItem("exclude_response_code") === "off"){
		$('#exclude_response_code').prop('checked', false);
	}

    //Finally show modal
    $("#scan_scope").modal("show");
}



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



  $( document ).ready(function() {
  		var storage = window.localStorage;
      $("input[type='checkbox']").change(function(){
        if (this.id.startsWith("exclude_")){
          if (!this.checked) {
            storage.setItem(this.id, "off");
          } else{
            storage.setItem(this.id, "on");
          }
        }
      });
  	});
