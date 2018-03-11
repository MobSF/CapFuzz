 function save_apis_ctxmenu(storage_key, id, text){
    var storage = window.localStorage;
    storage.setItem(storage_key, JSON.stringify({"txt": text, "id": id}));
    $.growl({ title: "API Checks", message: "Changes Saved!", style: "notice"});
  }

  function remove_api(api_key){
    var storage = window.localStorage;
    storage.removeItem(api_key);
    $("#" + api_key).text("");
  }

  function api_checks(){

    var storage = window.localStorage;
    //Restore State
    if (storage.getItem("api_login") && storage.getItem("api_login").length > 2){
      var login_o = JSON.parse(storage.getItem("api_login"))
      if (login_o) { $("#api_login").text(login_o.txt); }
    }
    if (storage.getItem("api_pin") && storage.getItem("api_pin").length > 2){
      var pin_o = JSON.parse(storage.getItem("api_pin"))
      if (pin_o) { $("#api_pin").text(pin_o.txt); }
    }
    if (storage.getItem("api_register") && storage.getItem("api_register").length > 2){
      var reg_o = JSON.parse(storage.getItem("api_register"))
      if (reg_o) { $("#api_register").text(reg_o.txt); }
    }
    $("#api_checks").modal("show");
  }