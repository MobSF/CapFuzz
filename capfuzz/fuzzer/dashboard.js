
  //Flow Selection Event Handler
  $('#jstree_div').on("changed.jstree", function (e, data) {
    selected_nodes = data.selected
    for (var i = 0; i < selected_nodes.length; i++) {
        if (selected_nodes[i].startsWith("http")){
        console.log("Domain: " + selected_nodes[i]);
        } else {
          get_flow_meta(selected_nodes[i]);
        }
    }
  });

  function get_flow_meta(flow_id){
      //Returns Request Response Details
      $.ajax({
          type: 'POST',
          url: "/flow_meta",
          headers: {
              'X-Flow-ID': flow_id,
          },
          data: {
              'project': $('meta[name=project]').attr("content"),
          },
          error: function(xhr, status, error) {
            console.log("[ERROR]")
            console.log(status);
            console.log(xhr.responseText);
          },
          success: function(flow) { 
            //Request Meta
            var request = flow.request.method + " " + flow.request.url + " " + flow.request.http_version + "\n"
            for (var key in flow.request.headers) {
                request += key + ": " +  flow.request.headers[key] + "\n"; 
            }
            if (flow.request.content){
                request += "\n\n" + flow.request.content
            }
            $("#request").val(request);
            //Response Meta
            var response = flow.response.http_version + " " + flow.response.status_code + " " + flow.response.reason + "\n"
            for (var key in flow.response.headers) {
                response += key + ": " +  flow.response.headers[key] + "\n"; 
            }
            if (flow.response.content){
                response += "\n\n" + flow.response.content
            }
            $("#response").val(response);
          }
        });
  }
  $( document ).ready(function() {
    // Tree View and Context menu
    $(function () { $('#jstree_div').jstree({
    "contextmenu":{         
    "items": function($node) {
        var tree = $("#tree").jstree(true);
        return {
            "Add to Scan Scope": {
                "separator_before": false,
                "separator_after": false,
                "label": "Add to Scan Scope",
                "action": function (data) { 
                    var inst = $.jstree.reference(data.reference),
                    obj = inst.is_selected(data.reference) ? inst.get_selected(true) : [inst.get_node(data.reference)];
                    for (var item in obj){
                      if (obj[item].id.startsWith("http")){
                          // id is domain
                          new_scope = obj[item].id;
                      } else {
                        new_scope = obj[item].data.url;
                      }
                      add_inc_scope(new_scope);
                    }
                }
            },
            "Remove from Scan Scope": {
                "separator_before": false,
                "separator_after": false,
                "label": "Remove from Scan Scope",
                "action": function (data) { 
                    var inst = $.jstree.reference(data.reference),
                    obj = inst.is_selected(data.reference) ? inst.get_selected(true) : [inst.get_node(data.reference)];
                    for (var item in obj){
                      if (obj[item].id.startsWith("http")){
                          // id is domain
                          del_scope = obj[item].id;
                      } else {
                        del_scope = obj[item].data.url;
                      }
                      remove_inc_scope(del_scope);
                    }
                }
            },
            "Exclude from Scope": {
                "separator_before": true,
                "separator_after": false,
                "label": "Exclude from Scope",
                "action": function (data) { 
                    var inst = $.jstree.reference(data.reference),
                    obj = inst.is_selected(data.reference) ? inst.get_selected(true) : [inst.get_node(data.reference)];
                    for (var item in obj){
                      if (obj[item].id.startsWith("http")){
                          // id is domain
                          new_exclude = obj[item].id;
                      } else {
                        new_exclude = obj[item].data.url;
                      }
                      exclude_scope(new_exclude);
                    }
                }
            },
            "API Checks": {
                "separator_before": true,
                "separator_after": false,
                "label": "API Checks",
                "action": false,
                "submenu": {
                      "Mark as Login API": {
                          "separator_before": false,
                          "separator_after": false,
                          "label": "Mark as Login API",
                          "action": function (data) { 
                            //Select only one even if multiple are selected by user
                            var inst = $.jstree.reference(data.reference),
                            obj = inst.is_selected(data.reference) ? inst.get_selected(true) : [inst.get_node(data.reference)];
                            if (obj[0].id.startsWith("http") === false ){
                              save_apis_ctxmenu("api_login", obj[0].id, obj[0].text);
                            }
                          }
                      },
                      "Mark as Login Pin API": {
                          "separator_before": false,
                          "icon": false,
                          "separator_after": false,
                          "label": "Mark as Login Pin API",
                          "action": function (data) { 
                            //Select only one even if multiple are selected by user
                            var inst = $.jstree.reference(data.reference),
                            obj = inst.is_selected(data.reference) ? inst.get_selected(true) : [inst.get_node(data.reference)];
                            if (obj[0].id.startsWith("http") === false ){
                              save_apis_ctxmenu("api_pin", obj[0].id, obj[0].text);
                            }
                          }
                      },
                      "Mark as Register API": {
                          "separator_before": false,
                          "icon": false,
                          "separator_after": false,
                          "label": "Mark as Register API",
                          "action": function (data) { 
                            //Select only one even if multiple are selected by user
                            var inst = $.jstree.reference(data.reference),
                            obj = inst.is_selected(data.reference) ? inst.get_selected(true) : [inst.get_node(data.reference)];
                            if (obj[0].id.startsWith("http") === false ){
                              save_apis_ctxmenu("api_register", obj[0].id, obj[0].text);
                            }
                          }
                      }
                  },
            },
          };
        }
    },
    "plugins" : [
      "contextmenu", "search",
      "state", "wholerow"
    ]
    });});
  });


  function load_project(){
    uri = $("#project_name option:selected").val();
    localStorage.clear();
    location.href = "/dashboard/" + uri;
  }
  function show_projects(){
    $("#projects").modal("show");
  }
  