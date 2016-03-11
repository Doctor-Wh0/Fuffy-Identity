
               $(function () {
                   
                   $("#bagiy").click(function () {
                       if (document.documentElement.clientWidth > 767) {
                           if ($("#menu-bar").hasClass("col-lg-3") && $("#menu-bar").hasClass("col-md-3") && $("#menu-bar").hasClass("col-sm-3")) {
                               $("#menu-bar").removeClass("col-lg-3 col-md-3 col-sm-3");
                               $("#menu-bar").addClass("menu-bar-seek");
                               $("#main").removeClass("col-lg-13 col-md-13 col-sm-13 col-xs-16");
                               $("#main").addClass("col-lg-16 col-md-16 col-sm-16 col-xs-16");
                               $("#bagiy").addClass("button-turnOf");
                               $("#button1").removeClass("button-turnOf");
                               $("#button1").addClass("button-turnOn");
                           }
                       }
                       else {

                           $(".menu1").css("display", "none");
                       }
                   });

                   $("#button1").click(function () {
                       if (document.documentElement.clientWidth > 767) {
                           $("#menu-bar").removeClass("menu-bar-seek");
                           $("#menu-bar").addClass("col-lg-3 col-md-3 col-sm-3");
                           $("#main").removeClass("col-lg-16 col-md-16 col-sm-16 col-xs-16");
                           $("#main").addClass("col-lg-13 col-md-13 col-sm-13 col-xs-16");
                           $("#bagiy").removeClass("button-turnOf");
                           $("#bagiy").addClass("button-turnOn");
                           $("#button1").removeClass("button-turnOn");
                           $("#button1").addClass("button-turnOf");
                       }
                       else {
                           //$("#tesla").addClass("menu11");
                           $("#button1").removeClass("button-turnOn");
                           $("#button1").addClass("button-turnOf");
                           $(".menu1").css("display", "block");
                       }
                   });
                    

                    
               })
         