// # Place all the behaviors and hooks related to the matching controller here.
// # All this logic will automatically be available in application.js.
// # You can use CoffeeScript in this file: http://jashkenas.github.com/coffee-script/



window.onload = function(){
var publicMenuLink = document.getElementById("publicMenuAnchor");

  publicMenuLink.addEventListener("click", function(event) {
    event.preventDefault();
    if (document.getElementById("publicMenu").style.display === "none"){
      document.getElementById("publicMenu").style.display = "block";
      document.getElementById("jsReaffirm").style.backgroundColor = "#dfdfdf";
    }
    else {
      document.getElementById("publicMenu").style.display = "none";
      document.getElementById("jsReaffirm").style.backgroundColor = "";
    }
  });
}