// # Place all the behaviors and hooks related to the matching controller here.
// # All this logic will automatically be available in application.js.
// # You can use CoffeeScript in this file: http://jashkenas.github.com/coffee-script/

function formatSelectedText(change) {
    var sel, range;
    if (window.getSelection) {
      sel = window.getSelection();
      var replacementText = "<" + change + ">" + sel + "</" + change + ">"
        var activeElement = document.activeElement;
        if (activeElement.nodeName == "TEXTAREA") {
               var val = activeElement.value, start = activeElement.selectionStart, end = activeElement.selectionEnd;
               activeElement.value = val.slice(0, start) + replacementText + val.slice(end);
        } else if (activeElement.nodeName != "TEXTAREA") { 
        
        }
        
        else { //older IE
          if (sel.rangeCount) {
              range = sel.getRangeAt(0);
              range.deleteContents();
              range.insertNode(document.createTextNode(replacementText));
          } else {
              sel.deleteFromDocument();
          }
        }
    } else if (document.selection && document.selection.createRange) {
        range = document.selection.createRange();
        range.text = replacementText;
    }
}

function insertParagraphBreak() {
    var sel, range;
    if (window.getSelection) {
      sel = window.getSelection();
      var replacementText = "<br><br>"
        var activeElement = document.activeElement;
        if (activeElement.nodeName == "TEXTAREA") {
               var val = activeElement.value, start = activeElement.selectionStart, end = activeElement.selectionEnd;
               activeElement.value = val.slice(0, start) + replacementText + val.slice(end);
        }  else if (activeElement.nodeName == "INPUT" && activeElement.type == "text") { 
        
        }  else { //older IE
          if (sel.rangeCount) {
              range = sel.getRangeAt(0);
              range.deleteContents();
              range.insertNode(document.createTextNode(replacementText));
          } else {
              sel.deleteFromDocument();
          }
        }
    } else if (document.selection && document.selection.createRange) {
        range = document.selection.createRange();
        range.text = replacementText;
    }
}

// function formatSelectedText(change) {
//     var sel, range;
//     if (window.getSelection) {
//       sel = window.getSelection();
//       console.log(sel)
//       // var replacementText = "<" + change + ">" + sel + "</" + change + ">"
//
//       var replacementText = document.createElement("strong")
//       replacementText.innerHTML = sel
//
//         var activeElement = document.activeElement;
//         if (activeElement.getAttribute("id") == "bioEdit") {
//           activeElement.innerHTML = replacementText;
//
//               var val = activeElement.innerHTML, start = activeElement.selectionStart, end = activeElement.selectionEnd;
//                activeElement.innerHTML = val.slice(0, start) + replacementText + val.slice(end);
//         }
//
//         else { //older IE
//           if (sel.rangeCount) {
//               range = sel.getRangeAt(0);
//               range.deleteContents();
//               range.insertNode(document.createTextNode(replacementText));
//           } else {
//               sel.deleteFromDocument();
//           }
//         }
//     } else if (document.selection && document.selection.createRange) {
//         range = document.selection.createRange();
//         range.text = replacementText;
//     }
// }
//
