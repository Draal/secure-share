"use strict";


function SecureShare()
{
  var urlHashFy = function(text) {
    return text.replace(/\+/g, '-').replace(/\//g, '_').replace(/\=+$/g, '');
  };
  var base64KeyDecode = function(key) {
    var k = key.replace(/\-/g, '+').replace(/_/g, '/') + "=";
    return CryptoJS.enc.Base64.parse(k);
  }
  var baseLink = function() {
    var link = window.location.protocol + "//" + window.location.hostname;
    if (window.location.port != "") {
      link += ":" + window.location.port;
    }
    return link;
  }
  var formLink = function(id, hash) {
    return baseLink() + "/s/"+id+"#" + hash
  }

  var showError = function(title, message) {
    var err = $("#error");
    err.find("h3").html(title);
    err.find("p").html(message);
    err.show();
  }

  var encrypt = function(text, passphrase, attach) {
    var secret = {
      att: attach,
    };
    var encText;
    var encFile;
    var hash = ""
    if (passphrase == "") {
      var h = CryptoJS.lib.WordArray.random(16);
      var passphrase  = h.toString(CryptoJS.enc.Base64);
      encText = CryptoJS.AES.encrypt(text, passphrase, {
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7
      });
      h.concat(encText.salt);
      hash = urlHashFy(h.toString(CryptoJS.enc.Base64));
    } else {
      encText = CryptoJS.AES.encrypt(text, passphrase, {
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7
      });
      hash = urlHashFy(encText.salt.toString(CryptoJS.enc.Base64));
      secret.passHash = CryptoJS.HmacSHA256(passphrase, hash).toString(CryptoJS.enc.Base64);
    }
    secret.data = encText.ciphertext.toString(CryptoJS.enc.Base64);
    $.ajax({
      url: baseLink() + "/p",
      type: "post",
      data: secret,
      dataType: "json"
    }).done(function(data) {
      $("#share_url").val(formLink(data.id, hash));
      $("#link_div").show();
      $("#secret_div").hide();
    });
  }
  $("#re_share_button").click(function() {
    $("#encrypt_button").click();
  });
  $("#new_button").click(function() {
    $("#link_div").hide();
    $("#secret_div").show();
    $("#passphrase").val("");
    $("#source").val("");
    $("#source_file").val("");
  });

  $("#encrypt_button").click(function() {
    $("#error").hide();
    var text = $("#source").val();
    var passphrase = $("#passphrase").val();
    var input = document.getElementById('source_file');
    if (input && input.files && input.files[0]) {
      var file = input.files[0];
      if (file.size > 1024 * 128) { // 128 kb max file size
        showError("Maximum file size exceed", "Maximum file size should not exceed 128kb");
        return;
      }
      var fr = new FileReader();
      fr.onload = function() {
        var f = {
          t: text,
          n: file.name,
          d: fr.result
        }
        encrypt(JSON.stringify(f), passphrase, true);
      };
      fr.readAsDataURL(file);
      return;
    }
    if (!text) {
      showError("Nothing to share", "Text or file should be provided");
      return;
    }
    encrypt(text, passphrase);
  });

  var hashSalt;
  var hashPassPhrase;

  $("#show_button").click(function() {
    $("#error").hide();
    var secret = {};
    var passphrase = "";
    if (hashPassPhrase) {
      passphrase = hashPassPhrase;
    } else {
      passphrase = $("#passphrase").val();
      var hash = urlHashFy(hashSalt.toString(CryptoJS.enc.Base64));
      secret.passHash = CryptoJS.HmacSHA256(passphrase, hash).toString(CryptoJS.enc.Base64);
    }
    var id = window.location.pathname.split("/")
    secret.id = id[id.length-1]
    $.ajax({
      url: baseLink() + "/g",
      type: "post",
      data: secret,
      dataType: "json"
    }).done(function(data) {
      var dec = CryptoJS.enc.Utf8.stringify(CryptoJS.AES.decrypt(CryptoJS.lib.CipherParams.create({
        ciphertext: CryptoJS.enc.Base64.parse(data.data), salt: hashSalt
        }), passphrase, {
            mode: CryptoJS.mode.CBC,
            padding: CryptoJS.pad.Pkcs7
        }));

      $("#first_div").hide();
      if (data.attach) {
        var d = JSON.parse(dec);
        var sf = $("#secret_file");
        sf.show();
        var a = sf.find("a");
        a.html("Download: " + d.n);
        a.attr("href", d.d);
        a.attr("download", d.n);
        $("#source").val(d.t);
      } else {
        $("#source").val(dec);
      }
      $("#secret_div").show();
    }).fail(function(data){
      showError(data.responseJSON.error.code, data.responseJSON.error.message);
    });
  })
  $(".new_share").click(function() {
    window.location.href = '/';
  });
  if (window.location.pathname.match(/^\/s\//) && window.location.hash.length > 0) {
    var keyParts = base64KeyDecode(window.location.hash.substring(1));
    if (keyParts.sigBytes == 8) {
      hashSalt = keyParts;
      $("#passphrase_div").show();
    } else if (keyParts.sigBytes == 24) {
      var h = keyParts.toString(CryptoJS.enc.Hex);
      hashPassPhrase = CryptoJS.enc.Hex.parse(h.substring(0, 32)).toString(CryptoJS.enc.Base64);
      hashSalt = CryptoJS.enc.Hex.parse(h.substring(32));
      $("#show_button").show();
    } else {
      showError("Incorrect link", "Your link has wrong structure");
      return;
    }
  }
};

$(function() {
  console.log( "ready!" );
  window.SecureShare = new SecureShare();
});
