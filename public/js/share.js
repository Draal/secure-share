"use strict";


function SecureShare()
{
  $("#languages_dropdown").find("a").each(function() {
    $(this).attr("href", $(this).attr("href") + window.location.hash);
  });

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

  var showError = function(code, message) {
    $("#progress_spiner").hide();
    var err = $("#error");
    if (message == "") {
      message = code;
    }
    err.find("p").html(message);
    err.show();
  }

  var getRandomBytes = function(length) {
    var array = new Uint8Array(length);
    var crypto = window.crypto || window.msCrypto;
    if (crypto) {
      console.log("Using window.crypto");
      crypto.getRandomValues(array);
    } else {
      console.log("Using math random");
      for (var i = 0; i < array.length; i++) {
        array[i] = Math.random() * 255;
      }
    }
    return array;
  }

  var encrypt = function(text, passphrase, attach) {
    var secret = {
      att: attach,
    };
    var encText;
    var encFile;
    var hash = ""
    if (passphrase == "") {
      var h = getRandomBytes(16);
      var passphrase  = window.btoa(String.fromCharCode.apply(null, h));
      encText = CryptoJS.AES.encrypt(text, passphrase, {
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7
      });
      h = CryptoJS.enc.Base64.parse(passphrase);
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
      $("#share_url").attr("share_id", data.id);
      $("#share_url").val(formLink(data.id, hash));
      var expires = new Date(data.expires*1000);
      $("#expires").html($("#expires").attr("label") + " " + expires);
      $("#link_div").show();
      $("#secret_div").hide();
      $("#progress_spiner").hide();
      $("#encrypt_button").prop('disabled', false);
    }).fail(function(data) {
      $("#progress_spiner").hide();
      $("#encrypt_button").prop('disabled', false);
      showError(data.responseJSON.error.code, data.responseJSON.error.message);
    });
  }
  var resetFile = function() {
    if ($("#t-file").attr("label")) {
      $("#t-file").html($("#t-file").attr("label"));
    }
    $("#source_file").val("");
  }
  $("#delete_button").click(function() {
    var id = $("#share_url").attr("share_id");
    $.ajax({
      url: baseLink() + "/g?id=" + id,
      type: "delete",
      dataType: "json"
    }).done(function(data) {
      $("#new_button").click();
    }).fail(function(data) {
      showError("Server error", "Couldn't delete share");
      return;
    });
  });

  $("#re_share_button").click(function() {
    $("#encrypt_button").click();
  });
  $("#new_button").click(function() {
    $("#link_div").hide();
    $("#secret_div").show();
    $("#passphrase").val("");
    $("#source").val("");
    $("#encrypt_button").prop('disabled', false);
    $("#progress_spiner").hide();
    resetFile();
  });


  var stringFileSize = function(size) {
    var s = size / (1024 * 1024);
    if (s > 1) {
      s = Math.floor(s)
      return s + "." + Math.round(((size - (s *(1024 * 1024)))  / (1024 * 1024)) *10) + "MB";
    } else {
      s = Math.floor(size / 1024);
      if (s < 99) {
        return s + "." + Math.round(((size - (s *1024))  / 1024) *10) + "KB";
      } else {
        return Math.round(size / 1024) + "KB";
      }
    }
  };
  $("#source_file").change(function() {
    var input = document.getElementById('source_file');
    if (input && input.files && input.files[0]) {
      var file = input.files[0];
      var sourceFile = $("#source_file");
      if (file.size > sourceFile.attr("maxsize")) {
        resetFile();
        showError(sourceFile.attr("maxsize-error-title"), sourceFile.attr("maxsize-error-message"));
        return;
      }
      if (!$("#t-file").attr("label")) {
        $("#t-file").attr("label", $("#t-file").html());
      }
      $("#t-file").html(file.name + " (" + stringFileSize(file.size) + ")");
      return
    } else {
      resetFile();
    }
  });

  $("#encrypt_button").click(function() {
    $("#error").hide();
    $(this).prop('disabled', true);
    $("#progress_spiner").show();
    var text = $("#source").val();
    var passphrase = $("#passphrase").val();
    var input = document.getElementById('source_file');
    if (input && input.files.length && input.files[0]) {
      var file = input.files[0];
      var sourceFile = $("#source_file");
      if (file.size > sourceFile.attr("maxsize")) {
        showError(sourceFile.attr("maxsize-error-title"), sourceFile.attr("maxsize-error-message"));
        $(this).prop('disabled', false);
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
    if (!text || !text.length) {
      $(this).prop('disabled', false);
      showError("Nothing to share", "Text or file should be provided");
      return;
    }
    encrypt(text, passphrase);
  });

  var dataToBlobURL = function(dataURL) {
    var contentType = contentType || '';
    var sliceSize = sliceSize || 512;
    var dataIdx = dataURL.indexOf(',');
    if (dataIdx == -1) {
      return null;
    }
    var header = dataURL.slice(5, dataIdx);
    var contentTypeIdx = header.indexOf(';')
    if (contentTypeIdx != -1) {
      contentType = header.slice(0, contentTypeIdx);
    }
    var b64Data = dataURL.slice(dataIdx+1);


    var binary = atob(b64Data);
    var byteArray = new Uint8Array(binary.length);
    for( var i = 0; i < binary.length; i++ ) {
      byteArray[i] = binary.charCodeAt(i)
    }
    var blob = new Blob([byteArray], {type: contentType});
    return URL.createObjectURL(blob);
  }
  var hashSalt;
  var hashPassPhrase;

  $("#show_button").click(function() {
    $("#error").hide();
    $(this).prop('disabled', true);
    $("#progress_spiner").show();
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
        var a = sf.find("a");
        if (d.n == "") {
          d.n == "download";
        }
        a.html(d.n);
        var blobUrl = dataToBlobURL(d.d);
        a.attr("href", blobUrl);
        a.attr("download", d.n);
        $("#source").val(d.t);
        sf.show();
      } else {
        $("#source").val(dec);
      }
      $("#secret_div").show();
      $("#progress_spiner").hide();
    }).fail(function(data){
      if (data.responseJSON.error.code == "Secure.Share.NotFound") {
        $("#new_button").show();
        $("#show_button").hide();
      }
      showError(data.responseJSON.error.code, data.responseJSON.error.message);
      $("#show_button").prop('disabled', false);
      $("#progress_spiner").hide();
    });
  })
  $(".new_share").click(function() {
    window.location.href = '/';
  });

  var wrongLink = function() {
    showError("Incorrect link", "Your link has wrong structure");
    $("#new_button").show();
    $("#show_button").hide();
  }
  if (window.location.pathname.match(/^\/s\//)) {
    if (window.location.hash.length == 0) {
      wrongLink();
      return;
    }
    var keyParts = base64KeyDecode(window.location.hash.substring(1));
    if (keyParts.sigBytes == 8) {
      hashSalt = keyParts;
      $("#passphrase_div").show();
    } else if (keyParts.sigBytes == 24) {
      var h = keyParts.toString(CryptoJS.enc.Hex);
      hashPassPhrase = CryptoJS.enc.Hex.parse(h.substring(0, 32)).toString(CryptoJS.enc.Base64);
      hashSalt = CryptoJS.enc.Hex.parse(h.substring(32));
      $("#show_button").show();
      $("#show_button").prop('disabled', false);
      $("#progress_spiner").hide();
    } else {
      wrongLink();
      return;
    }
  }

  $("#generate-secret").click(function() {
    $("#generator_secret_btn").show();
    $("#generator_passphrase_btn").hide();
    regenerate();
    $("#generator_div").show();
  });
  $("#generate-passphrase").click(function() {
    $("#generator_secret_btn").hide();
    $("#generator_passphrase_btn").show();
    regenerate();
    $("#generator_div").show();
  });

  var upperCase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  var lowerCase = "abcdefghijklmnopqrstuvwxyz";
  var digits = "0123456789";
  var dashes = "-_";
  var special = ";#$^<>{}[].()";
  var space = " ";
  var regenerate = function() {
    var set = [];
    if ($("#generator_upper").prop("checked")) {
      set = set.concat(upperCase.split(""));
    }
    if ($("#generator_lower").prop("checked")) {
      set = set.concat(lowerCase.split(""));
    }
    if ($("#generator_number").prop("checked")) {
      set = set.concat(digits.split(""));
    }
    if ($("#generator_dashes").prop("checked")) {
      set = set.concat(dashes.split(""));
    }
    if ($("#generator_special").prop("checked")) {
      set = set.concat(special.split(""));
    }
    if ($("#generator_spaces").prop("checked")) {
      set = set.concat([" "]);
    }
    var length = parseInt($("#generator_length").val());
    var password = "";
    var words = getRandomBytes(length);
    for (var i = 0; i < length; i++) {
      var l = set.length;
      if (i == 0 || i == length - 1) { // don't put spaces in front & back of the password
        l -= 1;
      }
      password += set[Math.abs(words[i]) % l];
    }
    var sets = {};
    var variants = 0;
    for (var i = 0; i < password.length; i++) {
      if (!sets["upperCase"] && upperCase.indexOf(password[i]) != -1) {
        sets["upperCase"] = 1;
        variants += upperCase.length;
      } else if (!sets["lowerCase"] && lowerCase.indexOf(password[i]) != -1) {
        sets["lowerCase"] = 1;
        variants += lowerCase.length;
      } else if (!sets["digits"] && digits.indexOf(password[i]) != -1) {
        sets["digits"] = 1;
        variants += digits.length;
      } else if (!sets["dashes"] && dashes.indexOf(password[i]) != -1) {
        sets["dashes"] = 1;
        variants += dashes.length;
      } else if (!sets["special"] && special.indexOf(password[i]) != -1) {
        sets["special"] = 1;
        variants += special.length;
      } else if (!sets["spaces"] && password[i] == " ") {
        sets["spaces"] = 1;
        variants += 1;
      }
    }
    var years = Math.pow(variants, length) / (34250000 * 3600 * 24 * 360);
    if (years > 400000) {
      years = 400000;
    }
    var quality = Math.round((years / 400000) * 100) + '%';
    $("#generator_quality").width(quality).find("div").html(quality);
    console.log(variants, length, years, quality);

    $("#generator_psw").val(password);
  };
  $("#generator_div").find("input[type=checkbox]").change(regenerate);
  $("#generator_length").change(regenerate);
  $("#generator_regen").click(regenerate);
  $("#generator_secret_btn").click(function() {
    $("#source").val($("#generator_psw").val());
    $("#generator_div").hide();
  });
  $("#generator_passphrase_btn").click(function() {
    $("#passphrase").val($("#generator_psw").val());
    $("#generator_div").hide();
  });
};

$(function() {
  console.log( "ready!" );
  window.SecureShare = new SecureShare();
});
