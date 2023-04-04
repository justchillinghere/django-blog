console.log('sing-up')
$(function () {
  $('#signUpForm').submit(singUp);
  $('#googleSignUp').submit(getGoogleQuery);
});

const google_auth_endpoint = "https://accounts.google.com/o/oauth2/auth"

function singUp(e) {
  let form = $(this);
  e.preventDefault();
  $.ajax({
    url: form.attr("action"),
    type: "POST",
    dataType: "json",
    data: form.serialize(),
    success: function (data) {
      console.log("success", data)
    },
    error: function (data) {
      console.log('error', data)
    }

  })
}

function getGoogleQuery(e) {
    let form = $(this);
  e.preventDefault();
  $.ajax({
    url: form.attr("action"),
    type: "GET",
    success: function (data) {
      window.location.replace(google_auth_endpoint + '?' + $.param(data));
    },
    error: function (data) {
      console.log('query params error', data);
    }

  })
}
