$(function() {
  const queryParams = new URLSearchParams(window.location.search);
  const home = "http://127.0.0.1:8008";
  $.ajax({
    url: location,
    type: "POST",
    dataType: "json",
    data: {
      "code": queryParams.get('code'),
      "state": queryParams.get('state')
    },
    success: function (data) {
      console.log("success", data)
      // window.location.replace(home);
    },
    error: function (data) {
      console.log('error', data)
    }

  })
});
