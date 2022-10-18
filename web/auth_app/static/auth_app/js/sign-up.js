console.log('sing-up')
$(function () {
  $('#signUpForm').submit(singUp);
});

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
