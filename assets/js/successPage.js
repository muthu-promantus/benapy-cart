$(document).ready(function () {
  getPaymentResponse();
});

function getPaymentResponse() {
  const queryString = window.location.search;
  console.log(queryString);

  const urlParams = new URLSearchParams(queryString);
  const response = urlParams.get('response')
  var decodedRes = atob(response);

  if (decodedRes != "") {
    var data = JSON.parse(decodedRes);
    $("#transactionId").html(data.transactionReference)
  }
}

function redirectHome() {
  var pathName = window.location.pathname

  if (pathName != "") {
    var name = pathName.split('/');

    var redirectUrl = window.location.origin;

    if (name[1] && name[1] != "" && name[1] != "success-page.html") {
      redirectUrl += "/" + name[1];
    }

    window.location.href = redirectUrl;
  }
}