$(document).ready(function () {
  getPaymentResponse();
});

function getPaymentResponse() {
  const queryString = window.location.search;
  console.log(queryString);

  const urlParams = new URLSearchParams(queryString);
  const response = urlParams.get('response')
  var decodedRes = atob(response);

  if(decodedRes != ""){
    var data = JSON.parse(decodedRes);
    $("#transactionId").html(data.transactionReference)
  }
}