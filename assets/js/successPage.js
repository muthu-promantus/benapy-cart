$(document).ready(function () {
  getPaymentResponse();
});

// / Configuration
const SECRET_KEY = 'C136440B7D5AC99F4435126DAC84EB7D86F7EB3421EEB5ED66CCF25EFBE3C160';
const ivBytes = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
 
async function getPaymentResponse() {
  const queryString = window.location.search;
  console.log(queryString);

  const urlParams = new URLSearchParams(queryString);
  const response = urlParams.get('response')
  if (response != "") {
    console.log("responseresponseresponse",response);
    const decryptedRes = await decryptText(response, SECRET_KEY);
    console.log("Decrypted response:", decryptedRes);

    if (decryptedRes != "") {
      var data = JSON.parse(decryptedRes);
      console.log("data", data);
      $("#transactionId").html(data.transactionReference);
    }
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

async function decryptText(encryptedText, password) {
  if (!window.crypto || !window.crypto.subtle) {
    console.error('Web Crypto API not supported.');
    return;
  }
  try {
    
    const encryptedBytes = base64UrlDecode(encryptedText);
    const enc = new TextEncoder();
    const passwordBytes = enc.encode(password);
    const saltBytes = passwordBytes;

    const keyMaterial = await window.crypto.subtle.importKey(
      "raw",
      passwordBytes,
      { name: "PBKDF2" },
      false,
      ["deriveKey"]
    );

    const key = await window.crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: saltBytes,
        iterations: 65536,
        hash: "SHA-256"
      },
      keyMaterial,
      { name: "AES-CBC", length: 256 },
      false,
      ["decrypt"]
    );

    const decryptedBytes = await window.crypto.subtle.decrypt(
      {
        name: "AES-CBC",
        iv: ivBytes
      },
      key,
      encryptedBytes
    );

    const dec = new TextDecoder();
    const decryptedText = dec.decode(decryptedBytes);
    return decryptedText;
  } catch (err) {
    console.error('Error occurred during decryption:', err);
    throw err;
  }
}

function base64UrlDecode(base64Url) {
  const padding = '='.repeat((4 - base64Url.length % 4) % 4);
  const base64 = (base64Url + padding)
    .replace(/\-/g, '+')
    .replace(/_/g, '/');
  const rawData = window.atob(base64);
  const outputArray = new Uint8Array(rawData.length);
  for (let i = 0; i < rawData.length; ++i) {
    outputArray[i] = rawData.charCodeAt(i);
  }
  return outputArray;
}