// 'use strict';

// const crypto = require('crypto');

/**
 * navbar toggle
 */

const overlay = document.querySelector("[data-overlay]");
const navOpenBtn = document.querySelector("[data-nav-open-btn]");
const navbar = document.querySelector("[data-navbar]");
const navCloseBtn = document.querySelector("[data-nav-close-btn]");

const navElems = [overlay, navOpenBtn, navCloseBtn];

for (let i = 0; i < navElems.length; i++) {
  navElems[i].addEventListener("click", function () {
    navbar.classList.toggle("active");
    overlay.classList.toggle("active");
  });
}

/**
 * header & go top btn active on page scroll
 */

const header = document.querySelector("[data-header]");
const goTopBtn = document.querySelector("[data-go-top]");

// Configuration
const SECRET_KEY = 'C136440B7D5AC99F4435126DAC84EB7D86F7EB3421EEB5ED66CCF25EFBE3C160';
const ivBytes = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);

window.addEventListener("scroll", function () {
  if (window.scrollY >= 80) {
    header.classList.add("active");
    goTopBtn.classList.add("active");
  } else {
    header.classList.remove("active");
    goTopBtn.classList.remove("active");
  }
});

$(document).ready(function () {
  $('.buyBtn').click(function () {
    $.LoadingOverlay("show");
    var amount = $(this).attr('data-value');
    const parameters = new URLSearchParams();

    parameters.append('grant_type', 'client_credentials');
    parameters.append('client_id', '6hlf403rn6t02lu0jgfn2jqf3u');
    parameters.append('client_secret', '1frbn3amvgcdbnef46ld4lcogeogikor1eme9ui9nvcebosq6gh5');

    fetch('https://bene-collect.auth.eu-west-2.amazoncognito.com/oauth2/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: parameters
    }).then(response => {
      if (!response.ok) {
        throw new Error('Network response was not ok');
      }
      return response.json();
    }).then(data => {
      console.log(data);
      if (data.access_token != "" && data.access_token != null && data.access_token != undefined) {
        payment(data.access_token, amount);
      }
    }).catch(error => {
      console.error('Error:', error);
      $.LoadingOverlay("hide");
    });
  });
});

async function payment(accessToken, amount) {
  if (accessToken != "" && amount != "") {
    var currentDate = new Date();
    var currentTimestamp = new Date().getTime();

    // Extract year, month, and day
    var year = currentDate.getFullYear();
    var month = (currentDate.getMonth() + 1).toString().padStart(2, '0'); // Adding 1 because months are zero-based
    var day = currentDate.getDate().toString().padStart(2, '0');

    // Format the date as YYYY-MM-DD
    var formattedDate = year + '-' + month + '-' + day;

    const jsonData = {
      "requestorTransactionId": currentTimestamp,
      "debtorName": "benepay",
      "debtorEmailId": "contact@benepay.io",
      "debtorMobileNumber": "8989898989",
      "collectionReferenceNumber": "API PAYMENT",
      "reasonForCollection": null,
      "initialDueAmount": amount,
      "initialDueDate": formattedDate,
      "charges": null,
      "reasonForCharges": "",
      "finalDueAmount": amount,
      "finalDueDate": formattedDate,
      "collectionAmountCurrency": "INR",
      "additionalComments": "API PAYMENT",
      "merchantLogoUrl": ""
    };

    // Encrypt the message
    const encryptedval = await encryptText(JSON.stringify(jsonData), SECRET_KEY);
    console.log('Encrypted value:', encryptedval);

    const options = {
      method: 'POST',
      headers: {
        "x-api-key": "m0OKyFypSF9Ndc8dLN8CW5QsKBWY0JoE7cYQNndb",
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${accessToken}`
      }
    };

    console.log("Payload", options);
    
    fetch(`https://uat-api-collect-payment.benepay.io/v1/realTimeRequestToPay/${encryptedval}`, options)
    // fetch(`https://ki6f28zlli.execute-api.eu-west-2.amazonaws.com/dev/v1/realTimeRequestToPay/${encryptedval}`, options)
      .then(response => {
        $.LoadingOverlay("hide");
        return response.json();
      })
      .then(data => {
        $.LoadingOverlay("hide");
        console.log("result", data);
    // Decrypt the incoming data
    if (data.message != "") {
      console.log("data.message",data.message);
          if (data.message) {
            window.location.href = data.message;
          }
      }
    })
      .catch(error => {
        $.LoadingOverlay("hide");
        console.error('Fetch error:', error);
      });
  }
}

async function encryptText(rawData, password) {
  try {
    // Convert raw data and password to byte arrays
    const ivBytes = new Uint8Array(16);

    const enc = new TextEncoder();
    const rawDataBytes = enc.encode(rawData);
    const passwordBytes = enc.encode(password);

    // Create salt from passwordBytes (to match Java code)
    const saltBytes = passwordBytes;

    // Derive key using PBKDF2
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
      ["encrypt"]
    );

    // Encrypt the data
    const encryptedBytes = await window.crypto.subtle.encrypt(
      {
        name: "AES-CBC",
        iv: ivBytes
      },
      key,
      rawDataBytes
    );

    // Encode the encrypted bytes to a base64 URL-safe string
    const encryptedText = base64UrlEncode(new Uint8Array(encryptedBytes));
    return encryptedText;
  } catch (err) {
    console.error('Error occurred during encryption:', err);
    throw err;
  }
}

async function decryptText(encryptedText, password) {
  try {
    const ivBytes = new Uint8Array(16);
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

function base64UrlEncode(arrayBuffer) {
  const base64String = btoa(String.fromCharCode.apply(null, arrayBuffer));
  return base64String.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
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
