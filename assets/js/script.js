/**
 * navbar toggle
*/
const overlay = document.querySelector("[data-overlay]");
const navOpenBtn = document.querySelector("[data-nav-open-btn]");
const navbar = document.querySelector("[data-navbar]");
const navCloseBtn = document.querySelector("[data-nav-close-btn]");
const navElems = [overlay, navOpenBtn, navCloseBtn];
// const baseURL = "http://localhost:8080";
// const baseURL = "https://uat-api-collect-payment.benepay.io";
const baseURL = "https://ki6f28zlli.execute-api.eu-west-2.amazonaws.com/dev";

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
const SECRET_KEY = 'B0C617CB176A18EE545D6BBF8F6336EEB7E897EBD145807834C1ED89394D25E6';
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
        parameters.append('client_id', '4ilu1ehe0rlg5t52ac51trpog3');
        parameters.append('client_secret', 'dqqvoj5q9fs175fb4g3hseudm3u2ldidef54s9udtnd3uses90r');

        //Request for get access token
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
            console.log("OAuth2 access token : ", data);

            if (data.access_token != "" && data.access_token != null && data.access_token != undefined) {
                encryptRequestPayload(data.access_token, amount);
            }
        }).catch(error => {
            console.error('Error:', error);
            $.LoadingOverlay("hide");
        });
    });
});

//Encrypting the request payload
async function encryptRequestPayload(accessToken, amount) {
    try {
        if (accessToken != "" && amount != "") {
            var currentDate = new Date();
            var currentTimestamp = new Date().getTime();

            // Extract year, month, and day
            var year = currentDate.getFullYear();
            var month = (currentDate.getMonth() + 1).toString().padStart(2, '0'); // Adding 1 because months are zero-based
            var day = currentDate.getDate().toString().padStart(2, '0');

            // Format the date as YYYY-MM-DD
            var formattedDate = year + '-' + month + '-' + day;

            const requestBody = JSON.stringify({
                "requestToPay": `{\n\"collectionAmountCurrency\": \"INR\", \n\"collectionReferenceNumber\": \"1dff0def-80b6-402c-bf2c-8b82f01b3ec8\", \n\"debtorEmailId\": \"ragavan@promantusinc.com\", \n\"debtorName\":\"Ragavan\",  \n\"finalDueAmount\": \"${amount}\", \n\"requestorTransactionId\": \"${currentTimestamp}\", \n\"debtorMobileNumber\": \"+91-9876543210\", \n\"reasonForCollection\": \"OnlinePayment\",  \n\"initialDueAmount\": \"${amount}\", \n\"initialDueDate\": \"${formattedDate}\", \n\"charges\": \"0\",  \n\"reasonForCharges\": \"NA\",  \n\"finalDueDate\": \"${formattedDate}\",  \n\"additionalComments\": \"Add Comments\", \n\"payVia\" : [\"CC\"]\n, \n\"allowPartialPayments\" : false\n}`,
                "encKey": `${SECRET_KEY}`
            });

            console.log("Request body before encryption - ", requestBody);

            const requestOptions = {
                method: "POST",
                headers: {
                    "x-api-key": "m0OKyFypSF9Ndc8dLN8CW5QsKBWY0JoE7cYQNndb",
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${accessToken}`
                },
                body: requestBody,
            };

            fetch(baseURL + "/v2/encryptRequest", requestOptions)
                .then((response) => response.text())
                .then((result) => {
                    console.log("Encrypted Request - ", result);
                    initiatePayment(result, accessToken);
                })
                .catch((error) => console.error("Error in get the encrypted request", error));
        }
        else {
            console.error("Faild to encrypt the request, access token or amount is empty");
        }
    } catch (error) {
        console.error("Error in request encryption : ", error);
    }
}

document.addEventListener("DOMContentLoaded", function () {
    const donateBtn = document.getElementById("donateNow");
    if (donateBtn) {
        donateBtn.addEventListener("click", function () {
            console.log("inside donate");

            const parameters = new URLSearchParams();
            parameters.append('grant_type', 'client_credentials');
            parameters.append('client_id', '4ilu1ehe0rlg5t52ac51trpog3');
            parameters.append('client_secret', 'dqqvoj5q9fs175fb4g3hseudm3u2ldidef54s9udtnd3uses90r');

            fetch('https://bene-collect.auth.eu-west-2.amazoncognito.com/oauth2/token', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: parameters
            })
            .then(response => {
                if (!response.ok) throw new Error('Failed to fetch token');
                return response.json();
            })
            .then(data => {
                console.log("data",data);
                
                console.log("OAuth2 access token:", data.access_token);
                if (data.access_token) {
                    const redirectUrl = `https://d2adxrnqqwuy1x.cloudfront.net/payment-request-initiate/teslanova?token=${(data.access_token)}`;
                    console.log("redirectUrl",redirectUrl);
                    
                    window.location.href = redirectUrl;
                } else {
                    console.error("Token is empty or invalid.");
                }
            })
            .catch(error => console.error('Error:', error));
        });
    } else {
        console.error("Element with ID 'donateNow' not found in the DOM.");
    }
});


//Making new payment request
async function initiatePayment(encryptedRequest, accessToken) {
    if (encryptedRequest != "") {
        
        const requestBody = JSON.stringify({
            "encryptedData": `${encryptedRequest}`
        });

        const options = {
            method: "POST",
            headers: {
                "x-api-key": "m0OKyFypSF9Ndc8dLN8CW5QsKBWY0JoE7cYQNndb",
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${accessToken}`
            },
            body: requestBody
        };

        fetch(baseURL + "/v1/realTimeRequestToPay", options)
            .then(response => {
                $.LoadingOverlay("hide");
                return response.json();
            })
            .then(data => {
                $.LoadingOverlay("hide");
                console.log("initiated payment response", data);

                // Decrypt the incoming data
                if (data.message != "") {
                    console.log("data.message", data.message);
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
        const ivBytes = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
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
        const ivBytes = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);

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