function sign(input, password) {
	// salt should be Uint8Array or ArrayBuffer
	var saltBuffer = str2ab('e85c53e7f119d41fd7895cdc9d7bb9dd');

	// don't use naive approaches for converting text, otherwise international
	// characters won't have the correct byte sequences. Use TextEncoder when
	// available or otherwise use relevant polyfills
	var passphraseKey = str2ab(password);

	// You should firstly import your passphrase Uint8array into a CryptoKey
	return window.crypto.subtle.importKey(
	  'raw', 
	  passphraseKey, 
	  {name: 'PBKDF2'},
	  false, 
	  ['deriveBits', 'deriveKey']
	).then(function(key) {
	  return window.crypto.subtle.deriveKey(
		{ "name": 'PBKDF2',
		  "salt": saltBuffer,
		  // don't get too ambitious, or at least remember
		  // that low-power phones will access your app
		  "iterations": 100,
		  "hash": 'SHA-256'
		},
		key,
		{ name: "HMAC", hash: {name: "SHA-256"}},

		// Whether or not the key is extractable (less secure) or not (more secure)
		// when false, the key can only be passed as a web crypto object, not inspected
		true,

		// this web crypto object will only be allowed for these functions
		[ "sign" ]
	  )
	}).then(function (webKey) {
		return window.crypto.subtle.sign(
			{
				name: "HMAC"
			},
			webKey,
			str2ab(input) //ArrayBuffer of data we want to sign
		)
		.then(function(signature){
			return {signature: signature, key: webKey};
		})
		.catch(function(err){
			console.error(err);
		});
	});
}

function verify(input, key, signature) {
	return window.crypto.subtle.verify(
		{
			name: "HMAC",
		},
		key,
		hex2buf(signature), //ArrayBuffer of the signature
		str2ab(input) //ArrayBuffer of the data
	).then(function(isvalid){
		return isvalid;
	}).catch(function(err){
		console.error(err);
	});
}

function str2ab(str) {
  var buf = new ArrayBuffer(str.length*2); // 2 bytes for each char
  var bufView = new Uint16Array(buf);
  for (var i=0, strLen=str.length; i<strLen; i++) {
    bufView[i] = str.charCodeAt(i);
  }
  return buf;
}

function buf2hex(buffer) { // buffer is an ArrayBuffer
  return Array.prototype.map.call(new Uint8Array(buffer), x => ('00' + x.toString(16)).slice(-2)).join('');
}

function hex2buf(hex) {
	var buffer = new ArrayBuffer(hex.length / 2);
	var array = new Uint8Array(buffer);
	var k = 0;
	for (var i = 0; i < hex.length; i +=2 ) {
		array[k] = parseInt(hex[i] + hex[i+1], 16);
		k++;
	}
	
	return buffer;
}

function arrayToBuffer(array) {
	var buffer = new ArrayBuffer(array.length);
	var backingArray = new Uint8Array(buffer);
	
	for (var i = 0; i < array.length; i ++) {
		backingArray[i] = array[i];
	}
	return buffer;
}
function signTest() {
	var input = document.getElementById("input").value;
	var password = document.getElementById("password").value;
	sign(input, password).then(function(result) {
		window.crypto.subtle.exportKey("raw", result.key).then(function(key) {
			document.getElementById("signature").value = buf2hex(result.signature);
			document.getElementById("key").value = buf2hex(key);
			document.getElementById("verifyInput").value = input;
		});
	})
}

function verifyTest() {
	var signature = document.getElementById("signature").value;
	var rawKey = document.getElementById("key").value;
	var input = document.getElementById("verifyInput").value;
	var keyBuffer = hex2buf(rawKey);
	
	window.crypto.subtle.importKey(
		"raw",
		keyBuffer,
		{   //this is the algorithm options
			name: "HMAC",
			hash: {name: "SHA-256"}, //can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
		},
		true, //whether the key is extractable (i.e. can be used in exportKey)
		["verify"] //can be any combination of "sign" and "verify"
	).then(function(key) {
		verify(input, key, signature).then(function(valid) {
			alert("Verification success: " + valid);
		});
	});
}