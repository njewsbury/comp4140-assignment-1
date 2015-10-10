/*global document, Math, Object */
/*eslint-env browser */
/*eslint no-console: 0 */

/**
	COMP 4140 Crypto Assignment One
	N. Jewsbury #7614402
	-------------------------------

	This is the main script for A1.
	It contains the following "Classes"
	1. Simple logger - allows customizing the
		console logs when running. Currently set to
		error so it's not spammed when running.

	2.

*/


/* DEFINE THE NAMESPACE */
var ca = {};
ca.njewsbury = {};
ca.njewsbury.crypto = {};

/**
	Simple Logger Proxy.
	<p>
	Versus brining in external libraries, (ie log4javascript)
	I opted to created just a simple lightweight javascript
	logger proxy to control the amount of information logged
	to the dev console while running.

	Mimics other logging libraries more commonly used.

*/
ca.njewsbury.crypto.Logger = (function () {
	'use strict';
	return {
		log: function(level, obj) {
			if (ca.njewsbury.crypto.Logger.ACTIVE_LOG_LEVEL
				===
				ca.njewsbury.crypto.Logger.DEBUG
			) {
				console.log(obj);
			} else if(ca.njewsbury.crypto.Logger.ACTIVE_LOG_LEVEL
				===
				ca.njewsbury.crypto.Logger.INFO
			) {
				if (level === ca.njewsbury.crypto.Logger.DEBUG) {
					return;
				}
				console.log(obj);
			} else if(ca.njewsbury.crypto.Logger.ACTIVE_LOG_LEVEL
				===
				ca.njewsbury.crypto.Logger.ERROR
			) {
				if (level === ca.njewsbury.crypto.Logger.ERROR) {
					console.log(obj);
				}
			}
		}
	};
}());

ca.njewsbury.crypto.Logger.INFO = 'info';
ca.njewsbury.crypto.Logger.DEBUG = 'debug';
ca.njewsbury.crypto.Logger.ERROR = 'error';
ca.njewsbury.crypto.Logger.ACTIVE_LOG_LEVEL = ca.njewsbury.crypto.Logger.ERROR;

/**
	English Language Definitions
	<p>
	Language to be used during encrypting/decrypting.
	- English
*/
ca.njewsbury.crypto.english = {};
ca.njewsbury.crypto.english.Alphabet = {
	'e': {'avgFreq' : 12.7},
	't': {'avgFreq' : 9.1},
	'a': {'avgFreq' : 8.2},
	'i': {'avgFreq' : 7.0},
	'n': {'avgFreq' : 6.7},
	's': {'avgFreq' : 6.3},
	'h': {'avgFreq' : 6.1},
	'r': {'avgFreq' : 6.0},
	'd': {'avgFreq' : 4.3},
	'l': {'avgFreq' : 4.0},
	'u': {'avgFreq' : 2.8},
	'c': {'avgFreq' : 2.8},
	'm': {'avgFreq' : 2.4},
	'w': {'avgFreq' : 2.4},
	'f': {'avgFreq' : 2.2},
	'g': {'avgFreq' : 2.0},
	'y': {'avgFreq' : 2.0},
	'p': {'avgFreq' : 1.9},
	'o': {'avgFreq' : 1.5},
	'b': {'avgFreq' : 1.5},
	'v': {'avgFreq' : 1.0},
	'k': {'avgFreq' : 0.8},
	'j': {'avgFreq' : 0.2},
	'x': {'avgFreq' : 0.2},
	'q': {'avgFreq' : 0.1},
	'z': {'avgFreq' : 0.1}
};
// Java script objects don't guarantee order.
ca.njewsbury.crypto.english.SortedAlphabet = [
	'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
	'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'
];
ca.njewsbury.crypto.english.SumOfSquares = 0.065;

/**
	'MAIN' Class for Crypto A1.
	<p>
	This is the main worker class for Assignment one.
	It loops through all the available PLAIN-TEXT INPUT
	and encrypts it using the defined cipher (Only shift & vigenere are options).
	The encrypted plain text is put into the CIPHER-TEXT INPUT section.
	Once all plain text is encrypted, it loops through the CIPHER-TEXT INPUT
	and tries to crack all the cipher text using the ciphers 'break' function.

	Lastly, it compares the cracked plain text to the (if provided) plain text
	to see if it was successful. If the plain text matches the cracked plain text
	the background colour is set to green (else red).

*/
ca.njewsbury.crypto.Converter = (function () {
	'use strict';

	var PLAIN_TEXT_INPUT = 'textarea.plain-text-input',
	CIPHER_TEXT_INPUT = 'textarea.cipher-text-input',
	PLAIN_TEXT_OUTPUT = 'textarea.plain-text-output',
	MATCHER_PREFIX = '[data-matcher="',
	MATCHER_SUFFIX = '"]',
	LOGGER = ca.njewsbury.crypto.Logger;

	function findMatchingTextArea(type, identifier) {
		if (!type || !identifier) {
			throw new Error('Invalid matcher input.');
		}
		var matcher,
		matchString = type + MATCHER_PREFIX + identifier + MATCHER_SUFFIX;
		matcher = document.querySelectorAll(matchString);
		if (!matcher) {
			throw new Error('Unable to find valid match.');
		}
		if (matcher.length !== 1) {
			LOGGER.log(LOGGER.ERROR, matcher);
			throw new Error('Matcher returned invalid results!');
		}
		return matcher[0];
	}

	function getEncryptionScheme(type) {
		if (type === 'shift') {
			return ca.njewsbury.crypto.ShiftCipher;
		} else if (type === 'vigenere') {
			return ca.njewsbury.crypto.VigenereCipher;
		}
		throw new Error('Unable to determine encryption type: ' + type);
	}

	function encryptPlainText(plainText, cipherType, key) {
		var encryption = getEncryptionScheme(cipherType),
		cipherText = encryption.encryptPlainText(plainText, key);
		return cipherText;
	}

	function decryptCipherText(cipherText, cipherType) {
		var decryption = getEncryptionScheme(cipherType),
		crackedCipher = decryption.breakEncryption(cipherText);
		return crackedCipher;
	}

	return {
		convertAllPlainTextInput : function () {
			var plainText = document.querySelectorAll(PLAIN_TEXT_INPUT),
			cipherInput,
			i,
			length;

			// CONVERT ALL PLAINTEXT INPUT
			for (i = 0, length = plainText.length; i < length; i++) {
				if (!plainText[i].value) {
					// This input doesn't exist.
					continue;
				}
				try {
					cipherInput = findMatchingTextArea(CIPHER_TEXT_INPUT, plainText[i].dataset.matcher);
				} catch (Error) {
					LOGGER.log(LOGGER.ERROR, Error);
					continue;
				}
				cipherInput.value = encryptPlainText(
						plainText[i].value,
						plainText[i].dataset.cipher,
						plainText[i].dataset.key);
			}
		},
		convertAllCipherTextInput : function () {
			var cipherText = document.querySelectorAll(CIPHER_TEXT_INPUT),
			crackedCipher,
			plainOutput,
			i,
			length;

			// CONVERT ALL CIPHERTEXT INPUT
			for (i = 0, length = cipherText.length; i < length; i++) {
				if (!cipherText[i].value) {
					// This input doesn't exist.
					continue;
				}
				try {
					plainOutput = findMatchingTextArea(PLAIN_TEXT_OUTPUT, cipherText[i].dataset.matcher);
				} catch (Error) {
					LOGGER.log(LOGGER.ERROR, Error);
					continue;
				}
				crackedCipher = decryptCipherText(
						cipherText[i].value,
						cipherText[i].dataset.cipher);
				console.log(crackedCipher);
				plainOutput.value = crackedCipher[0];
				plainOutput.parentElement.getElementsByTagName('label')[0].innerHTML = 'Key: ' + crackedCipher[1];
			}
		},
		comparePlainTextInputToOutput : function () {
			var decrypted = document.querySelectorAll(PLAIN_TEXT_OUTPUT),
				plainTextInput,
				plainText,
				length,
				i;
			for (i = 0, length = decrypted.length; i < length; i++) {
				if (!decrypted[i].value) {
					// This input doesn't exist.
					continue;
				}
				try {
					plainTextInput = findMatchingTextArea(PLAIN_TEXT_INPUT, decrypted[i].dataset.matcher);
				} catch (Error) {
					LOGGER.log(LOGGER.ERROR, Error);
					continue;
				}
				plainText = plainTextInput.value;
				if (!plainText || !plainText.trim()) {
					continue;
				}
				plainText = plainText.toLowerCase().replace(/\s/g, '');

				if (plainText == decrypted[i].value) {
					decrypted[i].className = decrypted[i].className + ' success';
				} else {
					decrypted[i].className = decrypted[i].className + ' fail';
				}
			}
		},
		doAllEncryptDecrypt: function() {
			this.convertAllPlainTextInput();
			LOGGER.log(LOGGER.DEBUG, 'Completed converting all plain-text input.');
			this.convertAllCipherTextInput();
			LOGGER.log(LOGGER.DEBUG, 'Completed converting all cipher-text input.');
			this.comparePlainTextInputToOutput();
			LOGGER.log(LOGGER.DEBUG, 'Compared all output plain-text to known plain text.');
		}
	};
}
	());

function documentMain() {
	'use strict';
	document.getElementById('encrypt-button').addEventListener('click', function() {
		ca.njewsbury.crypto.Converter.convertAllPlainTextInput();
	});
	document.getElementById('decrypt-button').addEventListener('click', function() {
		ca.njewsbury.crypto.Converter.convertAllCipherTextInput();
		ca.njewsbury.crypto.Converter.comparePlainTextInputToOutput();
	});

	ca.njewsbury.crypto.Converter.doAllEncryptDecrypt();
}
document.addEventListener('DOMContentLoaded', documentMain, false);
