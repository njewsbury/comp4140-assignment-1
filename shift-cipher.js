/*global window */
/*eslint no-extra-parens: 0*/
/**
	COMP 4140 Crypto Assignment One
	N. Jewsbury #7614402
	-------------------------------
*/
var ca;

if (!ca || !ca.njewsbury || !ca.njewsbury.crypto) {
	throw new Error('Namespace not yet defined!');
}

/**
	Simple Shift-Cipher Implementation
	<p>
	Shift cipher encryption and decryption, as well as 'breaking' functions.

	Shift Cipher breaking function uses frequency analysis to find the
	key within a defined tolerance.
*/
ca.njewsbury.crypto.ShiftCipher = (function () {
	'use strict';

	var LANGUAGE = ca.njewsbury.crypto.english,
		ALPHABET = LANGUAGE.Alphabet,
		SORTED_ALPHABET = LANGUAGE.SortedAlphabet,
		ALPHABET_LENGTH = Object.keys(ALPHABET).length,

		LOWERCASE_START_VAL = SORTED_ALPHABET[0].charCodeAt(0),
		LOWERCASE_END_VAL = SORTED_ALPHABET[ALPHABET_LENGTH-1].charCodeAt(0),

		INITIAL_KEY_TOLERANCE = 0.95,
		TOLERANCE_STEP_SIZE = 0.05,
		MINIMUM_TOLERANCE = 0.85,
		LOGGER = ca.njewsbury.crypto.Logger;

	// Used for deep-copying objects.
	function cloneObject(original) {
		var attr,
			clone = {};
		for (attr in original) {
			if (original.hasOwnProperty(attr)) {
				if (typeof original[attr] === 'object') {
					clone[attr] = cloneObject(original[attr]);
				} else {
					clone[attr] = original[attr];
				}
			}
		}
		return clone;
	}

	// Shift cipher encryption function
	function encrypt(plainText, key) {
		var length,
			i,
			asciiCode,
			cipherText = '';

		key = Math.abs(key) % ALPHABET_LENGTH;
		plainText = plainText.toLowerCase().replace(/\s/g, '');
		for (i = 0, length = plainText.length; i < length; i++) {

			asciiCode = plainText.charCodeAt(i);
			if (asciiCode >= LOWERCASE_START_VAL && asciiCode <= LOWERCASE_END_VAL) {
				cipherText += String.fromCharCode(
					((asciiCode - LOWERCASE_START_VAL + key) % ALPHABET_LENGTH)
					+ LOWERCASE_START_VAL
				);
			} else {
				// Unable to encrypt non-alphabetic char.
				cipherText += plainText.charAt(i);
			}
		}
		return cipherText.toUpperCase();
	}

	// Shift cipher decrypt function
	function decrypt(cipherText, key) {
		var length,
			i,
			asciiCode,
			plainText = '';
		key = Math.abs(key) % ALPHABET_LENGTH;
		cipherText = cipherText.toLowerCase();

		for (i = 0, length = cipherText.length; i < length; i++) {
			asciiCode = cipherText.charCodeAt(i);
			if (
				asciiCode >= LOWERCASE_START_VAL
				&& asciiCode <= LOWERCASE_END_VAL
			) {
				asciiCode = asciiCode - LOWERCASE_START_VAL - key;
				asciiCode += (asciiCode >= 0) ? LOWERCASE_START_VAL : LOWERCASE_END_VAL+1;
				plainText += String.fromCharCode(asciiCode);
			} else {
				// Unable to encrypt non-alphabetic char.
				plainText += cipherText.charAt(i);
			}
		}
		return plainText.toLowerCase();
	}

	// Create a frequency map for the given cipher text.
	function calculateFrequencyMap(cipherText) {
		var length,
			i,
			singleChar,
			frequencyMap = cloneObject(ALPHABET),
			missingLetters = [];

		cipherText = cipherText.toLowerCase();
		for (i = 0, length = cipherText.length; i < length; i++) {
			singleChar = cipherText.charAt(i);
			if (!frequencyMap[singleChar]) {
				LOGGER.log(LOGGER.ERROR, 'Encountered unknown character: ' + singleChar );
				continue;
			}
			if (!frequencyMap[singleChar].count) {
				frequencyMap[singleChar].count = 1;
			} else {
				frequencyMap[singleChar].count += 1;
			}
		}
		for (singleChar in frequencyMap) {
			if (!frequencyMap[singleChar].count) {
				missingLetters.push(singleChar);
				frequencyMap[singleChar].count = 0;
				frequencyMap[singleChar].absFreq = 0.0;
			} else {
				frequencyMap[singleChar].absFreq = window.parseFloat((
					frequencyMap[singleChar].count/cipherText.length*100.0
				).toFixed(2));
			}
		}
		LOGGER.log(LOGGER.DEBUG, 'Cipher text is missing ' + missingLetters.length + ' letters.');
		LOGGER.log(LOGGER.DEBUG, missingLetters);
		return frequencyMap;
	}

	// Using the frequency analysis, create a series of best guesses for the key value.
	function calculateKeyGuesses(frequencyMap, tolerance) {
		var j,
			length,
			singleChar,
			keyGuesses = {},
			sumOfProbs,
			charPos,
			charPrime;

		for (j = 0, length = ALPHABET_LENGTH; j < length; j++) {
			sumOfProbs = 0;
			for (singleChar in frequencyMap) {
				charPos = SORTED_ALPHABET.indexOf(singleChar);
				if (charPos < 0) {
					LOGGER.log(LOGGER.ERROR, 'Unable to locate ' + singleChar + ' in the alphabet.');
					continue;
				}
				charPrime = SORTED_ALPHABET[(charPos + j) % ALPHABET_LENGTH];
				sumOfProbs += (frequencyMap[singleChar].avgFreq * frequencyMap[charPrime].absFreq)/10000;
			}
			if (Math.abs(sumOfProbs/LANGUAGE.SumOfSquares) > tolerance) {
				keyGuesses[j] = {};
				keyGuesses[j].cipherProb = sumOfProbs;
				keyGuesses[j].diff = Math.abs(sumOfProbs/LANGUAGE.SumOfSquares);
			}
		}
		return keyGuesses;
	}

	function breakCipher(cipherText) {
		var frequencyMap = calculateFrequencyMap(cipherText),
			currentTolerance = INITIAL_KEY_TOLERANCE,
			keyGuessTable = calculateKeyGuesses(frequencyMap, currentTolerance),
			keyGuessLength,
			key,
			plainText = '',
			usedKey = '';

		while (!Object.keys(keyGuessTable).length && currentTolerance > MINIMUM_TOLERANCE) {
			currentTolerance -= TOLERANCE_STEP_SIZE;
			LOGGER.log(LOGGER.INFO, 'Unable to find key for given tolerance, lowering tolerance to ' + currentTolerance);
			keyGuessTable = calculateKeyGuesses(frequencyMap, currentTolerance);
		}

		keyGuessLength = Object.keys(keyGuessTable).length
		if (!keyGuessLength) {
			LOGGER.log(LOGGER.INFO, 'Unable to crack ciphertext.');
			return plainText;
		}

		for (key in keyGuessTable) {
			if (!plainText || !plainText.trim()) {
				LOGGER.log(LOGGER.DEBUG, 'Using key:: ' + key);
				plainText = decrypt(cipherText, key);
				usedKey = key;
			} else {
				LOGGER.log(LOGGER.DEBUG, 'They key may have also been: ' + key + ' resulting in:');
				LOGGER.log(LOGGER.DEBUG, '>> ' + decrypt(cipherText, key));
			}
		}
		return [plainText, usedKey];
	}

	return {
		encryptPlainText : function (plainText, key) {
			if (!plainText || !plainText.trim()) {
				throw new Error('Please provide plain-text!');
			}
			if (!key) {
				throw new Error('Please provide shift-number!');
			}
			return encrypt(plainText, parseInt(key));
		},
		decryptCipherText : function (cipherText, key) {
			if (!cipherText || !cipherText.trim()) {
				throw new Error('Please provide cipher-text!');
			}
			if (!key) {
				throw new Error('Please provide shift-number!');
			}
			return decrypt(cipherText, key);
		},
		breakEncryption : function (cipherText) {
			if (!cipherText || !cipherText.trim()) {
				throw new Error('Please provide cipher-text!');
			}
			return breakCipher(cipherText);
		}
	};

}
	());