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
	Vigenere Cipher Implementation
	<p>
	Vigenere cipher encryption and decryption, as well as 'breaking' functions.

	Vigenere cipher breaking uses a combination of Kaperski's method and frequency
	analysis to determine what the possible set of keys are. If the crack is unable to
	determine AT MOST a single character in the key, uses the English language probabilities
	to try and determine the best fit.
*/
ca.njewsbury.crypto.VigenereCipher = (function () {
	'use strict';

	var LANGUAGE = ca.njewsbury.crypto.english,
	ALPHABET = LANGUAGE.Alphabet,
	SORTED_ALPHABET = LANGUAGE.SortedAlphabet,
	ALPHABET_LENGTH = Object.keys(ALPHABET).length,

	LOWERCASE_START_VAL = SORTED_ALPHABET[0].charCodeAt(0),
	LOWERCASE_END_VAL = SORTED_ALPHABET[ALPHABET_LENGTH - 1].charCodeAt(0),

	LOGGER = ca.njewsbury.crypto.Logger;

	// Deep copy function
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

	// Vigeneres encrypt.
	function encrypt(plainText, key) {
		var length,
		i,
		asciiCode,
		keyLength = key.length,
		cipherText = '',
		keyCode;

		plainText = plainText.toLowerCase().replace(/\s/g, '');
		key = key.toLowerCase().replace(/\s/g, '');

		for (i = 0, length = plainText.length; i < length; i++) {
			asciiCode = plainText.charCodeAt(i);
			if (asciiCode >= LOWERCASE_START_VAL && asciiCode <= LOWERCASE_END_VAL) {
				keyCode = key.charCodeAt(i % keyLength) - LOWERCASE_START_VAL;
				cipherText += String.fromCharCode(
					((asciiCode - LOWERCASE_START_VAL + keyCode) % ALPHABET_LENGTH)
					+ LOWERCASE_START_VAL);
			} else {
				// Unable to encrypt non-alphabetic char.
				cipherText += plainText.charAt(i);
			}
		}
		return cipherText.toUpperCase();
	}

	// Vigeneres decrypt.
	function decrypt(cipherText, key) {
		var length,
		i,
		asciiCode,
		keyLength = key.length,
		plainText = '',
		keyCode;

		cipherText = cipherText.toLowerCase().replace(/\s/g, '');
		key = key.toLowerCase().replace(/\s/g, '');

		for (i = 0, length = cipherText.length; i < length; i++) {
			asciiCode = cipherText.charCodeAt(i);
			keyCode = key.charCodeAt(i % keyLength) - LOWERCASE_START_VAL;

			if (asciiCode >= LOWERCASE_START_VAL && asciiCode <= LOWERCASE_END_VAL) {
				asciiCode = asciiCode - LOWERCASE_START_VAL - keyCode;
				asciiCode += (asciiCode >= 0) ? LOWERCASE_START_VAL : LOWERCASE_END_VAL + 1;

				plainText += String.fromCharCode(asciiCode);
			} else {
				// Unable to encrypt non-alphabetic char.
				plainText += cipherText.charAt(i);
			}
		}
		return plainText.toLowerCase();
	}

	// Do frequency analysis.
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
				LOGGER.log(LOGGER.ERROR, 'Encountered unknown character: ' + singleChar);
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
							frequencyMap[singleChar].count / cipherText.length * 100.0).toFixed(2));
			}
		}
		LOGGER.log(LOGGER.DEBUG, 'Cipher text is missing ' + missingLetters.length + ' letters.');
		LOGGER.log(LOGGER.DEBUG, missingLetters);
		return frequencyMap;
	}

	// Calculate the sum of probabilities for the given map.
	function calculateSumOfProbability(frequencyMap) {
		var singleChar,
		sumOfProbs = 0;
		for (singleChar in frequencyMap) {
			sumOfProbs += (frequencyMap[singleChar].absFreq / 100 * frequencyMap[singleChar].absFreq / 100);
		}
		return sumOfProbs;
	}

	// Find the GCD between two numbers.
	function calculateGCD(first, second) {
		if (!second) {
			return first;
		}
		return calculateGCD(second, first % second);
	}

	// Find a list of possible GCD key lengths.
	function findTextGCD(cipherText, matchOn, upperBound) {
		var length = cipherText.length,
		currentPos,
		maxCount,
		subCipher,
		regexp,
		matchCount,
		matchList = {},
		distance,
		i,
		j,
		factors,
		gcd,
		keyLength,
		keyOccurs,
		keyIndex;

		/**
			This goes through the given cipher text and pulls out the different
			chunks of data of the length 'matchOn'
			ie if the text is abcdef and matchOn is 3, it'll get the number of times
			substrings 'abc' 'bce' 'cde' etc show up in the overall text.

			This is then used to calculate the distances between matching text.
		*/
		for (currentPos = 0, maxCount = length - matchOn; currentPos < maxCount; currentPos++) {
			subCipher = cipherText.substring(currentPos, currentPos + matchOn);
			regexp = new RegExp(subCipher, 'g');
			matchCount = (cipherText.match(regexp) || []).length;
			if (matchCount <= 1) {
				continue;
			}
			if (!matchList[subCipher]) {
				matchList[subCipher] = {};
				matchList[subCipher].count = matchCount;
				matchList[subCipher].posList = [];
			}
			matchList[subCipher].posList.push(currentPos);
		}

		/**
			We now have a list of all possible char combos that are repeated throughout
			the cipher text. Find the distances between those strings.
		*/
		factors = [];
		for (subCipher in matchList) {
			length = matchList[subCipher].posList.length;
			for (i = 0; i < length; i++) {
				for (j = i + 1; j < length; j++) {
					// So nestled.
					if (j === i) {
						continue;
					}
					distance = matchList[subCipher].posList[i] - matchList[subCipher].posList[j];
					distance = Math.abs(distance);
					if (factors.indexOf(distance) < 0) {
						factors.push(distance);
					}
				}
			}
		}
		/**
			We now have the distances between all repeated instances of sub-strings.
			Now we need to get the GCD between those distances, to try and find possible
			key lengths.
		*/
		keyLength = [];
		// For Debugging purposes.
		keyOccurs = [];
		if (factors.length > 1) {
			for (i = 0, length = factors.length; i < length; i++) {
				for (j = i + 1; j < length; j++) {
					if (j === i) {
						continue;
					}

					gcd = calculateGCD(factors[i], factors[j]);
					// I apologize for these magic numbers.
					// Basically ruling out invalid results.
					if (gcd === 1 || gcd === 0) {
						continue;
					}
					if (gcd < upperBound + 5 && gcd > matchOn) {
						keyIndex = keyLength.indexOf(gcd);
						if (keyIndex < 0) {
							keyLength.push(gcd);
							keyOccurs.push(1);
						} else {
							keyOccurs[keyIndex] += 1;
						}
					}

				}
			}
			LOGGER.log(LOGGER.DEBUG, 'Possible key lengths: ');
			LOGGER.log(LOGGER.DEBUG, keyLength);
			LOGGER.log(LOGGER.DEBUG, 'Key length guess occurences: ');
			LOGGER.log(LOGGER.DEBUG, keyOccurs);
		}
		return keyLength;
	}

	/**
		Break the given Vigener Ciphertext.
		<p>
		Attempts to break the given vigenere cipher text. Since we require the text
		is 't' times larger than the key (of length 't') an upper bound on the key length
		guesses is created. If this length is surpassed, the text is deemed unbreakable.

		@param {String} cipherText the ciphertext to break
		@returns {Array} containing cracked plaintext and the key.
	 */
	function breakCipher(cipherText) {
		var length = cipherText.length,
		upperBound = Math.ceil(Math.sqrt(length)) + 1,
		initialKeyLengthGuess = findTextGCD(cipherText, 'the'.length, upperBound),
		subCipher,
		testKey,
		unbreakableMin = cipherText.length,
		unbreakable,
		currentGuess,
		i,
		offset,
		j,
		output,
		keyword,
		plainText;

		/**
			Using the list of possible key lengths,
			we go through the different permutations of CT[i], CT[i+t] and CT[i+nT]
			to try and find the keyword used to encrypt the text.

			Once we build ALL possible keywords, we choose the one that had the
			LEAST number of unbreakable characters.

		*/
		for (i = 0; i < initialKeyLengthGuess.length; i++) {
			testKey = [];
			unbreakable = 0;
			for (offset = 0; offset < initialKeyLengthGuess[i]; offset++) {
				subCipher = '';
				for (j = offset; j < length; j += initialKeyLengthGuess[i]) {
					subCipher += cipherText.charAt(j);
				}
				output = ca.njewsbury.crypto.ShiftCipher.breakEncryption(subCipher);
				if (output) {
					testKey.push(window.parseInt(output[1]));
				} else {
					LOGGER.log(
						LOGGER.INFO,
						'Unable to break subCipher key: '
						+ initialKeyLengthGuess[i]
						+ ' offset: '
						+ offset);
					testKey.push(-1)
					unbreakable++;
				}
			}
			if (unbreakable < unbreakableMin) {
				unbreakableMin = unbreakable;
				currentGuess = testKey;
			}
		}
		if (!currentGuess) {
			return ['unable to break', -1];
		}

		/**
			For all unbreakable shift-keys, replace them with
			the wild card instead.
		*/
		keyword = '';
		for (i = 0; i < currentGuess.length; i++) {
			if (currentGuess[i] < 0) {
				keyword += '*';
			} else {
				keyword += String.fromCharCode(LOWERCASE_START_VAL + currentGuess[i]);
			}
		}

		/**
			If we were able to break all chars, just display it!
		*/
		if (unbreakableMin === 0) {
			// Able to break all keyword chars.
			plainText = decrypt(cipherText, keyword);
			return [plainText, keyword];
		}
		/**
			If we cracked all except one shift-cipher, try finding it
			by substituting all chars until the sum of probabilities matches
			the English sum.
		*/
		if (unbreakableMin === 1) {
			// Able to break all but one chars.
			return findBestBreakableFit(cipherText, keyword);
		}
		return [decrypt(cipherText, keyword.replace(/\*/g, 'a')), keyword];
	}

	// Run through all characters to try and find the one that makes the plain text sum match english.
	function findBestBreakableFit(cipherText, keyword) {
		var modKeyword,
		modPlaintext,
		numberMissing = (keyword.match(/\*/g) || []).length,
		frequencyMap,
		sumOfProbs,
		i,
		minDiff = cipherText.length,
		probModKey;
		if (numberMissing > 1) {
			LOGGER.log(LOGGER.ERROR, 'Too many combinations to try, considering code unbreakable.');
			return [decrypt(cipherText, keyword.replace(/\*/g, 'a')), keyword];
		}

		for (i = 0; i < ALPHABET_LENGTH; i++) {
			frequencyMap = {};
			modKeyword = keyword.replace(/\*/g, SORTED_ALPHABET[i]);
			modPlaintext = decrypt(cipherText, modKeyword);
			frequencyMap = calculateFrequencyMap(modPlaintext);
			sumOfProbs = calculateSumOfProbability(frequencyMap);

			if (Math.abs(sumOfProbs - LANGUAGE.SumOfSquares) < minDiff) {
				minDiff = Math.abs(sumOfProbs - LANGUAGE.SumOfSquares);
				probModKey = modKeyword;
			}
		}
		return [decrypt(cipherText, probModKey), probModKey];
	}

	return {
		encryptPlainText : function (plainText, key) {
			if (!plainText || !plainText.trim()) {
				throw new Error('Please provide plain-text!');
			}
			if (!key) {
				throw new Error('Please provide key!');
			}
			return encrypt(plainText, key);
		},
		decryptCipherText : function (cipherText, key) {
			if (!cipherText || !cipherText.trim()) {
				throw new Error('Please provide cipher-text!');
			}
			if (!key) {
				throw new Error('Please provide key!');
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