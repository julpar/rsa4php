<?php
/*
 * PHP implementation of the RSA algorithm
 * (C) Copyright 2004 Edsko de Vries, Ireland
 *
 * Object-oriented PHP implementation of the RSA algorithm and
 * new signature functions
 * (C) Copyright 2011 - 2013 Oliver Mueller, http://oliver-mueller.com/
 *
 * Licensed under the terms of the GNU Public License (GPL)
 * See file gpl-2.0.txt for details or alternatively
 * http://www.gnu.org/licenses/gpl-2.0.txt
 * or
 * http://oliver-mueller.com/licenses/gpl-2.0.txt
 *
 * This implementation has been verified against [3] 
 * (tested Java/PHP interoperability).
 *
 * References:
 * [1] "Applied Cryptography", Bruce Schneier, John Wiley & Sons, 1996
 * [2] "Prime Number Hide-and-Seek", Brian Raiter, Muppetlabs (online)
 * [3] "The Bouncy Castle Crypto Package", Legion of the Bouncy Castle,
 *      (open source cryptography library for Java, online)
 * [4] "PKCS #1: RSA Encryption Standard", RSA Laboratories Technical Note,
 *      version 1.5, revised November 1, 1993
 */

/*
 * Functions that are meant to be used by the user of this PHP module:
 *
 * Constructor:
 *   $mykey = new RSA($public_key, $private_key, $modulus, $keylength);
 * Notes:
 *   - $public_key, $private_key and $modulus should be numbers in
 *     (decimal) string format
 *   - $keylength should be a multiple of 8, and should be in bits

 * Encryption and decryption:
 *   $cipher    = $mykey->encrypt($plaintext);
 *   $plaintext = $mykey->decrypt($cipher);
 * Signing and verification:
 *   $signature = $mykey->sign($message, $hash_algorithm);
 *   $match     = $mykey->verify($message, $signature, $hash_algorithm);
 * Notes:
 *   - $plaintext, $cipher, $message and $signature are expected to be
 *     binary data.
 *   - For encrypt(), the length of $message should not exceed 
 *     ($keylength / 8) - 11 (as mandated by [4]).
 *   - encrypt() and sign() will automatically add padding to the message and
 *     message's hash respectively.
 *     For encrypt(), this padding will consist of random values; for sign(),
 *     padding will consist of the appropriate number of 0xFF values (see [4])
 *   - decrypt() will automatically remove message padding.
 *   - Blocks for decrypt() should be exactly ($keylength / 8) bytes long.
 *   - $hash_algorith is the cryptographic hash algorithm to be used during
 *     signing a message. Valid values algorithms which hash_algos() returns,
 *     e. g. "sha1", "sha256", "md5".
 *   - $match of verify() is a boolean value which tells whether the signature
 *     matches the message.
 *
 * Get version of this module:
 *   $version = RSA::version();
 * Notes:
 *   - $version is a string containing the version number.
 *
 */

/*
 * The actual implementation.
 * Requires BCMath support in PHP (compile with --enable-bcmath)
 */

/*
 * Some constants
 */
define("BCCOMP_LARGER", 1);

class RSA {

	protected $public_key;
	protected $private_key;
	protected $modulus;
	protected $keylength;

	public static function version()
	{
		return "0.10";
	}

	public function __construct($public_key, $private_key, $modulus, $keylength)
	{
		$this->public_key = $this->binary_to_number($public_key);
		$this->private_key = $this->binary_to_number($private_key);
		$this->modulus = $this->binary_to_number($modulus);
		$this->keylength = $keylength;
	}

	public function encrypt($message)
	{
		$padded = $this->add_PKCS1_padding($message, true, $this->keylength / 8);
		$number = $this->binary_to_number($padded);
		$encrypted = $this->pow_mod($number, $this->public_key, $this->modulus);
		$result = $this->number_to_binary($encrypted, $this->keylength / 8);

		return $result;
	}

	public function decrypt($message)
	{
		$number = $this->binary_to_number($message);
		$decrypted = $this->pow_mod($number, $this->private_key, $this->modulus);
		$result = $this->number_to_binary($decrypted, $this->keylength / 8);

		return $this->remove_PKCS1_padding($result, $this->keylength / 8);
	}

	public function sign($message, $hash_algorithm)
	{
		$hash = hash($hash_algorithm, $message, true);
		$padded = $this->add_PKCS1_padding($hash, false, $this->keylength / 8);
		$number = $this->binary_to_number($padded);
		$signed = $this->pow_mod($number, $this->private_key, $this->modulus);
		$result = $this->number_to_binary($signed, $this->keylength / 8);

		return $result;
	}

	public function verify($message, $signature, $hash_algorithm)
	{
		// Decrypt signature and restore hash
		$number = $this->binary_to_number($signature);
		$decrypted = $this->pow_mod($number, $this->public_key, $this->modulus);
		$result = $this->number_to_binary($decrypted, $this->keylength / 8);
		$hash1 = $this->remove_PKCS1_padding($result, $this->keylength / 8);

		// Calculate hash of message
		$hash2 = hash($hash_algorithm, $message, true);

		// Compare the hashes and return result
		return (strcasecmp($hash1, $hash2) == 0 ? true : false);
	}

	//--
	// Calculate (p ^ q) mod r 
	//
	// We need some trickery to [2]:
	//   (a) Avoid calculating (p ^ q) before (p ^ q) mod r, because for typical RSA
	//       applications, (p ^ q) is going to be _WAY_ too large.
	//       (I mean, __WAY__ too large - won't fit in your computer's memory.)
	//   (b) Still be reasonably efficient.
	//
	// We assume p, q and r are all positive, and that r is non-zero.
	//
	// Note that the more simple algorithm of multiplying $p by itself $q times, and
	// applying "mod $r" at every step is also valid, but is O($q), whereas this
	// algorithm is O(log $q). Big difference.
	//
	// As far as I can see, the algorithm I use is optimal; there is no redundancy
	// in the calculation of the partial results. 
	//--
	protected function pow_mod($p, $q, $r)
	{
		// Extract powers of 2 from $q
		$factors = array();
		$div = $q;
		$power_of_two = 0;
		while(bccomp($div, "0") == BCCOMP_LARGER)
		{
			$rem = bcmod($div, 2);
			$div = bcdiv($div, 2);
		
			if($rem) array_push($factors, $power_of_two);
			$power_of_two++;
		}

		// Calculate partial results for each factor, using each partial result as a
		// starting point for the next. This depends of the factors of two being
		// generated in increasing order.
		$partial_results = array();
		$part_res = $p;
		$idx = 0;
		foreach($factors as $factor)
		{
			while($idx < $factor)
			{
				$part_res = bcpow($part_res, "2");
				$part_res = bcmod($part_res, $r);

				$idx++;
			}
			
			array_push($partial_results, $part_res);
		}

		// Calculate final result
		$result = "1";
		foreach($partial_results as $part_res)
		{
			$result = bcmul($result, $part_res);
			$result = bcmod($result, $r);
		}

		return $result;
	}

	//--
	// Function to add padding to a decrypted string
	// We need to know if this is a private or a public key operation [4]
	//--
	protected function add_PKCS1_padding($data, $isPublicKey, $blocksize)
	{
		$pad_length = $blocksize - 3 - strlen($data);

		if($isPublicKey)
		{
			$block_type = "\x02";
		
			$padding = "";
			for($i = 0; $i < $pad_length; $i++)
			{
				$rnd = mt_rand(1, 255);
				$padding .= chr($rnd);
			}
		}
		else
		{
			$block_type = "\x01";
			$padding = str_repeat("\xFF", $pad_length);
		}
		
		return "\x00" . $block_type . $padding . "\x00" . $data;
	}

	//--
	// Remove padding from a decrypted string
	// See [4] for more details.
	//--
	protected function remove_PKCS1_padding($data, $blocksize)
	{
		assert(strlen($data) == $blocksize);
		$data = substr($data, 1);

		// We cannot deal with block type 0
		if($data{0} == '\0')
			die("Block type 0 not implemented.");

		// Then the block type must be 1 or 2 
		assert(($data{0} == "\x01") || ($data{0} == "\x02"));

		// Remove the padding
		$offset = strpos($data, "\0", 1);
		return substr($data, $offset + 1);
	}

	//--
	// Convert binary data to a decimal number
	//--
	protected function binary_to_number($data)
	{
		$base = "256";
		$radix = "1";
		$result = "0";

		for($i = strlen($data) - 1; $i >= 0; $i--)
		{
			$digit = ord($data{$i});
			$part_res = bcmul($digit, $radix);
			$result = bcadd($result, $part_res);
			$radix = bcmul($radix, $base);
		}

		return $result;
	}

	//--
	// Convert a number back into binary form
	//--
	protected function number_to_binary($number, $blocksize)
	{
		$base = "256";
		$result = "";

		$div = $number;
		while($div > 0)
		{
			$mod = bcmod($div, $base);
			$div = bcdiv($div, $base);
			
			$result = chr($mod) . $result;
		}

		return str_pad($result, $blocksize, "\x00", STR_PAD_LEFT);
	}
}
?>
