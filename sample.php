<?php

/*
 *
 *  Passwords^14 / Proof of work as an authentication factor / Sample code
 *
 *  This is sample code, not a secure implementation.
 *
 *  Copyright (c) 2014, Philippe Paquet & Jason Nehrboss
 *  All rights reserved.
 *  
 *  Redistribution and use in source and binary forms, with or without modification,
 *  are permitted provided that the following conditions are met:
 *  
 *  1. Redistributions of source code must retain the above copyright notice, this
 *     list of conditions and the following disclaimer.
 *  
 *  2. Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *  
 *  3. Neither the name of the copyright holder nor the names of its contributors
 *     may be used to endorse or promote products derived from this software
 *     without specific prior written permission.
 *  
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 *  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 *  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 *  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 *  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 *  NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 *  PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 *  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 *
 */





define('DEFAULT_ALGO', 'sha1');		// Default algorithm (md5, sha1, sha256, sha512, ripemd160).
define('DEFAULT_BITS', 14);			// Default size of the partial collision requested.
define('DEFAULT_SEED_SIZE', 16);	// Default number of bytes for the seed.





// Start session
session_start();



// Set the proof of work algorithm if necessary
if(empty($_SESSION['algorithm'])) {
	$_SESSION['algorithm'] = DEFAULT_ALGO;
}



// Set the size of the partial collision if necessary
if(empty($_SESSION['bits'])) {
	$_SESSION['bits'] = DEFAULT_BITS;
}



// Set the proof of work seed if necessary
if(empty($_SESSION['seed'])) {
	$_SESSION['seed'] = bin2hex(openssl_random_pseudo_bytes(DEFAULT_SEED_SIZE));
}



// Set user authentication status if necessary
if(empty($_SESSION['auth'])) {
	$_SESSION['auth'] = FALSE;
}



// Process actions if any
$action = filter_input(INPUT_POST, 'action', FILTER_SANITIZE_STRING);
switch($action) {

	case 'login':

		// Filter input
		$username = filter_input(INPUT_POST, 'username', FILTER_SANITIZE_STRING);
		$password = filter_input(INPUT_POST, 'password', FILTER_SANITIZE_STRING);
		$proof = filter_input(INPUT_POST, 'proof', FILTER_SANITIZE_NUMBER_INT);

		// Compute proof of work
		switch ($_SESSION['algorithm']) {
			case 'md5':
				$check_proof = hash('md5', $_SESSION['seed'] . $proof);
				break;
			case 'sha1':
				$check_proof = hash('sha1', $_SESSION['seed'] . $proof);
				break;
			case 'sha256':
				$check_proof = hash('sha256', $_SESSION['seed'] . $proof);
				break;
			case 'sha512':
				$check_proof = hash('sha512', $_SESSION['seed'] . $proof);
				break;
			case 'ripemd160':
				$check_proof = hash('ripemd160', $_SESSION['seed'] . $proof);
				break;
			default:
				die('Undefined $algo');
				break;
		}

		// Check that the proof is valid
		$valid_proof = TRUE;
		for ($i = 0; $i < $_SESSION['bits']; $i++) {
			$half_byte = hexdec($check_proof[$i / 4]);
			if ($half_byte & (1 << (3 - ($i % 4)))) {
				$valid_proof = FALSE;
			}
		}

		// If the proof is valid
		if (TRUE == $valid_proof) {

			// Check username
			if ($username === "user") {

				// Check password
				if ($password === "pass") {

					// User is authenticated
					$_SESSION['auth'] = TRUE;

				} else {

					// Reset seed
					$_SESSION['seed'] = bin2hex(openssl_random_pseudo_bytes(DEFAULT_SEED_SIZE));

					// Error message
					$error = 'Invalid password';
				}

			} else {

				// Reset seed
				$_SESSION['seed'] = bin2hex(openssl_random_pseudo_bytes(DEFAULT_SEED_SIZE));

				// Error message
				$error = 'Invalid username';
			}

		} else {

			// Reset seed
			$_SESSION['seed'] = bin2hex(openssl_random_pseudo_bytes(DEFAULT_SEED_SIZE));

			// Error message
			$error = 'Invalid proof of work';
		}
		break;

	case 'logout':

		// Reset session
		session_unset();
		session_destroy();
		session_write_close();
		session_start();

		// Set parameters
		$_SESSION['algorithm'] = DEFAULT_ALGO;
		$_SESSION['bits'] = DEFAULT_BITS;
		$_SESSION['seed'] = bin2hex(openssl_random_pseudo_bytes(DEFAULT_SEED_SIZE));
		$_SESSION['auth'] = FALSE;
		break;

	default:
		break;
}



if (FALSE == $_SESSION['auth']) { ?>

	<!DOCTYPE html>
		<head>
			<meta charset="utf-8">
			<title>Passwords^14 / Proof of work as an authentication factor / Sample code</title>
			<script language="javascript" src="http://crypto-js.googlecode.com/svn/tags/3.1.2/build/components/core-min.js"></script>
			<script language="javascript" src="http://crypto-js.googlecode.com/svn/tags/3.1.2/build/components/md5-min.js"></script>
			<script language="javascript" src="http://crypto-js.googlecode.com/svn/tags/3.1.2/build/components/sha1-min.js"></script>
			<script language="javascript" src="http://crypto-js.googlecode.com/svn/tags/3.1.2/build/components/sha256-min.js"></script>
			<script language="javascript" src="http://crypto-js.googlecode.com/svn/tags/3.1.2/build/components/sha512-min.js"></script>
			<script language="javascript" src="http://crypto-js.googlecode.com/svn/tags/3.1.2/build/components/ripemd160-min.js"></script>
			<script type="text/javascript">
				function calculateProof() {

					// Get parameters
					var algorithm = document.getElementById('algorithm').value;
					var seed = document.getElementById('seed').value;
					var bits = parseInt(document.getElementById('bits').value, 10);

					var proof = 0;
					var proof_complete = false;
					while (proof_complete != true) {

						// Compute proof
						var check_proof;
						switch(algorithm) {
							case 'md5':
								check_proof = CryptoJS.MD5(seed + proof.toString()).toString();
								break;
							case 'sha1':
								check_proof = CryptoJS.SHA1(seed + proof.toString()).toString();
								break;
							case 'sha256':
								check_proof = CryptoJS.SHA256(seed + proof.toString()).toString();
								break;
							case 'sha512':
								check_proof = CryptoJS.SHA512(seed + proof.toString()).toString();
								break;
							case 'ripemd160':
								check_proof = CryptoJS.RIPEMD160(seed + proof.toString()).toString();
								break;
						}

						// Check that the proof is valid
						var valid_proof = true;
						for (var i = 0; i < bits; i++) {
							var half_byte = parseInt(check_proof.charAt(i / 4), 16);
							if ((half_byte & (1 << (3 - (i % 4)))) != 0) {
								valid_proof = false;
							}
						}

						// If the proof is valid, inject the proof in the form
						if (valid_proof == true) {
							document.getElementById('proof').value = proof.toString();
							proof_complete = true;
						} else {
							proof = proof + 1;
						}
					}

					// Submit the form
					document.getElementById('form').submit();
				}
			</script>
		</head>
		<body>
			<h3>Passwords^14</h3>
			<b>Proof of work as an authentication factor</b><br />
			Philippe Paquet, Jason Nehrboss<br />
			<br />
			Source code available on Github:<br />
			<a href="https://github.com/jaegerindustries/passwords14">https://github.com/jaegerindustries/passwords14</a><br />
			<br />
			Valid credentials for this sample are "user" and "pass"<br />
			<br />
			Algorithm: <?php echo $_SESSION['algorithm']; ?><br />
			Seed: <?php echo $_SESSION['seed']; ?><br />
			Bits: <?php echo $_SESSION['bits']; ?><br />
			<br />
			<?php if (isset($error)) { ?>
				<div style="color: red;">
					Error: <?php echo $error; ?><br />
					Username: <?php echo $username; ?><br />
					Password: <?php echo $password; ?><br />
					Proof: <?php echo $proof; ?><br />
					Proof Check: <?php echo $check_proof; ?><br />
				</div>
				<br />
			<?php } ?>
			<form id="form" name="form" method="post" action="">
				<input type="hidden" name="action" value="login" />
				<input type="hidden" id="algorithm" name="algorithm" value="<?php echo $_SESSION['algorithm']; ?>" />
				<input type="hidden" id="seed" name="seed" value="<?php echo $_SESSION['seed']; ?>" />
				<input type="hidden" id="bits" name="bits" value="<?php echo $_SESSION['bits']; ?>" />
				<input type="hidden" id="proof" name="proof" value="" />
				Username: <input type="text" name="username"/><br />
				Password: <input type="password" name="password"/><br />
				<input type="submit" value="Login" onclick="calculateProof();" /><br />
			</form>
		</body>
	</html>

<?php } else { ?>

	<!DOCTYPE html>
		<head>
			<meta charset="utf-8">
			<title>Passwords^14 / Proof of work as an authentication factor / Sample code</title>
		</head>
		<body>
			<h3>Passwords^14</h3>
			<b>Proof of work as an authentication factor</b><br />
			Philippe Paquet, Jason Nehrboss<br />
			<br />
			Source code available on Github:<br />
			<a href="https://github.com/jaegerindustries/passwords14">https://github.com/jaegerindustries/passwords14</a><br />
			<br />
			A valid proof of work and valid credentials were presented.<br />
			<br />
			Algorithm: <?php echo $_SESSION['algorithm']; ?><br />
			Seed: <?php echo $_SESSION['seed']; ?><br />
			Bits: <?php echo $_SESSION['bits']; ?><br />
			<br />
			<form id="form" name="form" method="post" action="">
				<input type="hidden" name="action" value="logout" />
				<input type="submit" value="Logout" />
			</form>
		</body>
	</html>

<?php } ?>
