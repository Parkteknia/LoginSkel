<?php

require 'Base32.php';

// TOTP.php
class TOTP {

    private $base32;
    
    // Constructor initializes the Base32 encoder/decoder
    public function __construct() {
        $this->base32 = new Base32();
    }
    
    /**
    * Generates a secret key for the TOTP (Time-Based One-Time Password).
    *
    * This function creates a random secret key of a specified length (base32)
    * using a character set consisting of uppercase letters (A-Z)
    * and numbers (2-7). This key is used to generate time-based one-time passwords,
    * commonly used for two-factor authentication (2FA).
    *
    * @param int $length The length of the secret key to generate. The default is 32.
    * @return string The generated secret key.
    */

    public function generateSecret($length = 32) {
        // base32 uses only uppercase letters A-Z and only the numbers 2 through 7.
        // It does not include lowercase letters or the digits 0,1,8, or 9.
        $characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $secret = '';
        for ($i = 0; $i < $length; $i++) {
            $secret .= $characters[random_int(0, strlen($characters) - 1)];
        }
        return $secret;
    }
    
    /**
     * Generates the URL for the QR Code used in TOTP setup.
     *
     * This function constructs a URL that can be used to generate a QR code
     * for setting up TOTP with a user application like Google Authenticator.
     *
     * @param string $username The username of the account.
     * @param string $secret The base32 encoded secret key.
     * @param string $issuer The name of the issuer (usually the application name).
     * @return string The URL to be used for QR code generation.
     */
    public function getQRCodeUrl($username, $secret, $issuer = 'LoginSkel') {
        return 'otpauth://totp/' . $issuer . ':' . $username . '?secret=' . $secret . '&issuer=' . $issuer;
    }
    
    /**
     * Verifies a TOTP code against the secret key.
     *
     * This function checks the provided TOTP code by generating valid codes
     * for the current time and an acceptable window (usually ±1 time slice)
     * to account for slight time differences between client and server.
     *
     * @param string $secret The base32 encoded secret key.
     * @param string $code The TOTP code to verify.
     * @return bool True if the code is valid, false otherwise.
     */
    public function verifyCode($secret, $code) {
        // Get the current time slice (30 seconds)
        $timeSlice = floor(time() / 30);
        // Check codes for the current time slice and adjacent slices
        for ($i = -1; $i <= 1; $i++) {
            $calculatedCode = $this->calculateTOTPCode($secret, $timeSlice + $i);
            if ($calculatedCode == $code) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * Calculates a TOTP code for a given time slice.
     *
     * This function generates a TOTP code based on the secret key and a specific
     * time slice (usually 30-second intervals). It follows the TOTP standard
     * as defined by RFC 6238.
     *
     * @param string $secret The base32 encoded secret key.
     * @param int $timeSlice The time slice to calculate the TOTP code for.
     * @return string The generated TOTP code.
     */
    private function calculateTOTPCode($secret, $timeSlice) {
        // Decode the base32 encoded secret key
        $key = $this->base32->decode($secret);
        
        // Pack the time slice into binary format
        $time = pack('N*', 0) . pack('N*', $timeSlice);
        // Generate HMAC-SHA1 of the time slice with the secret key
        $hm = hash_hmac('sha1', $time, $key, true);
        // Extract the dynamic offset from the last byte of the HMAC
        $offset = ord($hm[19]) & 0xf;
        // Extract a 4-byte string starting at the dynamic offset
        $hashpart = substr($hm, $offset, 4);
        
        // Convert the binary data to an integer and truncate to a 6-digit code
        $value = unpack('N', $hashpart);
        $value = $value[1] & 0x7fffffff;
        $modulo = 10 ** 6;
        
        // Return the 6-digit code as a zero-padded string
        return str_pad($value % $modulo, 6, '0', STR_PAD_LEFT);
    }
}