<?php

class Base32 {
    
    // Base32 character set including padding character '='
    private static $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=';
    
    /**
     * Decodes a base32 encoded string.
     *
     * This function converts a base32 encoded string back to its original binary form.
     * It handles padding characters and checks for valid base32 input.
     *
     * @param string $input The base32 encoded string to decode.
     * @return string|bool The decoded binary data, or false if input is invalid.
     */
    public function decode($input) {
        // Count padding chars
        $paddingCharCount = substr_count($input, '=');
        $allowedValues = [6, 4, 3, 1, 0];
        if (!in_array($paddingCharCount, $allowedValues)) {
            return false;
        }

        // Validate the placement of padding characters
        for ($i = 0; $i < 4; $i++) {
            if ($paddingCharCount == $allowedValues[$i] &&
                substr($input, -($allowedValues[$i])) != str_repeat('=', $allowedValues[$i])) {
                return false;
            }
        }

        // Remove padding characters
        $input = str_replace('=', '', $input);
        $output = '';
        $inputLength = strlen($input);
        for ($i = 0; $i < $inputLength; $i += 8) {
            $chunk = substr($input, $i, 8);
            $bits = '';
            for ($j = 0; $j < 8; $j++) {
                $char = $chunk[$j];
                if ($char !== false) {
                    // Convert each base32 character to its 5-bit binary representation
                    $bits .= str_pad(base_convert(strpos(self::$alphabet, $char), 10, 2), 5, '0', STR_PAD_LEFT);
                }
            }
            // Convert binary data back to ASCII characters
            $output .= chr(bindec(substr($bits, 0, 8)));
            if (strlen($bits) >= 16) {
                $output .= chr(bindec(substr($bits, 8, 8)));
            }
            if (strlen($bits) >= 24) {
                $output .= chr(bindec(substr($bits, 16, 8)));
            }
            if (strlen($bits) >= 32) {
                $output .= chr(bindec(substr($bits, 24, 8)));
            }
            if (strlen($bits) >= 40) {
                $output .= chr(bindec(substr($bits, 32, 8)));
            }
        }
        return $output;
    }
    
    /**
     * Encodes a binary string into base32.
     *
     * This function converts a binary input string to its base32 representation,
     * which is a text-friendly encoding scheme that uses a limited set of characters.
     *
     * @param string $input The binary data to encode.
     * @return string The base32 encoded string.
     */
    public function encode($input) {
        if (empty($input)) {
            return "";
        }

        $inputLength = strlen($input);
        $output = '';
        $v = 0;
        $vBits = 0;
        
        // Process each byte of the input
        for ($i = 0; $i < $inputLength; $i++) {
            // Shift the current byte into the working integer
            $v = ($v << 8) | ord($input[$i]);
            $vBits += 8;
            // Extract 5-bit segments from the working integer and encode as base32 characters
            while ($vBits >= 5) {
                $vBits -= 5;
                $output .= self::$alphabet[($v >> $vBits) & 0x1F];
            }
        }
        
        // Encode any remaining bits in the final byte
        if ($vBits > 0) {
            $output .= self::$alphabet[($v << (5 - $vBits)) & 0x1F];
        }

        // Add padding characters to ensure the output length is a multiple of 8
        while (strlen($output) % 8 !== 0) {
            $output .= '=';
        }

        return $output;
    }
}