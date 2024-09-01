<?php

declare(strict_types=1);

class JWE
{
    private string $encryptionKey;
    private string $algorithm = 'aes-256-gcm';

    public function __construct(string $encryptionKey)
    {
        $this->encryptionKey = $encryptionKey;
    }

    /**
     * Generates a JWE with AES-256-GCM encryption.
     */
    public function generateJWE(array $payload): string
    {
        // Convertir el payload a JSON
        $payloadJson = json_encode($payload, JSON_THROW_ON_ERROR);

        // Generate a 12-byte IV (Initialization Vector) for GCM
        $iv = random_bytes(openssl_cipher_iv_length($this->algorithm));

        // Encrypt the payload using AES-256-GCM
        $ciphertext = openssl_encrypt(
            $payloadJson,
            $this->algorithm,
            $this->encryptionKey,
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );

        if ($ciphertext === false) {
            throw new RuntimeException('Failed to encrypt payload.');
        }

        // Create the protected JWE header
        $header = [
            'alg' => 'dir', // Direct algorithm, uses the symmetric key directly
            'enc' => 'A256GCM' // 256-bit AES GCM encryption
        ];

        // Encode the protected JWE header in UTF-8 and then in Base64URL
        $encodedHeader = $this->base64UrlEncode(json_encode($header, JSON_THROW_ON_ERROR));

        // Encode the protected JWE header in UTF-8 and then in Base64URL
        $encryptedKey = '';

        // Encode IV, ciphertext and tag in Base64URL
        $encodedIv = $this->base64UrlEncode($iv);
        $encodedCiphertext = $this->base64UrlEncode($ciphertext);
        $encodedTag = $this->base64UrlEncode($tag);

        // Building the JWE according to RFC 7516
        return implode('.', [$encodedHeader, $encryptedKey, $encodedIv, $encodedCiphertext, $encodedTag]);
    }

    /**
     * Decodes and decrypts a JWE into the original payload.
     */
    public function decryptJWE(string $jwe): array
    {
        // Separate the different parts of the JWE
        [$encodedHeader, $encodedEncryptedKey, $encodedIv, $encodedCiphertext, $encodedTag] = explode('.', $jwe);

        // Decode each part
        $iv = $this->base64UrlDecode($encodedIv);
        $ciphertext = $this->base64UrlDecode($encodedCiphertext);
        $tag = $this->base64UrlDecode($encodedTag);

        // Decrypt the payload using AES-256-GCM
        $decryptedPayload = openssl_decrypt(
            $ciphertext,
            $this->algorithm,
            $this->encryptionKey,
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );

        if ($decryptedPayload === false) {
            throw new RuntimeException('Failed to decrypt JWE.');
        }

        return json_decode($decryptedPayload, true, 512, JSON_THROW_ON_ERROR);
    }

    /**
     * Encodes a string in base64url format.
     */
    private function base64UrlEncode(string $data): string
    {
        return str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($data));
    }

    /**
     * Decodes a string in base64url format.
     */
    private function base64UrlDecode(string $data): string
    {
        $base64 = str_replace(['-', '_'], ['+', '/'], $data);
        return base64_decode($base64, true);
    }
}

