<?php

/**
 * Class JWT
 *
 * This class provides methods to create, encode, sign, and verify JSON Web Tokens (JWT).
 * It also includes support for payload preparation, encryption, and decryption of tokens.
 * JWTs are widely used for authentication and authorization in web applications.
 */
class JWT
{
    // Private key used for signing JWTs
    private string $privateKey;
    
    // Public key used for verifying JWT signatures
    private string $publicKey;
    
    // Algorithm used for signing and verifying JWTs (e.g., HS256, RS256)
    private string $algorithm;
    
    // Type of the token (usually "JWT")
    private string $type;
    
    // Indicates whether the token is encrypted
    private bool $encrypted;
    
    // Encryption key for encrypting and decrypting tokens
    private string $encryptionKey;
    
    // Encryption algorithm used for encrypting tokens
    private string $encryptionAlgorithm = 'AES-256-CBC';
    
    /**
     * Constructor for the JWT class.
     *
     * Initializes the JWT class with private and public keys, the signing algorithm,
     * the type of the token, and an encryption key. Loads the keys from specified paths.
     *
     * @param array $keys Array containing paths to the private and public key files.
     * @param string $algorithm The algorithm to be used for signing the token.
     * @param string $type The type of the token (typically "JWT").
     * @param string $encryptionKey The key to be used for encrypting the token.
     */
    public function __construct(array $keys, string $algorithm, string $type, string $encryptionKey)
    {
        
        $this->privateKey = $this->loadKey($keys['private']);
        $this->publicKey = $this->loadKey($keys['public']);
        $this->algorithm = $algorithm;
        $this->type = $type;
        $this->encryptionKey = $encryptionKey;
    }
    
    /**
     * Loads a key from a file path.
     *
     * Reads the contents of a file and returns it as a string. Throws an exception if the file cannot be read.
     *
     * @param string $path The file path to the key.
     * @return string The key read from the file.
     * @throws Exception If the key cannot be read from the file.
     */
    private function loadKey(string $path): string
    {
        $key = file_get_contents($path);
        if (!$key) {
            throw new Exception("Unable to read key from file: $path");
        }
        return $key;
    }
    
    /**
     * Prepares the payload for the JWT.
     *
     * This method creates a default payload with standard claims and merges it with the provided payload.
     * It handles default values and optional claims.
     *
     * @param array $payload The custom payload to be included in the token.
     * @return array The complete payload with standard and custom claims.
     */
    public function preparePayload($payload) {
        
        $defaultPayload = [
            'iss' => (isset($payload['iss'])&&!empty($payload['iss'])?$payload['iss']:"JWT-Issuer"),
            'iat' => time(),
            'exp' => time() + (isset($payload['exp'])&&!empty($payload['exp']))?$payload['exp']:3600,
            'aud' => (isset($payload['aud'])&&!empty($payload['aud']))?$payload['aud']:'Audience',
        ];
        
        if (isset($payload['nbf'])&&!empty($payload['nbf'])) {
            $defaultPayload['nbf'] = $payload['nbf'];
        }elseif(isset($payload['nbf'])&&empty($payload['nbf'])) {
            unset($payload['nbf']);
        }
        
        if (isset($payload['sub'])&&!empty($payload['sub'])) {
            $defaultPayload['sub'] = $payload['sub'];
        }elseif(isset($payload['sub'])&&empty($payload['sub'])) {
            unset($payload['sub']);
        }
        
        if (isset($payload['key']) && !empty($payload['key'])) {
            foreach ($payload['key'] AS $key => $value) {
                $payload[$key] = $value;
            }
            unset($payload['key']);
        }
        // Merge the default payload with the provided payload
        return array_merge($defaultPayload, $payload);
    }
    
    /**
     * Generates a signed JWT token.
     *
     * This method creates a JWT with the specified payload, encodes it, and signs it with the private key.
     * Optionally, the token can be encrypted before being returned.
     *
     * @param array $payload The payload to be included in the token.
     * @param bool $encrypt Whether to encrypt the token after signing.
     * @return string The generated JWT token.
     */
    public function generateToken(array $payload)
    {
        $header = [
            'alg' => $this->algorithm,
            'typ' => $this->type
        ];

        $now = time();
        
        $payload = $this->preparePayload($payload);
        
        $headerEncoded = $this->base64UrlEncode(json_encode($header));
        $payloadEncoded = $this->base64UrlEncode(json_encode($payload));
        
        $signature = $this->sign("$headerEncoded.$payloadEncoded");

        $token = "$headerEncoded.$payloadEncoded.$signature";
        
        return $token;
    }
    
    /**
     * Decodes a JWT token.
     *
     * This method is a placeholder for decoding a JWT token. It needs to be implemented to parse the token
     * and extract the payload.
     *
     * @param string $token The JWT token to decode.
     */
    public function decodeToken($token) {
        // To be implemented: decode the token and extract the payload
    }
    
    /**
     * Verifies a JWT token.
     *
     * This method checks if a token is valid by verifying its signature and claims.
     * It supports checking for token encryption and validating claims against a configuration payload.
     *
     * @param object $conf_payload The configuration payload with expected claim values.
     * @param string $token The JWT token to verify.
     * @param bool $checkClaims Whether to validate the claims in the token.
     * @return array|bool The decoded payload if valid, or an array with errors if invalid.
     */
    public function verifyToken($conf_payload, $token, $checkClaims = true)
    {

        try {
            list($headerEncoded, $payloadEncoded, $signatureEncoded) = explode('.', $token);
        } catch (Exception $exc) {
            return ['errors' => 'Invalid headers'];
        }        

        $signature = $this->base64UrlDecode($signatureEncoded);

        $validSignature = openssl_verify("$headerEncoded.$payloadEncoded", $signature, $this->publicKey, OPENSSL_ALGO_SHA256);
        
        if ($validSignature !== 1) {
            return ['errors' => 'Invalid signature'];
        }
        
        $payload = json_decode($this->base64UrlDecode($payloadEncoded), true);
        
        if ($checkClaims) {
            
            $validateClaims = $this->validateClaims($conf_payload, $payload);
            
            if (isset($validateClaims['errors'])) {
                return $validateClaims;
            }            
        }
        
        return $payload;
    }
    
    /**
     * Signs data using the private key.
     *
     * This method uses the private key to sign the provided data string using the specified algorithm.
     * The signature is then base64 URL encoded and returned.
     *
     * @param string $data The data to sign.
     * @return string The base64 URL encoded signature.
     * @throws Exception If the private key resource cannot be obtained.
     */
    private function sign(string $data): string
    {
        $privateKeyResource = openssl_pkey_get_private($this->privateKey);
        if (!$privateKeyResource) {
            throw new Exception("Unable to get private key resource");
        }
        openssl_sign($data, $signature, $privateKeyResource, OPENSSL_ALGO_SHA256);
        return $this->base64UrlEncode($signature);
    }
    
    /**
     * Verifies the signature of a JWT token.
     *
     * This method checks the validity of a token's signature using the public key and the specified algorithm.
     * It decodes the signature from base64 URL format before verification.
     *
     * @param string $data The signed data.
     * @param string $signature The signature to verify.
     * @return bool True if the signature is valid, false otherwise.
     * @throws Exception If the public key resource cannot be obtained.
     */
    private function verifySignature(string $data, string $signature): bool
    {
        $decodedSignature = $this->base64UrlDecode($signature);
        $publicKeyResource = openssl_pkey_get_public($this->publicKey);
        if (!$publicKeyResource) {
            throw new Exception("Unable to get public key resource");
        }
        return openssl_verify($data, $decodedSignature, $publicKeyResource, OPENSSL_ALGO_SHA256) === 1;
    }
    
    private function validateClaims($conf_payload, $payload) {
        $currentTime = time();
        $errors = [];
        // Verificar expiración
        if (isset($payload['exp']) && $payload['exp'] < $currentTime) {
            $errors['exp'] = '[exp] Token has expired';
        }
        
        // Verificar issued at
        if (isset($payload['iat']) && $payload['iat'] > $currentTime) {
            $errors[] = '[iat] Token issued in the future';
        }
        
        // Verificar issuer
        if (isset($payload['iss']) && $payload['iss'] !== $conf_payload->iss) {
            $errors[] = '[iss] Invalid issuer';
        }
        
        // Verificar audience
        if (isset($payload['aud']) && $payload['aud'] !== $conf_payload->aud) {
            $errors[] = '[aud] Invalid audience';
        }
        
        // Verificar subject
        if (isset($payload['sub']) && $payload['sub'] !== $conf_payload->sub) {
            $errors[] = '[sub] Invalid subject';
        }
        
        if (!empty($errors)) {
           return ['errors' => $errors]; 
        }
        
        return true;
        // Puedes agregar más validaciones personalizadas aquí
    }
    
    private function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    private function base64UrlDecode(string $data): string
    {
        $data = strtr($data, '-_', '+/');
        $padding = strlen($data) % 4;
        if ($padding) {
            $data .= str_repeat('=', 4 - $padding);
        }
        return base64_decode($data);
    }
    
}


