<?php

class RSAKeyManager {
    private $keysPath;
    private $privateKey;
    private $publicKey;


    public function __construct($keysPath, $keys) {

       $this->keysPath = $keysPath;
       $this->privateKey = $keys['private'];
       $this->publicKey = $keys['public'];
    }
    
    public function checkKeys() {
        return $this->loadKeys();
    }
    
    private function loadKeys() {
        
        if(is_dir($this->keysPath)) {
            
            $this->privateKey = $this->keysPath.$this->privateKey;
            $this->publicKey = $this->keysPath.$this->publicKey;
            // Si las llaves no existen, generarlas
            if (!file_exists($this->privateKey) || !file_exists($this->publicKey)) {
                $result = [
                    'error' => true,
                    'msg'   => 'RSA Keys not found',
                ];
                return $result;

            }
        }

        // Leer la clave privada
        $this->privateKey = file_get_contents($this->privateKey);
        if ($this->privateKey === false) {
            $result = [
                'error' => true,
                'msg'   => 'Failed to read private key',
            ];
            return $result;
        }

        // Verificar si el archivo de clave pública existe
        if (!file_exists($this->publicKey)) {
            
            $result = [
                'error' => true,
                'msg'   => 'Public key file does not exist',
            ];
            return $result;
        }

        // Leer la clave pública
        $this->publicKey = file_get_contents($this->publicKey);
        if ($this->publicKey === false) {
             $result = [
                'error' => true,
                'msg'   => 'Failed to read public key',
            ];
            return $result;
        }
        
        return true;

    }

    private function validateKeys() {
        // Verificar la validez de la clave privada
        if (!openssl_pkey_get_private($this->privateKey)) {
            throw new Exception('Invalid private key');
        }

        // Verificar la validez de la clave pública
        if (!openssl_pkey_get_public($this->publicKey)) {
            throw new Exception('Invalid public key');
        }
    }

    public function generateRSAKeys($keySize = 2048) {
        // Configuración para generar la clave RSA
        $config = [
            "private_key_bits" => $keySize,
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
        ];

        // Crear una nueva clave privada
        $privateKeyResource = openssl_pkey_new($config);

        // Extraer la clave privada del recurso
        openssl_pkey_export($privateKeyResource, $privateKey);

        // Obtener la clave pública a partir de la clave privada
        $publicKeyDetails = openssl_pkey_get_details($privateKeyResource);
        $publicKey = $publicKeyDetails['key'];
        
        try {
            // Guardar las claves en archivos
            file_put_contents($this->keysPath.$this->privateKey, $privateKey);
            file_put_contents($this->keysPath.$this->publicKey, $publicKey);
            return true;
        } catch (Exception $error) {
            return $error;
        }   
    }

    public function getPrivateKey() {
        return $this->privateKey;
    }

    public function getPublicKey() {
        return $this->publicKey;
    }
}

function generateRSAKeys($keySize = 2048) {
    // Generar un nuevo par de claves RSA
    $config = [
        "private_key_bits" => $keySize,
        "private_key_type" => OPENSSL_KEYTYPE_RSA,
    ];

    // Crear una nueva clave privada
    $privateKeyResource = openssl_pkey_new($config);

    // Extraer la clave privada del recurso
    openssl_pkey_export($privateKeyResource, $privateKey);

    // Obtener la clave pública a partir de la clave privada
    $publicKeyDetails = openssl_pkey_get_details($privateKeyResource);
    $publicKey = $publicKeyDetails['key'];

    // Guardar las claves en archivos
    file_put_contents($privateKeyPath, $privateKey);
    file_put_contents($publicKeyPath, $publicKey);

    echo "Private key and public key have been generated and saved.\n";
}

