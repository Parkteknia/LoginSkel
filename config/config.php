<?php

if (!defined('SECURE_ACCESS')) {
    header('HTTP/1.0 403 Forbidden', true, 403);
}

return [
    'db_dsn' => 'mysql:host=localhost;dbname=',
    'db_username' => '',
    'db_password' => '',
    'jwt_encrypt_key' => '',
    'keys_path' => '',
    'keys_name' => ['private' => 'private.key','public' => 'public.key'],
    'qr_codes_folder' => ''
];
