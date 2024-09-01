<?php

require 'LoginSkelException.php';
require '../lib/Translator.php';
require '../lib/TOTP.php';
require '../lib/phpqrcode/qrlib.php';

/**
 * LoginSkel.php Class
 *
 * The features included in the class have been organized by sections to facilitate understanding and navigation.
 * 
 *
 * @category   Authentication and Authorization Web Interfaces
 * @package    LoginSkel
 * @author     P3r4nd <author@example.com>
 * @copyright  2024 - Parkteknia
 * @version    Release: @1.0@
 * @link       https://github.com/Parkteknia/LoginSkel
 */
class LoginSkel {

    private $config;
    private $app_debug = true;
    private $pdo;
    private $lang;
    private $translator;
    private $timezone;
    private $app_url;
    private $app_path;
    private $app_errors;
    private $cookie_domain;
    private $session_name;
    private $max_attempts;
    private $max_attempts_interval;
    private $block_duration;
    private $hash_algo;
    private $ps_protect;
    private $validate_account;
    private $validate_method;
    private $jwt;
    private $jwt_encrypt;
    private $jwt_encrypt_key;
    private $keys_path;
    private $keys_name;
    private $twoFactor;
    private $totp;
    private $qrDirectory;
    private $filtersDirectory;

    // ================================
    // SECTION: Constructor
    // ================================

    /**
     * LoginSkel constructor.
     */
    public function __construct() {
        
        // Set debug mode to show errors or not
        $this->setDebugMode();
        
        // Prevent direct access in some files
        define('SECURE_ACCESS', true);

        // Load config file
        $config = require '../config/config.php';

        // Run all configurations
        $this->globalConfig($config);
    }
    
    /**
     * Set debug mode based on the app_debug property.
     *
     * If app_debug is true, set error reporting to show all errors.
     * If app_debug is false, set error reporting to hide errors.
     */
    private function setDebugMode() {
        if ($this->app_debug) {
            ini_set('display_errors', 1);
            ini_set('display_startup_errors', 1);
            error_reporting(E_ALL);
        } else {
            ini_set('display_errors', 0);
            ini_set('display_startup_errors', 0);
            error_reporting(0);
        }
    }
    
    // ================================
    // SECTION: Set initial configuration
    // ================================

    /**
     * Set initial global configuration.
     * 
     * @param array $config is from config/config.php saved during install
     */
    private function globalConfig($config) {

        // Set config.php
        $this->config = $config;

        // DB Configuration
        $this->configDB();
        
        if ($this->app_errors) {
            
            return;
        }
        // LoginSkel Global configuration
        $this->configLoginSkel();

        // Session configuration
        $this->configSession();

        // Lang configuration
        $this->configGlobalLang();

        // Two Factor configuration
        $this->config2fa();

        // Global JWT configuration
        $this->configGlobalJWT();

        // Date and Time configuration
        $this->configGlobalDateTime();
    }

    // ================================
    // SECTION: Database configuration
    // ================================

    /**
     * Configures the database connection using PDO.
     *
     * This function initializes the PDO object with the database connection details 
     * provided in the configuration config.php. It sets error handling and fetch mode options 
     * for the PDO instance.
     * 
     * If the connection fails, it catches the exception and logs a "db_error" to the application errors.
     *
     * @return void
     */
    private function configDB() {

        try {
            $db_access = [
                'db_dsn' => $this->config['db_dsn'],
                'db_username' => $this->config['db_username'],
                'db_password' => $this->config['db_password']
            ];

            $this->pdo = new PDO($db_access['db_dsn'], $db_access['db_username'], $db_access['db_password']);
            $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            $this->pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
        } catch (Exception $exc) {
            $this->app_errors[] = "db_error";
        }
    }

    // ================================
    // SECTION: LoginSkel default global configuration
    // ================================

    /**
     * Configures the default global settings for the LoginSkel application.
     *
     * This function retrieves the global configuration settings stored as a JSON string 
     * in the database or configuration file, decodes them into an associative array, 
     * and merges them with the existing configuration settings.
     * 
     * If the global configuration is successfully retrieved, it initializes several 
     * application-specific properties such as URLs, paths, error tracking, security settings, 
     * and other application settings.
     *
     * @return void
     */
    private function configLoginSkel() {

        // Retrieve global configuration from storage and decode it into an array
        $globalConfig = (array) json_decode($this->getConfigByKey('global_config'));

        // Merge the global configuration into the current configuration
        $this->config = array_merge($this->config, $globalConfig);

        if ($globalConfig) {
            // Initialize application-specific properties based on global configuration
            $this->app_url = $globalConfig['app_url'];
            $this->app_path = $globalConfig['app_path'];
            $this->app_errors = [];
            $this->cookie_domain = $globalConfig['cookie_domain'];
            $this->max_attempts = $globalConfig['max_attempts'];
            $this->max_attempts_interval = $globalConfig['max_attempts_interval'];
            $this->block_duration = $globalConfig['block_duration'];
            $this->validate_account = $globalConfig['validate_account'];
            $this->validate_method = $globalConfig['validate_method'];
            $this->hash_algo = $globalConfig['hash_algo'];
            $this->ps_protect = $globalConfig['ps_protect'];
            $this->filtersDirectory = "../filters";
            $this->jwt = $globalConfig['jwt_auth'];
        }
    }

    // ================================
    // SECTION: Session and Cookies functions
    // ================================

    /**
     * Configures and starts a new session with specific security settings.
     *
     * This function sets up session configurations such as the session name,
     * cookie parameters, and security options to enhance session security.
     * It ensures that sessions are secure and consistent across different environments.
     *
     * Session configurations include:
     * - Custom session name defined in the configuration.
     * - Cookie parameters such as lifetime, path, domain, security flags (secure, httponly), and SameSite attribute.
     * - The session is started after configuration is set.
     *
     * @return void
     */
    private function configSession() {

        // Session config
        session_name($this->config['session_name']);

        session_set_cookie_params([
            'lifetime' => 0,
            'path' => '/',
            'domain' => $this->config['cookie_domain'],
            'secure' => isset($_SERVER['HTTPS']),
            'httponly' => true,
            'samesite' => 'Strict',
        ]);

        session_start();
    }

    /**
     * Registers a new session for the user.
     *
     * This function creates a new session record in the database using the provided
     * user ID, IP address, and user agent. It's used to track user sessions and 
     * enhance security by monitoring session data.
     *
     * @param int $user_id The ID of the user who is logging in.
     * @param string $ip The IP address from which the user is logging in.
     * @param string $user_agent The user agent string of the user's browser.
     * 
     * @return void
     */
    private function registerSession($user_id, $ip, $user_agent) {

        // Regenerate session ID to prevent session fixation
        session_regenerate_id(true);

        $session_id = session_id();

        // Generate a random session ID
        $user_session_id = $this->generateRandomToken(32);

        $_SESSION[$this->session_name] = $user_session_id;

        $this->insertUserSession($session_id, $user_session_id, $user_id, $ip, $user_agent, 'active');

        $this->clearLoginAttempts($ip);
    }
    
    /**
     * 
     * Set New Cookies
     *
     * @param string $access_token  
     * @param string $refresh_token
     */
    private function setNewCookies($access_token, $refresh_token) {

        setcookie('access_token', $access_token, [
            'expires' => time() + 3600,
            'path' => $this->app_path,
            'domain' => $this->cookie_domain,
            'secure' => true,
            'httponly' => true,
            'samesite' => "strict"]);

        setcookie('refresh_token', $refresh_token, [
            'expires' => time() + (30 * 24 * 60 * 60),
            'path' => $this->app_path,
            'domain' => $this->cookie_domain,
            'secure' => true,
            'httponly' => true,
            'samesite' => "strict"]);
    }

    // ================================
    // SECTION: Lang functions
    // ================================

    /**
     * Configures the global language settings for the application.
     *
     * This function checks if the language is already set in the session. 
     * If not, it initializes the language to the default language specified in the configuration 
     * and sets it accordingly. This ensures that the application has a consistent language 
     * setting for all users.
     *
     * @return void
     */
    private function configGlobalLang() {

        // Check if the language is not set in the session
        if (!isset($_SESSION['lang'])) {
            // Set the language to the default language specified in the configuration
            $this->lang = $this->config['default_lang'];

            // Apply the language setting
            $this->setLanguage($this->lang);
        }
    }

    /**
     * 
     * Get available langs in ../locale folder
     *
     */
    private function getAvailableLangs($path = '../locale') {

        $dirs = scandir($path);
        $langs = [];

        foreach ($dirs as $dir) {
            if ($dir === '.' || $dir === '..') {
                continue; // We skip the special directories '.' and '..'
            }

            if (is_dir($path . '/' . $dir)) {
                $langs[] = $dir;
            }
        }

        return $langs;
    }

    /**
     * 
     * Set LoginSkel Language is called from public configLang()
     *
     * @param string $lang  Regional code identifier
     */
    private function setLanguage($lang = null) {
        if (isset($lang)) {

            if ($this->isValidLanguage($lang)) {
                $_SESSION['lang'] = $lang;
                $this->lang = $lang;
            }
        }

        if (!isset($_SESSION['lang'])) {
            $_SESSION['lang'] = $this->lang; // Default language
        }
    }

    /**
     * 
     * Check if lang exists in locale folder
     *
     * @param string $lang  Regional code identifier
     * @return boolean
     */
    private function isValidLanguage($lang) {
        return is_dir('../locale/' . $lang);
    }

    /**
     * 
     * GetLangName($lang) is used from renderLangMenu($lang) to display each language in its own language
     *
     * @param string $lang  Regional code identifier
     * @return string Lang Name
     */
    private function getLangName($lang) {
        $messages = include('../locale/' . $lang . '/messages.php');
        return $messages[$lang];
    }

    /**
     * 
     * Render lang menu selector in pages
     *
     * @param string $current_lang  Current active lang
     * @return html Menu lang select
     */
    public function renderLangMenu($current_lang) {

        $lang_menu = '<select id="language-select" name="lang" onchange="this.form.submit()">';

        $langs = $this->getAvailableLangs();

        foreach ($langs AS $lang_key) {

            $lang_menu .= '<option value="' . $lang_key . '"' . (($lang_key === $current_lang) ? "selected" : "") . '>' . $this->getLangName($lang_key) . '</option>';
        }
        $lang_menu .= '</select>';

        return $lang_menu;
    }

    /**
     * 
     * Public function to call private $lang($lang)
     *
     * @param string $lang  Current active lang
     */
    public function configLang($lang) {
        $this->setLanguage($lang);
    }

    /**
     * 
     * Get current configured language
     *
     * @return string $lang  Regional code in $this->lang
     */
    public function getCurrentLanguage() {

        if (isset($_GET['lang'])) {
            $lang = $_GET['lang'];
            $this->configLang($lang);
        }

        if ($_SESSION['lang']) {
            return $_SESSION['lang'];
        }

        return $this->lang;
    }

    /**
     * 
     * Public function to call Translator and get translation for a key
     *
     * @return string $key Translated "key"
     */
    public function getTranslation($key) {
        $lang = $_SESSION['lang'];
        $messages = include('../locale/' . $lang . '/messages.php');

        return Translator::getTranslation($messages, $key) ?? $key;
    }
    
    // ================================
    // SECTION: Two-Factor Authentication (2FA)
    // ================================

    /**
     * Configures the two-factor authentication (2FA) settings for the application.
     *
     * Initializes 2FA settings based on the global configuration. 
     * Sets the 2FA status and QR code directory, and initializes the TOTP (Time-Based One-Time Password) instance.
     *
     * @return void
     */
    private function config2fa() {
        // Set 2FA status from the global configuration
        $this->twoFactor = $this->config['2fa_auth'];
        // Set directory for storing QR codes
        $this->qrDirectory = $this->config['qr_codes_folder'];
        // Initialize TOTP instance for generating and verifying one-time passwords
        $this->totp = new TOTP();
    }

    /**
     * Disables two-factor authentication (2FA) for the application.
     *
     * Updates the global configuration to set 2FA as disabled.
     *
     * @return bool True on success, False on failure
     */
    public function disable2FA() {

        return $this->updateGlobalConfig("2fa_auth", false);
    }

    /**
     * Enables two-factor authentication (2FA) for the application.
     *
     * Updates the global configuration to set 2FA as enabled.
     *
     * @return void
     */
    public function enable2FA() {

        $this->updateGlobalConfig("2fa_auth", true);
    }

    /**
     * Retrieves the TOTP (Time-Based One-Time Password) instance.
     *
     * Provides access to the TOTP instance for generating and verifying one-time passwords.
     *
     * @return TOTP The TOTP instance used for 2FA
     */
    public function getTOPT() {
        return $this->totp;
    }
    
    /**
    * Generates a new TOTP secret key for a user and updates it in the database.
    *
    * This function creates a new secret key for the TOTP using the TOTP class instance,
    * and updates this key in the database for the specified user. The TOTP is used
    * for two-factor authentication (2FA), providing an additional layer of security.
    *
    * @param string $username The username of the user to be assigned the new secret key.
    * @return bool Returns true if the secret key was successfully updated, otherwise returns false.
    */
    public function genAndUpdateUserTotp($username) {

        $totp = new TOTP();
        $secret = $totp->generateSecret();

        // Prepare the SQL query to save the user's secret key
        $sql = "UPDATE users SET secret_key = :secret_key WHERE username = :username";

        // Prepare the declaration
        $stmt = $this->pdo->prepare($sql);

        // Execute the statement
        $stmt->execute([
            ':secret_key' => $secret,
            ':username' => $username
        ]);

        // Check if the update was successful
        if ($stmt->rowCount() > 0) {
            return true;
        } else {
            return false;
        }
    }
    
    /**
     * Retrieves the 2FA configuration for a specific user.
     *
     * Fetches the 2FA settings from the database or configuration for the given user ID.
     *
     * @param int $user_id The ID of the user whose 2FA configuration is being retrieved
     * @return mixed The user's 2FA configuration data, or null if not set
     */
    public function getUser2faConf($user_id) {

        return $this->getUser2fa($user_id);
    }

    /**
     * Updates the 2FA configuration for a specific user.
     *
     * Modifies the user's 2FA settings in the database or configuration.
     *
     * @param string $username The username of the user whose 2FA configuration is being updated
     * @param mixed $conf The new 2FA configuration data to be set for the user
     * @return bool True on success, False on failure
     */
    public function updateUser2faConf($username, $conf) {

        return $this->updateUser2fa($username, $conf);
    }
    
    // ================================
    // SECTION: Global Configuration functions
    // ================================

    /**
     * 
     * Update global config by $key => $value
     *
     * @param string $key  "key" inside global_config 
     * @param string $value  "value" for a "key" inside global_config
     * @param string $extra_config  Setted only for  validate_account and method to validate
     * @return boolean
     */
    private function updateGlobalConfig($key, $value, $extra_config = null) {

        $globalConfig = (array) json_decode($this->getConfigByKey('global_config'));

        switch ($key) {
            
            case 'jwt_auth':

                $globalConfig['jwt_auth'] = ($value===true?true:false);

                break;
            
            case 'hash_algo':

                $globalConfig['hash_algo'] = $value;

                break;

            case 'ps_protect':

                $globalConfig['ps_protect'] = $value;

                break;

            case '2fa_auth':

                $globalConfig['2fa_auth'] = $value;

                break;

            case 'validate_account':

                $globalConfig['validate_account'] = $value;

                if (isset($extra_config)) {
                    $validValues = ['code', 'token'];
                    if (in_array($extra_config, $globalConfig)) {
                        $globalConfig['validate_method'] = $extra_config;
                    }
                }

                break;
            default:
                break;
        }

        try {

            $stmt = $this->pdo->prepare("UPDATE config SET conf_value = :conf_value WHERE conf_key = :conf_key");

            $stmt->execute([
                ':conf_key' => 'global_config',
                ':conf_value' => json_encode($globalConfig)
            ]);
            $this->refreshGlobalConfig();
            return true;
        } catch (Exception $ex) {
            return $ex->getMessage();
        }
    }

    /**
     * 
     * Bulk Update global config
     *
     * @param array $conf_data  More than one "key => value" from global_config array
     */
    private function bulkUpdateGlobalConfig($conf_data) {

        $globalConfig = (array) json_decode($this->getConfigByKey('global_config'));

        foreach ($conf_data AS $key => $value) {

            $globalConfig[$key] = $value;
        }

        try {

            $stmt = $this->pdo->prepare("UPDATE config SET conf_value = :conf_value WHERE conf_key = :conf_key");

            $stmt->execute([
                ':conf_key' => 'global_config',
                ':conf_value' => json_encode($globalConfig)
            ]);
        } catch (Exception $ex) {
            return $ex->getMessage();
        }
    }

    /**
     * 
     * Public function to access bulkUpdateGlobalConfig()
     *
     * @param array $conf_data  More than one "key => value" from global_config array
     */
    public function bulkUpdate($conf_data) {
        return $this->bulkUpdateGlobalConfig($conf_data);
    }

    /**
     * 
     * Refresh configuration after global_config udpate
     *
     */
    public function refreshGlobalConfig() {
        $this->configLoginSkel();
        $this->config2fa();
    }

    // ================================
    // SECTION: Password Hash Algorithm
    // ================================

    public function updatePasswordHashAlgorithm($algo) {
        $this->updateGlobalConfig('hash_algo', $algo);
    }

    // ================================
    // SECTION: Password Protect
    // ================================

    public function enablePassProtect() {
        $this->updateGlobalConfig('ps_protect', 'true');
    }

    public function disablePassProtect() {
        $this->updateGlobalConfig('ps_protect', 'false');
    }

    // ================================
    // SECTION: Validation account
    // ================================

    public function disableValidateAccount() {

        $this->updateGlobalConfig("validate_account", false);
    }

    public function enableValidateAccount($validate_method) {

        $this->updateGlobalConfig("validate_account", true, $validate_method);
    }

    

    // ================================
    // SECTION: Global LoginSkel functions
    // ================================

    function getDirectoryPath() {
        // Break down the URL into components
        $parsedUrl = parse_url($this->getBaseDirURL());

        // Get the URL path
        $path = $parsedUrl['path'] ?? '';

        // Delete the file at the end of the path (e.g. 'index.php')
        $pathWithoutFile = preg_replace('/\/[^\/]*$/', '', $path);

        return $pathWithoutFile;
    }

    function checkDirectory($directoryPath) {
        if (!is_dir($directoryPath)) {
            return $this->getTranslation('directory_not_exists');
        }

        if (!is_writable($directoryPath)) {
            return $this->getTranslation('directory_not_writable');
        }

        return true;
    }

    public function getBaseDirURL() {
        $scheme = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http';
        $host = $_SERVER['HTTP_HOST'];
        $requestUri = $_SERVER['REQUEST_URI'];

        return $scheme . '://' . $host . $requestUri;
    }

    private function isValidURL($url) {
        return filter_var($url, FILTER_VALIDATE_URL) !== false;
    }

    private function isValidTimezone($timezone) {
        $validTimezones = DateTimeZone::listIdentifiers();

        return in_array($timezone, $validTimezones);
    }

    public function validateConfig($data) {

        $errors = [];

        foreach ($data AS $key => $value) {

            switch ($key) {

                case 'timezone':

                    if (!$this->isValidTimezone($data['timezone'])) {
                        $errors['timezone'] = $this->getTranslation('invalid_timezone');
                    } else {
                        $_SESSION['timezone'] = $data['timezone'];
                    }

                    break;

                case 'app_url':

                    if (!$this->isValidURL($data['app_url'])) {
                        $errors['appurl'] = $this->getTranslation('invalid_url');
                    } else {
                        $_SESSION['app_url'] = $data['app_url'];
                    }
                    break;

                case 'app_path':

                    if ($this->getDirectoryPath() !== $data['app_path']) {
                        $errors['apppath'] = $this->getTranslation('invalid_app_path');
                    } else {
                        $_SESSION['app_path'] = $data['app_path'];
                    }
                    break;

                case 'max_attempts':

                    if (!filter_var($data['max_attempts'], FILTER_VALIDATE_INT)) {
                        $errors['max_attempts'] = $this->getTranslation('invalid_max_attempts');
                    } else {
                        $_SESSION['max_attempts'] = $data['max_attempts'];
                    }
                    break;

                case 'max_attempts_interval':

                    $intervals = ['second', 'minute', 'hour', 'day', 'week', 'month', 'year'];
                    $interval = explode(" ", $data['max_attempts_interval']);

                    if (!filter_var((int) $interval[0], FILTER_VALIDATE_INT) || !in_array($interval[1], $intervals)) {
                        $errors['max_attempts_interval'] = $this->getTranslation('invalid_interval');
                    } else {
                        $_SESSION['max_attempts_interval'] = $data['max_attempts_interval'];
                    }
                    break;

                case 'block_duration':

                    if (!filter_var($data['block_duration'], FILTER_VALIDATE_INT)) {
                        $errors['block_duration'] = $this->getTranslation('invalid_block_interval');
                    } else {
                        $_SESSION['block_duration'] = $data['block_duration'];
                    }
                    break;

                case 'toggle_validate':

                    if ($data['toggle_validate']) {

                        $_SESSION['validate_account'] = true;
                    }
                    break;

                case 'validate_method':

                    if ($_SESSION['validate_account']) {
                        if ($data['validate_method'] === 'code' || $data['validate_method'] === 'token') {
                            $_SESSION['validate_method'] = $data['validate_method'];
                        } else {
                            $errors['validate_method'] = $this->getTranslation('invalid_validate_method');
                        }
                    }
                    break;

                case 'toggle_jwt':

                    if ($data['toggle_jwt']) {

                        $_SESSION['jwt_auth'] = true;
                    }
                    break;

                case 'keys_path':

                    if ($_SESSION['jwt_auth']) {
                        $check_path = $this->checkDirectory($data['keys_path']);
                        if (true !== $check_path) {
                            $errors['jwt_keys_path'] = $check_path;
                        } else {
                            $_SESSION['keys_path'] = $data['keys_path'];
                        }
                    }

                case 'toggle_2fa':

                    if ($data['toggle_2fa']) {

                        $_SESSION['2fa_auth'] = true;
                    }
                    break;

                case 'codes_path':

                    if ($_SESSION['2fa_auth']) {
                        unset($_SESSION['errors']['2fa_codes_path']);
                        $check_path = $this->checkDirectory($data['codes_path']);
                        if (true !== $check_path) {
                            $errors['2fa_codes_path'] = $check_path;
                        } else {
                            $_SESSION['qr_codes_folder'] = $data['codes_path'];
                        }
                    }
                    break;

                case 'toggle_jwt_encrypted':

                    if ($data['toggle_jwt_encrypted']) {

                        $_SESSION['jwt_encrypt'] = true;
                    }
                    break;

                case 'encryption_key':

                    if (isset($_SESSION['jwt_encrypt'])) {

                        if (empty($data['encryption_key'])) {
                            $errors['no_encryption_key'] = $this->getTranslation('no_encryption_key');
                        } else {
                            $_SESSION['jwt_encrypt_key'] = $data['encryption_key'];
                        }
                    }

                default:
                    break;
            }
        }

        if (empty($errors)) {
            return true;
        }

        return $errors;
    }

    // ================================
    // SECTION: Validation functions
    // ================================

    public function validateUsername($username) {
        return preg_match('/^[a-zA-Z][a-zA-Z0-9_]{5,}$/', $username);
    }

    public function validateEmail($email) {
        return filter_var($email, FILTER_VALIDATE_EMAIL);
    }

    /**
     * Checks if the specified hashing algorithm is available in the PHP environment.
     *
     * @param string $algo Algorithm to verify. Must be 'bcrypt' or 'argon2'.
     * @return bool Returns true if the algorithm is available, false otherwise.
     */
    public function validateHashAlgorithm($algo) {
        switch ($algo) {
            case 'bcrypt':
                // Check if bcrypt is available
                return defined('PASSWORD_BCRYPT');

            case 'argon2':
                // Check PHP version
                if (version_compare(PHP_VERSION, '7.2.0', '<')) {
                    return false; // Argon2 requires PHP 7.2.0 or higher
                }

                // Check if password_hash function supports Argon2
                $hash = password_hash('test', PASSWORD_ARGON2I);
                return $hash !== false;

            default:
                // Unrecognized algorithm
                return false;
        }
    }

    public function validatePassword($password) {

        if ($this->ps_protect) {
            if ($this->isKnownPassord($password)) {
                return ['error' => 'ps_known'];
            }

            return preg_match('/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_])[A-Za-z\d\W_]{8,128}$/', $password);
        }

        return preg_match('/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_])[A-Za-z\d\W_]{8,128}$/', $password);
    }

    private function isKnownPassord($password) {
        // Get the list of .txt files in the directory
        $files = $this->readFilterFiles();

        // Go through each file and look for the password
        foreach ($files as $filePath) {
            // Open the file in read-only mode
            $file = fopen($filePath, 'r');
            if (!$file) {
                continue; // If the file cannot be opened, go to the next one
            }
            // Loop through each line of the file
            while (($line = fgets($file)) !== false) {
                // Removes whitespace (including line breaks)
                $line = trim($line);

                // Compare the current line with the password
                if ($line === $password) {
                    fclose($file);
                    return true; // If the password is found, return true
                }
            }

            // Close file
            fclose($file);
        }

        // If the password was not found in any of the files, return false
        return false;
    }

    // ================================
    // SECTION: Register accounts
    // ================================

    public function register($ip, $user_agent, $username, $email, $password) {

        if (!$this->validRegisterAttempt($ip)) {
            $this->blockIp($ip);
            return false;
        }

        // Register registration attempt
        $stmt = $this->pdo->prepare("INSERT INTO register_attempts (ip_address, user_agent, attempt_username, attempt_email) VALUES (:ip_address, :user_agent, :attempt_username, :attempt_email)");
        $stmt->bindParam(':ip_address', $ip);
        $stmt->bindParam(':user_agent', $user_agent);
        $stmt->bindParam(':attempt_username', $username);
        $stmt->bindParam(':attempt_email', $email);
        $stmt->execute();

        $stmt = $this->pdo->prepare("SELECT id FROM users WHERE username = :username OR email = :email");
        $stmt->execute(['username' => $username, 'email' => $email]);
        $user = $stmt->fetch();

        if ($user) {
            // Dummy comparison to normalize response time
            password_verify($password, password_hash(bin2hex(random_bytes(32)), PASSWORD_DEFAULT));
            return false; // User exists
        } else {
            // Dummy comparison if user does not exist
            password_verify($password, password_hash(bin2hex(random_bytes(32)), PASSWORD_DEFAULT));
        }

        $roleID = $this->getRoleID();

        if ($this->hash_algo === 'bcrypt') {
            $hash = $this->hashPasswordBcrypt($password);
        }

        if ($this->hash_algo === 'argon2') {
            $hash = $this->hashPasswordArgon2($password);
        }

        $stmt = $this->pdo->prepare("INSERT INTO users (username, email, password, role_id, activation_code) VALUES (:username, :email, :password, :role_id, :activation_code)");
        $stmt->execute([
            'username' => $username,
            'email' => $email,
            'password' => $hash,
            'role_id' => $roleID,
            'activation_code' => null]);

        $userID = $this->pdo->lastInsertId();

        if ($this->validate_account) {

            if ($this->validate_method === "token") {
                // Generate the account validation token
                $token = $this->generateRandomToken(32);
                $stmt = $this->pdo->prepare("INSERT INTO tokens (user_id, token, generated_at, token_type, status) VALUES (:user_id, :token, NOW(), 'account_validate', 'valid')");
                $stmt->execute([
                    'user_id' => $userID,
                    'token' => $token,
                ]);

                // Send the validation email to the user
                $validation_link = $this->buildLink("actv_link", $token);
                $email_body = sprintf("%s: %s", $this->getTranslation('validate_account_title'), $validation_link);
            }

            if ($this->validate_method === "code") {
                $actv_code = random_int(100000, 999999);
                $stmt = $this->pdo->prepare('UPDATE users SET activation_code = :activation_code, code_at = NOW() WHERE id = :id');
                $stmt->execute([
                    'id' => $userID,
                    'activation_code' => $actv_code]);
                $_SESSION['activation_code'] = $token;
                $email_body = sprintf("%s: %s", $this->getTranslation('actvation_account_code_title'), $actv_code);
            }

            mail($email, $this->getTranslation('validate_your_account'), $email_body);
        } else {
            $stmt = $this->pdo->prepare('UPDATE users SET status = :status WHERE id = :id');
            $stmt->execute([
                'id' => $userID,
                'status' => 'active']);
        }

        if ($this->twoFactor) {

            if ($this->genAndUpdateUserTotp($username)) {
                return true;
            }
        }

        return true;
    }
    
    // ================================
    // SECTION: JWT Configuration and Functions
    // ================================

    /**
     * Configures the JSON Web Token (JWT) settings for the application.
     *
     * Initializes JWT and encryption settings based on the global configuration.
     * If JWT or JWT encryption is enabled in the configuration, the corresponding libraries are included.
     *
     * @return void
     */
    private function configGlobalJWT() {
        // Set JWT and JWT encryption settings from the global configuration
        $this->jwt = $this->config['jwt_auth'];
        $this->jwt_encrypt = $this->config['jwt_encrypt'];
        
        // Set paths and keys for JWT encryption if required
        $this->keys_path = $this->config['keys_path'];
        $this->keys_name = $this->config['keys_name'];
        $this->jwt_encrypt_key = $this->config['jwt_encrypt_key'];
        
        // Include JWT library if JWT is enabled
        if ($this->jwt) {
            require '../lib/JWT.php';
        }
        
        // Include RSA Key Manager library if JWT encryption is enabled
        if ($this->jwt_encrypt) {
            require '../lib/RSAKeyManager.php';
            require '../lib/JWE.php';
        }
    }
    
    public function enableJWT() {
        
        $this->updateGlobalConfig('jwt_auth', true);

    }
    /**
    * Configures JWT (JSON Web Token) settings.
    *
    * This function initializes the JWT configuration based on current settings and configurations.
    * It checks if JWT is enabled, verifies global payload settings, and sets up encryption keys if needed.
    *
    * @return array|string JWT configuration array or an error message if JWT is disabled.
    */
    public function configJWT() {
        
        // Check if JWT is disabled
        if (!$this->jwt) {
            return "JWT Disabled!";
        }
        
        // Initialize JWT configuration array
        $jwt_config = [
            'enabled' => true,
            'global_payload' => true
        ];

        // Get global payload configuration
        $jwt_payload = $this->getConfigByKey('global_payload');
        $jwt_config['payload'] = json_decode($jwt_payload);
        
        // If payload is not set, disable global payload
        if (!$jwt_payload) {
            $jwt_config['global_payload'] = false;
        }
        
        return $jwt_config;
    }
    
    /**
    * Checks if JSON Web Token (JWT) is available and properly configured.
    *
    * This function verifies if JWT functionality is active and if the global payload configuration is set.
    * 
    * @return bool True if JWT is available and configured; otherwise, false.
    */
    public function JWTisAvailable() {
        // Check if JWT is active
        if (!$this->JWTisActive()) {
            return false;
        }
        // Get JWT configuration
        $jwtConfig = $this->configJWT();
        
        // Check if global payload is set and valid
        if (!isset($jwtConfig['global_payload']) || !$jwtConfig['global_payload']) {
            return false;
        }

        return true;
    }
    
    /**
    * Checks if JSON Web Token (JWT) is active.
    *
    * @return bool True if JWT is active; otherwise, false.
    */
    public function JWTisActive() {
        return $this->jwt;
    }
    
    public function JWEisEnabled() {
        return $this->jwt_encrypt;
        
    }
    
    private function storeTokenJTI($jti, $user_id) {
        $stmt = $this->pdo->prepare("INSERT INTO jwt_tokens (jti, user_id, created_at) VALUES (:jti, :user_id, NOW())");
        $stmt->execute([':jti' => $jti, ':user_id' => $user_id]);
    }
    
    private function generateEncryptedJWT() {

        $keys = [
            'private' => $this->keys_path . $this->keys_name['private'],
            'public' => $this->keys_path . $this->keys_name['public']
        ];
    }

    public function newJWTObject() {

        $keys = [
            'private' => $this->keys_path . $this->keys_name['private'],
            'public' => $this->keys_path . $this->keys_name['public']
        ];

        return new JWT($keys, 'RS256', 'JWT', $this->jwt_encrypt_key);
    }
    
    /**
    * Generates a JWT (JSON Web Token) for the given user.
    *
    * This function creates a JWT using the provided user ID and configuration settings. It includes
    * generating the token, parsing the payload, storing the JTI (JWT ID) if present, and saving it in the session.
    *
    * @param int $user_id The ID of the user for whom the JWT is being generated.
    * @return array An array containing the generated token and optionally the JTI.
    */
    private function generateJWT($user_id) {
        
        // Define paths to private and public key files
        $keys = [
            'private' => $this->keys_path . $this->keys_name['private'],
            'public' => $this->keys_path . $this->keys_name['public']
        ];
        
        // Initialize JWT instance with specified algorithm and encryption key
        $jwt = new JWT($keys, 'RS256', 'JWT', $this->jwt_encrypt_key);

        $jwt_obj = [];

        // Decode global payload configuration
        $payload = json_decode($this->getConfigByKey('global_payload'), true);
        
        // Parse payload for the specific user
        $parsed_payload = $this->parseJWTPayload($payload, $user_id);
        
        // Generate the JWT token
        $token = $jwt->generateToken($parsed_payload, false);

        $jwt_obj['token'] = $token;
        
        // Check if JTI (JWT ID) is present in the payload
        if (isset($parsed_payload['jti'])) {
            // Store JTI in the database and session
            $this->storeTokenJTI($parsed_payload['jti'], $user_id);
            $jwt_obj['jti'] = $parsed_payload['jti'];
            $_SESSION['jti'] = $parsed_payload['jti'];
        }

        return $jwt_obj;
    }
    
    /**
    * Retrieves the generated JWT for the current user.
    *
    * This function calls `generateJWT` to generate a new JWT for the current user. It assumes that 
    * `generateJWT` is configured to handle the current user's ID.
    *
    * @return array An array containing the generated token and optionally the JTI.
    */
    public function getJWT($user_id) {
        return $this->generateJWT($user_id);
    }
    
    /**
    * Registers or updates the global JWT payload in the configuration.
    *
    * This function saves the provided payload as a JSON-encoded string in the database under the key 'global_payload'.
    * If the entry already exists, it updates the existing record.
    *
    * @param array $payload The payload to be saved in the global configuration.
    * @return bool Returns true if the operation was successful, false otherwise.
    */
    private function registerJWTGlobalPayload($payload) {

        $globalPayload = json_encode($payload);

        // Prepare the SQL query for insertion or update
        $sql = "INSERT INTO config (`conf_key`, `conf_value`) VALUES (:conf_key, :conf_value)
                ON DUPLICATE KEY UPDATE `conf_value` = VALUES(`conf_value`)";

        try {
            $stmt = $this->pdo->prepare($sql);

            // Execute the SQL query with provided payload
            $stmt->execute([
                ':conf_key' => 'global_payload',
                ':conf_value' => $globalPayload
            ]);

            return true;
        } catch (PDOException $e) {
            return False;
        }
    }
    
    /**
    * Arrange JWT Payload 'keys'
    *
    * Custom payload keys come from form in a payload['custom_keys'] = array($key -> $type_of_key). (int, text, email, double)
    * This function assure that each array key has their 'type' assigned, and return array in an arranged Payload Keys array
    *
    * @param array $keys array of keys
    * @param array $types (text, int, email, double)
    * @return array $keyTypePairs
    */
    private function arrangePayloadKeys($keys, $types) {

        $types = $types ?? [];

        if (count($keys) !== count($types)) {
            echo "Error: Key and type arrays do not match.";
            exit;
        }

        $keyTypePairs = [];

        for ($i = 0; $i < count($keys); $i++) {
            $key = trim($keys[$i]);
            $type = trim($types[$i]);

            if (!empty($key)) {
                $keyTypePairs[$key] = $type;
            }
        }

        return $keyTypePairs;
    }
    
    /**
     * Validates the 'iss' (issuer) field of a JWT.
     *
     * @param mixed $iss The 'iss' field value to be validated.
     * 
     * @return bool Returns true if the 'iss' value is valid; otherwise, false.
     *
     * This function performs the following checks:
     * - If the 'iss' value is empty, it is considered valid as the 'iss' field is optional.
     * - If the 'iss' value is a string:
     *   - Optionally, it checks if the string is a valid URI using `filter_var` with the `FILTER_VALIDATE_URL` filter.
     *   - If the string is not a valid URI, it ensures that the string is non-empty.
     * 
     * If the value is either a valid URI or a non-empty string, the function returns true.
     * If the value is not a valid string or URI, or if it does not meet the criteria, the function returns false.
     */
    private function validateIssField($iss) {
        // If is empty, is valid because "iss" is optional
        if (empty($iss)) {
            return true;
        }

        // Check if the value is a text string
        if (is_string($iss)) {
            // Optional: Check if this is a valid URI
            // Use filter_var to validate that $iss is a valid URI
            if (filter_var($iss, FILTER_VALIDATE_URL) !== false) {
                return true;
            }

            // If it is not a valid URI, make sure it is a non-empty string
            return !empty($iss);
        }

        // If not a valid string or URI, return false
        return false;
    }
    
    /**
     * Validates if a given expiration field value is in an acceptable format.
     *
     * @param string $value The expiration field value to be validated.
     * 
     * @return bool Returns true if the value matches the allowed formats; otherwise, false.
     *
     * This function performs the following checks:
     * - It uses a regular expression to validate if the value matches one of the acceptable formats:
     *   - `inf` for infinite expiration.
     *   - Numeric values followed by `min` (minutes), `h` (hours), `w` (weeks), or `y` (years) to specify expiration duration.
     * 
     * If the value matches the pattern, the function returns true, indicating a valid expiration format.
     * Otherwise, it returns false, indicating an invalid expiration format.
     */
    private function validateExpField($value) {
        // Regular expression to validate allowed formats
        $pattern = '/^(inf|[0-9]+(min|h|w|y))$/';

        // Check if the value matches the pattern
        if (preg_match($pattern, $value)) {
            return true; // Valor válido
        } else {
            return false; // Valor no válido
        }
    }
    
    /**
     * Validates if a given string is a valid DateTime in the format YYYY-MM-DDTHH:MM.
     *
     * @param string $value The DateTime string to be validated.
     * 
     * @return bool Returns true if the string matches the DateTime format and represents a valid DateTime; otherwise, false.
     *
     * This function performs the following checks:
     * - It uses a regular expression to verify that the string follows the format `YYYY-MM-DDTHH:MM`.
     * - It then attempts to create a `DateTime` object from the string using the format `Y-m-d\TH:i`.
     * - Finally, it ensures that the `DateTime` object is valid and that the formatted output matches the input string.
     * 
     * If both checks are successful, the function returns true; otherwise, it returns false.
     */
    function validateDateTime($value) {
        // Regular expression to validate the format YYYY-MM-DDTHH:MM
        $pattern = '/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/';

        // Check if the value matches the pattern
        if (!preg_match($pattern, $value)) {
            return false; // Does not match the format
        }

        // Try to create a DateTime object with the value
        $dateTime = DateTime::createFromFormat('Y-m-d\TH:i', $value);

        // Check if the date and time are valid
        if ($dateTime && $dateTime->format('Y-m-d\TH:i') === $value) {
            return true;
        } else {
            return false;
        }
    }
    
    /**
     * Validates the JWT payload fields and returns any errors found.
     *
     * @param array $payload The JWT payload to be validated.
     * 
     * @return array|bool An array of errors if validation fails, or true if all fields are valid.
     *
     * This function checks the validity of specific fields in the JWT payload:
     * - For `iss`, `sub`, and `aud`, it verifies if the `iss` field is valid using the `validateIssField` method.
     * - For `exp`, it checks if the `exp` field is valid using the `validateExpField` method.
     * - For `nbf`, it ensures that the `nbf` field is a valid datetime using the `validateDateTime` method.
     * 
     * If any field fails validation, an array of errors is returned with corresponding messages.
     * If all fields are valid, the function returns true.
     */
    public function valdiatePayloadJWT($payload) {

        $errors = [];

        foreach ($payload AS $key => $value) {

            switch ($key) {
                
                case 'iss':
                case 'sub':    
                case 'aud':
                    if (!$this->validateIssField($value)) {
                        $errors['iss'] = $this->getTranslation('invalid_iss');
                    }
                    break;
                    
                case 'exp':

                    if (!$this->validateExpField($value)) {
                        $errors['exp'] = $this->getTranslation('invalid_exp');
                    }

                    break;

                case 'nbf':

                    if (!$this->validateDateTime($value)) {
                        $errors['nbf'] = $this->getTranslation('invalid_nbf');
                    }

                    break;

                default:
                    break;
            }
        }

        if (!empty($errors)) {
            return $errors;
        }

        return true;
    }
    
    /**
     * Sanitizes and saves the global JWT payload.
     *
     * @param array $payload The JWT payload to be sanitized and saved.
     * 
     * @return mixed The result of saving the global JWT payload.
     *
     * This function performs the following operations on the provided JWT payload:
     * - Sanitizes each key in the `key` array by applying the `sanitizeKeyName` method.
     * - Arranges the sanitized keys in the `key` array based on the payload type using the `arrangePayloadKeys` method.
     * - Removes the `type` key from the payload.
     * - Saves the modified payload using the `registerJWTGlobalPayload` method and returns the result.
     */
    public function saveGlobalPayloadJWT($payload) {

        $sanitized_keys = [];

        foreach ($payload['key'] AS $item_payload) {
            $sanitized_keys[] = $this->sanitizeKeyName($item_payload);
        }

        $payload['key'] = $sanitized_keys;

        
        $payload['key'] = $this->arrangePayloadKeys($payload['key'], $payload['type']);

        unset($payload['type']);

        return $this->registerJWTGlobalPayload($payload);
    }
    
    /**
     * Parses and updates the JWT payload based on provided user information.
     *
     * @param array $payload The JWT payload to be parsed and updated.
     * @param int $user_id The ID of the user associated with the JWT.
     * 
     * @return array The updated JWT payload.
     *
     * This function processes the JWT payload by:
     * - Parsing and converting expiration (`exp`) and "not before" (`nbf`) times if they are present.
     * - Fetching user details if the payload contains a valid public key or a JWT ID (`jti`).
     * - Generating a new JWT ID (`jti`) if it is present in the payload.
     * - Updating the payload with the user's ID, username, role, and email if these fields are present in the payload.
     * 
     * The function returns the updated payload with all modifications applied.
     */
    private function parseJWTPayload($payload, $user_id) {

        if (isset($payload['exp']) && !empty($payload['exp'])) {
            $payload['exp'] = $this->parseExpirationTime($payload['exp']);
        }

        if (isset($payload['nbf']) && !empty($payload['nbf'])) {
            $payload['nbf'] = $this->parseNotBefore($payload['nbf']);
        }

        if ($this->userPublicKeysActived($payload['key']) || isset($payload['jti'])) {

            $user = $this->getUserByID($user_id);
        }

        if (isset($payload['jti']) && isset($payload['jti']) === true) {

            $jti = $this->generateJTI();
            $payload['jti'] = $jti;
        }

        if (isset($payload['key']['user_id'])) {

            $payload['key']['user_id'] = $user['id'];
        }

        if (isset($payload['key']['username'])) {

            $payload['key']['username'] = $user['username'];
        }

        if (isset($payload['key']['role'])) {

            $payload['key']['role'] = $user['role_id'];
        }

        if (isset($payload['key']['email'])) {

            $payload['key']['email'] = $user['email'];
        }


        return $payload;
    }
    
    private function generateJTI() {
        return bin2hex(random_bytes(16)); // Generates a random unique identifier of 32 hexadecimal characters
    }

    // Set the refresh token to revoked
    private function revokeRefreshToken($jti) {

        $stmt = $this->pdo->prepare("UPDATE refresh_tokens SET expires_at = NOW(), revoked = 1 WHERE jti = :jti");
        $stmt->execute(['jti' => $jti]);
    }

    private function revokeToken($jti) {
        $stmt = $this->pdo->prepare("UPDATE jwt_tokens SET revoked_at = NOW() WHERE jti = :jti");
        $stmt->execute([':jti' => $jti]);
    }

    private function generateRefreshToken($user_id) {
        return bin2hex(random_bytes(32));
    }

    private function getRefreshTokenData($refresh_token) {
        
    }

    // Method to validate the refresh token
    private function validateRefreshToken($refreshToken) {

        $stmt = $this->pdo->prepare("SELECT * FROM refresh_tokens WHERE token = :token AND revoked = 0 AND expires_at > NOW()");
        $stmt->execute(['token' => $refreshToken]);
        $refreshTokenData = $stmt->fetch();

        return $refreshTokenData ? $refreshTokenData : false;
    }

    private function updateRefreshToken($token, $jti, $expires_at) {

        $sql = "UPDATE refresh_tokens SET jti = :jti, expires_at = :expired_at WHERE token = :refresh_token";
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([
            ':refresh_token' => $token,
            ':jti' => $jti,
            ':expired_at' => $expires_at
        ]);
    }

    // Method to refresh the JWT using the refresh token
    private function refreshJWT($refreshToken) {

        $refresh_token = $this->validateRefreshToken($refreshToken);

        if ($refresh_token) {

            $user_id = $refresh_token['user_id'];

            $this->revokeToken($refresh_token['jti']);

            $new_jwt = $this->generateJWT($user_id);

            $expInterval = 30 * 24 * 60 * 60; // 30 days in seconds

            $expirationDate = $this->getExpirationDate($expInterval);

            $this->updateRefreshToken($refreshToken, $new_jwt['jti'], $expirationDate);

            return $new_jwt;
        }

        return false; // The refresh token is not valid
    }
    
    private function saveRefreshToken($userId, $refreshToken, $jti, $expiresIn) {

        try {
            // Prepare the query to insert the token and its expiration date
            $stmt = $this->pdo->prepare("
                INSERT INTO refresh_tokens (user_id, token, jti, created_at, expires_at)
                VALUES (:user_id, :token, :jti, NOW(), :expires_at)
                ON DUPLICATE KEY UPDATE 
                    token = VALUES(token), 
                    expires_at = VALUES(expires_at)");

            $stmt->execute([
                ':user_id' => $userId,
                ':token' => $refreshToken,
                ':jti' => $jti,
                ':expires_at' => $expiresIn
            ]);

            return true;
        } catch (PDOException $e) {
            return false;
        }
    }
    
    public function getJWE() {
        
        $user = $this->getUser(false);
        $user_id = $user['id'];
        // Decode global payload configuration
        $payload = json_decode($this->getConfigByKey('global_payload'), true);
        
        // Parse payload for the specific user
        $parsed_payload = $this->parseJWTPayload($payload, $user_id);
        
        // Ejemplo de uso:
        $encryptionKey = $this->jwt_encrypt_key;
        $jweGenerator = new JWE($encryptionKey);
        
        // Generar un JWE
        $jwe = $jweGenerator->generateJWE($parsed_payload);
        //echo "JWE: " . $jwe . PHP_EOL;

        // Descifrar el JWE
        //$decryptedPayload = $jweGenerator->decryptJWE($jwe);
        
        return $jwe;
    }
    
    // ================================
    // SECTION: Password hash algorithms
    // ================================

    function hashPasswordBcrypt(string $password): string {
        // Generate a bcrypt hash for the password
        $hashed = password_hash($password, PASSWORD_BCRYPT);
        return 'bcrypt:' . $hashed; // Add the prefix 'bcrypt:'
    }

    function hashPasswordArgon2(string $password): string {

        $options = [
            'memory_cost' => PASSWORD_ARGON2_DEFAULT_MEMORY_COST,
            'time_cost' => PASSWORD_ARGON2_DEFAULT_TIME_COST,
            'threads' => PASSWORD_ARGON2_DEFAULT_THREADS,
        ];
        // Generates an Argon2 hash for the password
        $hashed = password_hash($password, PASSWORD_ARGON2ID, $options);

        return 'argon2:' . $hashed; // Add prefix 'argon2:'
    }

    private function configGlobalDateTime() {

        $this->timezone = $this->config['timezone'];
        date_default_timezone_set($this->timezone);
    }

    public function isHttpsEnabled() {
        return isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on';
    }

    private function readFilterFiles($return_paths = null) {
        // Make sure the directory exists
        if (!is_dir($this->filtersDirectory)) {
            return [];
        }

        // Get all .txt files from the directory
        $files = glob($this->filtersDirectory . '/*.txt');

        if ($return_paths) {
            $files = array_map('basename', $files);
            return $files;
        }
        // Returns the list of files found
        return $files;
    }

    public function getActivatedFilters() {

        $stmt = $this->pdo->prepare("SELECT * FROM filters");
        $stmt->execute();

        $current_filters = (array) $stmt->fetchAll();

        $available_filters = $this->readFilterFiles(true);

        $final_filters = [];

        foreach ($available_filters as $filter_file) {

            // Check if filter_file is in $filters
            $found = array_filter($current_filters, function($filter) use ($filter_file) {
                return $filter['filter_file'] === $filter_file;
            });

            // If found, the first result is obtained
            $found_filter = reset($found);

            // Create the new array with the existing $filters keys and the new "enabled" key
            $new_filter = $found_filter ? $found_filter : ['filter_file' => $filter_file];

            // Add the "enabled" key
            $new_filter['enabled'] = $found_filter ? 'on' : 'off';

            // Add to final array
            $final_filters[] = $new_filter;
        }

        return $final_filters;
    }

    public function validateUploadFile($_FILE) {

        $fileName = $_FILES['file']['name'];
        $fileSize = $_FILES['file']['size'];
        $fileType = $_FILES['file']['type'];
        $fileExtension = pathinfo($fileName, PATHINFO_EXTENSION);
        $fileTmpPath = $_FILES['file']['tmp_name'];
        // Verify that the file is a .txt file
        if ($fileExtension !== 'txt') {
            return ['error' => $this->getTranslation('no_txt_file')];
        }
        // Read the contents of the file to validate
        $fileContent = file_get_contents($fileTmpPath);
        // Validate that the file contains only text
        if (!is_string($fileContent) || empty(trim($fileContent))) {
            return ['error' => $this->getTranslation('empty_or_wrong_file')];
        }
        // Optional: Check the file size (e.g. maximum 2 MB)
        if ($fileSize > 2 * 1024 * 1024) { // 2 MB
            return ['error' => $this->getTranslation('file_too_big')];
        }
        return true;
    }

    private function uploadFilterFile($_FILE) {

        $fileName = $_FILES['file']['name'];
        $fileTmpPath = $_FILES['file']['tmp_name'];

        // Guardar el archivo en el servidor (opcional)
        $destination = $this->filtersDirectory . '/' . basename($fileName);

        if (move_uploaded_file($fileTmpPath, $destination)) {
            return ['success' => $this->getTranslation('successful_upload')];
        } else {
            return ['error' => $this->getTranslation('wrong_upload')];
        }
    }

    public function uploadFilter($_FILE) {

        return $this->uploadFilterFile($_FILE);
    }

    public function validate2faCode($code) {
        return preg_match('/^\d{6}$/', $code);
    }

    public function validateActivationCode($code) {
        return preg_match('/^\d{6}$/', $code);
    }

    private function sanitizeKeyName($keyName) {
        // Usa una expresión regular para permitir solo letras, números y guiones bajos
        $sanitizedKeyName = preg_replace('/[^a-zA-Z0-9_]/', '', $keyName);

        return $sanitizedKeyName;
    }

    public function parseExpirationTime($input) {

        $now = new DateTime("now", new DateTimeZone($this->timezone));
        $interval = null;

        // Detectar el tipo de entrada
        if (preg_match('/^(\d+)(min|h|w|y)$/', $input, $matches)) {
            $number = intval($matches[1]);
            $unit = $matches[2];

            switch ($unit) {
                case 'min':
                    $interval = new DateInterval("PT{$number}M");
                    break;
                case 'h':
                    $interval = new DateInterval("PT{$number}H");
                    break;
                case 'w':
                    $interval = new DateInterval("P{$number}W");
                    break;
                case 'y':
                    $interval = new DateInterval("P{$number}Y");
                    break;
            }

            $now->add($interval);
            return $now->getTimestamp(); // Devuelve el timestamp UTC
        } elseif ($input === 'inf') {
            return null; // Infinito, no establece un tiempo de expiración
        } else {
            throw new InvalidArgumentException("Formato de expiración no válido.");
        }
    }

    public function parseNotBefore($nbf) {
        // Comprobar si el valor es una fecha en el formato ISO 8601
        if (DateTime::createFromFormat('Y-m-d\TH:i', $nbf) !== false) {
            try {
                // Crear un objeto DateTime a partir del valor recibido
                $date = new DateTime($nbf, new DateTimeZone('UTC'));
                // Retornar el timestamp en UTC
                return $date->getTimestamp();
            } catch (Exception $e) {
                // Manejar excepciones, si hay problemas al crear el objeto DateTime
                return false;
            }
        } else {
            // Formato de fecha no válido
            return false;
        }
    }
    
    // ================================
    // SECTION: USER Functions
    // ================================
    
    public function getUser($complete_data = false) {

        if ($this->isLoggedIn()) {
            // Get the user_id from the user_sessions table using user_session_id
            $stmt = $this->pdo->prepare("SELECT user_id FROM user_sessions WHERE user_session_id = :user_session_id");
            $stmt->execute(['user_session_id' => $_SESSION[$this->session_name]]);
            $result = $stmt->fetch();

            if ($result) {
                $user_id = $result['user_id'];
                $stmt = $this->pdo->prepare("SELECT id, username FROM users WHERE id = :id");
                if ($complete_data === true) {
                    $stmt = $this->pdo->prepare("SELECT id, username, role_id, email FROM users WHERE id = :id");
                }
                $stmt->execute(['id' => $user_id]);
                return $stmt->fetch();
            }
        }
        return null;
    }

    public function getUserByName($username) {

        $stmt = $this->pdo->prepare('SELECT * FROM users WHERE username = :username');
        $stmt->execute(['username' => $username]);
        $userData = $stmt->fetch();

        return $userData;
    }

    public function getUserByID($user_id) {

        $stmt = $this->pdo->prepare('SELECT * FROM users WHERE id = :user_id');
        $stmt->execute(['user_id' => $user_id]);
        $userData = $stmt->fetch();

        return $userData;
    }

    public function getUserToken($user_id) {

        $stmt = $this->pdo->prepare('SELECT token FROM tokens WHERE user_id = :user_id');
        $stmt->execute(['user_id' => $user_id]);
        $tokenData = $stmt->fetch();

        return $tokenData;
    }
    
    private function getUserRole($username) {

        $stmt = $this->pdo->prepare("SELECT roles.name FROM users INNER JOIN roles ON roles.id = users.role_id WHERE users.username = :username");
        $stmt->execute([
            ':username' => $username
        ]);
        return $stmt->fetchColumn();
    }

    public function getRoleID() {

        // Verificar si hay usuarios registrados
        $query = $this->pdo->prepare("SELECT COUNT(*) FROM users");
        $query->execute();
        $userCount = $query->fetchColumn();

        // Determinar el rol
        if ($userCount == 0) {
            // Primer usuario, asignar rol de admin
            $roleIdQuery = $this->pdo->prepare("SELECT id FROM roles WHERE name = 'admin'");
        } else {
            // Siguientes usuarios, asignar rol de user
            $roleIdQuery = $this->pdo->prepare("SELECT id FROM roles WHERE name = 'user'");
        }
        $roleIdQuery->execute();
        $roleID = $roleIdQuery->fetchColumn();

        return $roleID;
    }

    public function isUserAdmin($username) {

        $userRole = $this->getUserRole($username);

        if ($userRole === 'admin') {
            return true;
        }

        return false;
    }
    
    public function getUserConnectionData() {

        $user_agent = filter_input(INPUT_SERVER, 'HTTP_USER_AGENT', FILTER_SANITIZE_FULL_SPECIAL_CHARS);
        $ip = filter_input(INPUT_SERVER, 'HTTP_X_FORWARDED_FOR') ?? filter_input(INPUT_SERVER, 'REMOTE_ADDR', FILTER_VALIDATE_IP);

        return [
            "user_agent" => $user_agent,
            "ip" => $ip
        ];
    }

    public function findUserByIdentifier($identifier) {
        $stmt = $this->pdo->prepare("SELECT * FROM users WHERE username = :identifier OR email = :identifier");
        $stmt->execute(['identifier' => $identifier]);
        return $stmt->fetch();
    }
    
    private function getUserIdFromSession($session_id) {
        $stmt = $this->pdo->prepare("SELECT user_id FROM user_sessions WHERE session_id = :session_id");
        $stmt->execute(['session_id' => $session_id]);
        $result = $stmt->fetch();

        return $result ? $result['user_id'] : null;
    }
    
    public function isUserAccountActive($user) {

        // Consulta para verificar las credenciales
        $stmt = $this->pdo->prepare("SELECT id, password FROM users WHERE (username = :identifier OR email = :identifier) AND status = 'active'");
        $stmt->execute(['identifier' => $user]);
        $user = $stmt->fetch();

        if (!$user) {
            return false;
        }

        return true;
    }
    
    private function updateUserPassword($user_id, $password_hash) {

        $stmt = $this->pdo->prepare('UPDATE users SET password = :password WHERE id = :id');
        $stmt->execute([
            ':password' => $password_hash,
            ':id' => $user_id,
        ]);
    }

    private function getUser2fa($user_id) {

        $stmt = $this->pdo->prepare("SELECT username, 2fa_conf FROM users WHERE id = :user_id");
        $stmt->execute(['user_id' => $user_id]);
        $twoFactorConfigured = $stmt->fetch();
        return $twoFactorConfigured;
    }

    private function updateUser2fa($username, $conf) {

        $sql = "UPDATE users SET 2fa_conf = :2fa_conf WHERE username = :username";

        // Preparar la declaración
        $stmt = $this->pdo->prepare($sql);

        // Ejecutar la declaración con los valores de los parámetros
        $stmt->execute([
            '2fa_conf' => $conf,
            'username' => $username
        ]);
    }

    public function sendMail($to, $type, $data) {

        switch ($type) {

            case 'pass_reset':
                $token = $data;
                $pass_reset_link = $this->buildLink("pass_reset_link", $token);
                $email_body = sprintf("%s: %s", $this->getTranslation('email_validate_account'), $pass_reset_link);
                $subject = $this->getTranslation('Password change request');

                try {
                    mail($to, $subject, $email_body);
                    return true;
                } catch (Exception $error) {
                    return false;
                }

                break;

            default:
                break;
        }
    }

    public function login($ip, $user_agent, $identifier, $password) {

        $user = $this->searchUser($identifier);

        // Avoid side-channel attacks assigning user data yes or yes
        if (!$user) {
            $user = [
                'id' => null,
                'password' => 'bcrypt:' . password_hash(random_bytes(32), PASSWORD_DEFAULT),
            ];
        }

        // Extract the prefix to determine the algorithm used
        $storedPassword = $user['password'];
        $algorithmPrefix = substr($storedPassword, 0, 7);

        $isPasswordValid = false;

        // Verify password according to algorithm
        if ($algorithmPrefix === 'bcrypt:') {
            $isPasswordValid = password_verify($password, substr($storedPassword, 7));
            // If the verification is correct and we are now using Argon2, rehash and update
            if ($isPasswordValid && $this->hash_algo === 'argon2') {
                $newHashedPassword = $this->hashPasswordArgon2($password);
                $this->updateUserPassword($user['id'], $newHashedPassword);
            }
        } elseif ($algorithmPrefix === 'argon2:') {
            $isPasswordValid = password_verify($password, substr($storedPassword, 7));
            // If the verification is correct and we are now using Bcrypt, rehash and update
            if ($isPasswordValid && $this->hash_algo === 'bcrypt') {
                $newHashedPassword = $this->hashPasswordBcrypt($password);
                $this->updateUserPassword($user['id'], $newHashedPassword);
            }
        }

        if ($isPasswordValid) {

            if ($user['id'] !== null) {

                $this->registerSession($user['id'], $ip, $user_agent);

                if ($this->JWTisAvailable()) {

                    $jwt_config = $this->configJWT();

                    if (isset($jwt_config['global_payload']) && $jwt_config['global_payload'] === true) {

                        $jwt = $this->generateJWT($user['id']);

                        $refresh_jwt = $this->generateRefreshToken($user['id']);
                        // Define el intervalo en segundos (30 días)
                        $expInterval = 30 * 24 * 60 * 60; // 30 días en segundos

                        $expirationDate = $this->getExpirationDate($expInterval);
                        $expirationTime = $this->getExpirationDateTime($expirationDate);

                        $this->saveRefreshToken($user['id'], $refresh_jwt, $jwt['jti'], $expirationDate);

                        $this->setNewCookies($jwt['token'], $refresh_jwt);
                    }
                }

                return true;
            }
        }

        $this->recordLoginAttempt($ip, $user_agent);

        if ($this->isBlocked($ip)) {
            $this->blockIp($ip);
        }

        return false;
    }

    public function isLoggedIn() {
        if (isset($_SESSION[$this->session_name])) {
            $session_id = session_id();
            $user_id = $this->getUserIdFromSession($session_id);

            if ($user_id) {
                $this->updateLastActivity($user_id);
            }

            return true;
        }

        return false;
    }

    public function logout() {

        if (isset($_SESSION[$this->session_name])) {

            $user_session_id = $_SESSION[$this->session_name];

            $this->closeUserSession($user_session_id);

            $jti = $_SESSION['jti'] ?? null;

            if ($jti) {
                // Update the database to mark the token as revoked
                $this->revokeToken($jti);
                $this->revokeRefreshToken($jti);
                // Clear the session jti
                unset($_SESSION['jti']);
            }

            // Delete cookies if present
            if (isset($_COOKIE['access_token'])) {
                setcookie('access_token', '', time() - 3600, '/', '', true, true);
            }
            if (isset($_COOKIE['refresh_token'])) {
                setcookie('refresh_token', '', time() - 3600, '/', '', true, true);
            }

            // Destroy the session on the server side
            // Destroy the session cookie on the client side
            if (ini_get("session.use_cookies")) {
                $params = session_get_cookie_params();
                setcookie(session_name(), '', time() - 42000,
                        $params["path"], $params["domain"],
                        $params["secure"], $params["httponly"]
                );
            }

            $_SESSION = [];
            session_destroy();

            // Regenerate session ID
            session_regenerate_id(true);
        }
    }

    public function activateAccountByCode($activation_code) {
        // Verify the activation code
        $stmt = $this->pdo->prepare("SELECT id, username FROM users WHERE activation_code = :activation_code AND status = :status");
        $stmt->execute(['activation_code' => $activation_code, 'status' => 'inactive']);
        $user = $stmt->fetch();

        if ($user) {
            // Activate the user account
            $stmt = $this->pdo->prepare("UPDATE users SET status = :status WHERE id = :id");
            $stmt->execute(['id' => $user['id'], 'status' => 'active']);

            return $user;
        }

        return false;
    }

    public function activateAccountByToken($token) {
        // Verify the token
        $stmt = $this->pdo->prepare("SELECT user_id FROM tokens WHERE token = :token AND token_type = 'account_validate' AND status = 'valid' AND generated_at > NOW() - INTERVAL 1 DAY");
        $stmt->execute(['token' => $token]);
        $user = $stmt->fetch();

        if ($user) {
            // Activate the user account
            $stmt = $this->pdo->prepare("UPDATE users SET status = :status WHERE id = :id");
            $stmt->execute(['id' => $user['user_id'], 'status' => 'active']);

            // Mark the token as used
            $stmt = $this->pdo->prepare("UPDATE tokens SET status = 'unvalid', validated_at = NOW(), unvalidated_at = NOW() WHERE token = :token");
            $stmt->execute(['token' => $token]);

            return $user;
        }

        return false;
    }

    private function userPublicKeysActived($user_keys) {
        // Find the words that are in both arrays
        $commonWords = array_intersect($this->getUserPublicKeys(), $user_keys);
        return !empty($commonWords);
    }

    private function getUserPublicKeys() {

        $user_keys = ["user_id", "username", "role", "email"];

        return $user_keys;
    }

    private function updateLastActivity($user_id) {
        $stmt = $this->pdo->prepare("UPDATE user_sessions SET last_activity = NOW() WHERE user_id = :user_id AND session_id = :session_id");
        $stmt->execute([
            'user_id' => $user_id,
            'session_id' => session_id()
        ]);
    }

    private function searchUser($identifier) {

        $stmt = $this->pdo->prepare("SELECT id, password FROM users WHERE username = :identifier OR email = :identifier");
        $stmt->execute(['identifier' => $identifier]);
        return $stmt->fetch();
    }

    private function getAllUsersInfo() {

        $query = "
            SELECT 
                u.id AS user_id,
                u.username,
                u.email,
                r.name AS role_name,
                us.session_id,
                us.status AS session_status,
                us.last_activity
            FROM 
                users u
            INNER JOIN 
                roles r ON u.role_id = r.id
            LEFT JOIN 
                user_sessions us 
                ON u.id = us.user_id 
                AND us.last_activity = (
                    SELECT MAX(last_activity) 
                    FROM user_sessions 
                    WHERE user_id = u.id
                )
            ORDER BY 
                u.id;
        ";

        $stmt = $this->pdo->prepare($query);
        $stmt->execute();
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    private function getAllUsers() {
        try {

            $users = $this->getAllUsersInfo();

            return $users;
        } catch (PDOException $e) {
            echo "Error: " . $e->getMessage();
        }
    }

    public function getUsers() {

        return $this->getAllUsers();
    }

    public function generateCSRFToken() {
        if (empty($_SESSION['csrf_token'])) {
            $_SESSION['csrf_token'] = $this->generateRandomToken();
        }
        return $_SESSION['csrf_token'];
    }

    public function verifyCSRFToken($token) {
        return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
    }

    private function generateRandomToken($length = 32) {
        $token = bin2hex(random_bytes($length / 2));
        return $token;
    }

    /**
     * Function to validate a Token
     *
     * @param string $token
     * @param int $length
     * @return bool
     */
    public function isValidToken($token, $length) {
        $expectedLength = $length;
        return preg_match('/^[a-f0-9]+$/', $token) && strlen($token) === $expectedLength;
    }

    private function codeExist($code) {
        $stmt = $this->pdo->prepare('SELECT COUNT(*) FROM users WHERE activation_code = :code');
        $stmt->execute(['code' => $code]);
        return $stmt->fetchColumn() > 0;
    }

    private function generateRandomTemporalCode() {

        do {
            $activation_code = random_int(100000, 999999);
        } while ($this->codeExist($activation_code));

        return $activation_code;
    }

    public function sanitizeInput($data) {
        return htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
    }

    private function recordLoginAttempt($ip, $user_agent) {
        $stmt = $this->pdo->prepare("INSERT INTO login_attempts (ip, user_agent, attempt_time) VALUES (:ip, :user_agent, NOW())");
        $stmt->execute([
            'ip' => $ip,
            'user_agent' => $user_agent
        ]);
    }

    private function validRegisterAttempt($ip) {

        // Check recent registration attempts
        $stmt = $this->pdo->prepare("SELECT COUNT(*) FROM register_attempts WHERE ip_address = :ip_address AND attempted_at > (NOW() - INTERVAL $this->max_attempts_interval)");
        $stmt->execute(['ip_address' => $ip]);
        $attempts = $stmt->fetchColumn();

        if ($attempts >= $this->max_attempts) {
            return false; // Too many recent registration attempts
        }

        return true;
    }

    public function publicRecordLoginAttempt($ip, $user_agent) {
        $this->recordLoginAttempt($ip, $user_agent);
        if ($this->isBlocked($ip)) {
            $this->blockIp($ip);
            $_SESSION['banned'] = true;
        }
    }

    private function insertUserSession($session_id, $user_session_id, $user_id, $ip_address, $user_agent, $status) {

        $stmt = $this->pdo->prepare('
            INSERT INTO user_sessions (session_id, user_session_id, user_id, ip_address, user_agent, status, start_activity) 
            VALUES (:session_id, :user_session_id, :user_id, :ip_address, :user_agent, :status, NOW())
        ');
        $stmt->bindParam(':session_id', $session_id);
        $stmt->bindParam(':user_session_id', $user_session_id);
        $stmt->bindParam(':user_id', $user_id);
        $stmt->bindParam(':ip_address', $ip_address);
        $stmt->bindParam(':user_agent', $user_agent);
        $stmt->bindParam(':status', $status);

        $stmt->execute();
    }

    private function closeUserSession($user_session_id) {
        $stmt = $this->pdo->prepare('
            UPDATE user_sessions 
            SET last_activity = NOW(), status = "inactive" 
            WHERE user_session_id = :user_session_id
        ');
        $stmt->execute(['user_session_id' => $user_session_id]);
    }

    private function blockIp($ip) {
        $stmt = $this->pdo->prepare("INSERT INTO blocked_ips (ip_address, blocked_at) VALUES (:ip, NOW())");
        $stmt->execute(['ip' => $ip]);
        $_SESSION['banned'] = true;
    }

    private function isBlocked($ip) {
        $stmt = $this->pdo->prepare("SELECT COUNT(*) AS attempt_count FROM login_attempts WHERE ip = :ip AND attempt_time > (NOW() - INTERVAL :block_duration SECOND)");
        $stmt->execute(['ip' => $ip, 'block_duration' => $this->block_duration]);
        $result = $stmt->fetch();

        return $result['attempt_count'] >= $this->max_attempts;
    }

    public function isIpBlocked($ip) {
        $stmt = $this->pdo->prepare("SELECT COUNT(*) FROM blocked_ips WHERE ip_address = :ip");
        $stmt->execute(['ip' => $ip]);
        return $stmt->fetchColumn() > 0;
    }

    private function clearLoginAttempts($ip) {
        $stmt = $this->pdo->prepare("DELETE FROM login_attempts WHERE ip = :ip");
        $stmt->execute(['ip' => $ip]);
    }

    public function getTOTPSecret($username) {
        $stmt = $this->pdo->prepare("SELECT secret_key FROM users WHERE username = :username");
        $stmt->execute(['username' => $username]);
        $result = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($result && isset($result['secret_key'])) {
            return $result['secret_key'];
        } else {
            return false;
        }
    }

    public function get2FactorQR($username) {

        return '<img id="qr_img" src="' . $this->qrDirectory . $username . '.png" alt="' . $this->getTranslation('qr_code') . '">';
    }

    public function get2Factor() {
        return $this->twoFactor;
    }

    /**
     * Generates a QR code for the TOTP secret associated with a user.
     *
     * @param string $username The username of the user for whom the QR code is generated.
     * @param bool $regenerate Optional. Whether to regenerate the TOTP secret for the user. Defaults to false.
     * @param bool $return_path Optional. Whether to return the path to the generated QR code image. Defaults to true.
     * 
     * @return string|void Returns the path to the generated QR code image if `$return_path` is true; otherwise, no return value.
     *
     * This function generates a QR code that contains the TOTP secret for the user identified by `$username`.
     * If `$regenerate` is set to true, the function will first regenerate the TOTP secret and update it for the user.
     * The function optionally returns the file path to the generated QR code image if `$return_path` is true.
     */
    public function generateQR($username, $regenerate = false, $return_path = true) {

        if ($regenerate) {
            $this->genAndUpdateUserTotp($username);
        }

        try {
            $secret = $this->getTOTPSecret($username);
            // URL for the QR code, using otpauth
            $qrData = "otpauth://totp/LoginSkel:{$username}?secret={$secret}&issuer=LoginSkel";
            $qrFilename = "{$username}.png";
            $qrPath = $this->qrDirectory . $qrFilename;

            // Generate the QR code and save it on the server
            QRcode::png($qrData, $qrPath, QR_ECLEVEL_H, 4); // Generate QR Code
        } catch (Exception $exc) {
            return False;
        }

        if ($return_path) {
            return $qrFilename; // Returns the path where the QR code was saved
        }

        return true;
    }
    
    /**
     * Serves a QR code image to the browser.
     *
     * @param string $imagePath The path to the QR code image file.
     * 
     * This function checks if the specified image file exists and is of an appropriate type (JPEG, PNG, GIF).
     * If the file exists and is valid, it sends the correct headers to the browser and streams the image content.
     * If the file cannot be found, is of an unsupported type, or cannot be opened, it sends an appropriate HTTP error
     * response to the browser.
     */
    public function serveQR($imagePath) {
        // Check if the file exists
        if (file_exists($imagePath)) {
            // Get the content type (MIME type)
            $mimeType = mime_content_type($imagePath);
            // Make sure the MIME type is appropriate for the image
            if (in_array($mimeType, ['image/jpeg', 'image/png', 'image/gif'])) {
                ob_end_clean();
                header('Content-Type: ' . $mimeType);
                header('Content-Length: ' . filesize($imagePath));
                // Read and send the contents of the file
                $file = fopen($imagePath, 'rb');
                if ($file) {
                    while (!feof($file)) {
                        echo fread($file, 8192);
                        flush(); // Ensure that content is sent immediately
                    }
                    fclose($file);
                } else {
                    // Handle the case where the file cannot be opened
                    header("HTTP/1.0 500 Internal Server Error");
                    echo "Cannot open file.";
                }
            } else {
                // Handle unsupported MIME type
                header("HTTP/1.0 415 Unsupported Media Type");
                echo "Image type not supported.";
            }
        } else {
            // Handle the case where the file is not found
            header("HTTP/1.0 404 Not Found");
            echo "Image not found.";
        }
    }

    public function has2faValidated() {
        return isset($_SESSION['2fa_passed']) && $_SESSION['2fa_passed'] === true;
    }

    public function mark2faValidated() {
        $_SESSION['2fa_passed'] = true;
    }

    public function reset2fa() {
        unset($_SESSION['2fa_passed']);
    }

    public function getAdminPath() {

        return "admin";
    }

    public function getAppPath() {

        return $this->app_path;
    }

    public function getAppURL() {

        return $this->app_url;
    }
    
    /**
     * Constructs a URL link based on the type and data provided.
     *
     * @param string $link_type The type of link to build (e.g., "actv_link" or "pass_reset_link").
     * @param string $data The data to be included in the link, typically a token or code.
     * 
     * @return string The constructed URL link.
     *
     * This function generates a URL link based on the `$link_type` provided. Depending on the type of link,
     * it formats the URL using the base application URL (`$this->app_url`) and path (`$this->app_path`), 
     * appending the relevant query parameters. The function supports different link types such as activation
     * and password reset links. If an unknown link type is provided, it returns an empty string.
     */
    private function buildLink($link_type, $data) {

        $link = "";

        switch ($link_type) {

            case "actv_link":

                $link = sprintf("%s/validate?t=%s", $this->app_url . $this->app_path, urlencode($data));

                break;

            case "pass_reset_link":

                $link = sprintf("%s/reset_pass?t=%s", $this->app_url . $this->app_path, urlencode($data));

                break;

            default:

                break;
        }

        return $link;
    }
    
    /**
     * Checks if a verification code has expired based on its timestamp.
     *
     * @param string $code_at The timestamp when the code was generated.
     * 
     * @return bool|string Returns true if the code has expired, otherwise returns the timestamp of the code.
     *
     * This function compares the current time with the timestamp of when the `$code_at` was generated to determine
     * if the code has been valid for more than 1 hour. If the code has expired, the function returns true. If the
     * code is still valid, the function returns the original timestamp `$code_at`.
     */
    public function isExpiredCode($code_at) {
        // Check for code expiration
        $codeAt = new DateTime($code_at, new DateTimeZone($this->timezone));
        $currentTime = new DateTime('now', new DateTimeZone($this->timezone));
        $interval = $currentTime->diff($codeAt);

        if ($interval->invert == 0 && $interval->days == 0 && $interval->h >= 1) {
            return true; // Token has expired
        }

        return $code_at;
    }
    
    /**
     * Checks if a token has expired based on its generation timestamp.
     *
     * @param string $token The token to check for expiration.
     * 
     * @return bool|string Returns true if the token has expired, otherwise returns the token's generation timestamp.
     *
     * This function retrieves the generation timestamp of the specified `$token` from the database. It then
     * compares the current time with the token's generation time to determine if the token has been valid for
     * more than 1 hour. If the token has expired, the function returns true. If the token is not found, it
     * also returns true, indicating the token is considered expired. If the token is still valid, the function
     * returns the generation timestamp.
     */
    public function isExpiredToken($token) {

        // We prepare the query to obtain the token generation timestamp
        $stmt = $this->pdo->prepare('SELECT generated_at FROM tokens WHERE token = :token');
        $stmt->execute(['token' => $token]);
        $tokenData = $stmt->fetch();

        if ($tokenData) {

            $generatedAt = new DateTime($tokenData['generated_at'], new DateTimeZone($this->timezone));

            $currentTime = new DateTime('now', new DateTimeZone($this->timezone));
            $interval = $currentTime->diff($generatedAt);
            // We check if more than 1 hour (60 minutes) has passed
            if ($interval->invert == 0 && $interval->days == 0 && $interval->h >= 1) {
                return true; // Token has expired
            }

            return $tokenData['generated_at'];
        }

        return true; // If the token is not found, we consider it expired
    }
    
    /**
     * Invalidates an expired token by updating its status in the database.
     *
     * @param string $token The token to be invalidated.
     *
     * This function updates the status of the specified `$token` to "unvalid" in the `tokens` table, 
     * and sets the `unvalidated_at` timestamp to the current date and time. This operation marks the token
     * as no longer valid, preventing its further use. The function performs the update only if the token's
     * current status is "valid".
     */
    public function invalidateExpiredToken($token) {
        // We prepare the query to update the token status
        $stmt = $this->pdo->prepare('
            UPDATE tokens 
            SET status = "unvalid", unvalidated_at = NOW() 
            WHERE token = :token AND status = "valid"
        ');
        $stmt->execute(['token' => $token]);
    }
    
    /**
     * Retrieves the current time zone setting.
     *
     * @return string The time zone currently set in the system or application.
     *
     * This function returns the value of the `$timezone` property, which represents the time zone configuration
     * used by the system or application. This setting is typically used for date and time operations to ensure
     * consistency across different time zones.
     */
    public function getTimeZone() {
        return $this->timezone;
    }
    
    /**
     * Calculates the remaining time for account validation based on the creation timestamp.
     *
     * @param string $createdAt The timestamp when the account validation was created.
     * 
     * @return int The number of seconds remaining until the validation expires.
     *
     * This function computes the time remaining until the validation expires by comparing the current time with
     * the provided `$createdAt` timestamp. It returns the number of seconds left before the validation period ends.
     * If the validation period has already expired, the function may return a negative value or zero.
     */
    public function getRemainingTime($createdAt) {
        // Converting timestamps to DateTime objects
        $currentTime = (new DateTime('now', new DateTimeZone($this->getTimeZone())))->format('Y-m-d H:i:s');
        $createdAtDateTime = new DateTime($createdAt);
        $currentDateTime = new DateTime($currentTime);

        // Calculate the difference
        $interval = $currentDateTime->diff($createdAtDateTime);

        // Calculate time in minutes
        $minutesElapsed = ($interval->days * 24 * 60) + ($interval->h * 60) + $interval->i;

        // The time window is 60 minutes
        $timeWindow = 60;

        if ($minutesElapsed < $timeWindow) {
            // Return the remaining time in minutes
            return $timeWindow - $minutesElapsed;
        } else {
            // Token or code expired
            return false;
        }
    }
    
    /**
     * Checks if the validation token or code for a user is still valid.
     *
     * @param string $identifier The username or email of the user.
     * @param string $validation_method The method used for validation, either "token" or "code".
     * 
     * @return bool True if the validation is still valid, false if it has expired.
     *
     * This function retrieves the user record based on the provided `$identifier` (username or email). It then
     * checks the validity of the validation method specified by `$validation_method`. 
     * - If the method is "token", it retrieves the user's token and checks if it has expired using `isExpiredToken()`.
     * - If the method is "code", it checks the expiration status of the validation code using `isExpiredCode()`.
     * The function returns true if the validation is still valid and false if it has expired. If the user is not found,
     * the function will return true by default.
     */
    public function isValidationInTime($identifier, $validation_method) {

        $stmt = $this->pdo->prepare("SELECT id, code_at FROM users WHERE username = :identifier OR email = :identifier");
        $stmt->execute(['identifier' => $identifier]);
        $user = $stmt->fetch();

        if ($user) {

            if ($validation_method === "token") {

                $token = $this->getUserToken($user['id']);

                $expired_token = $this->isExpiredToken($token['token']);

                if ($expired_token === true) {
                    return false;
                }

                return $expired_token;
            }

            if ($validation_method === "code") {

                $expired_code = $this->isExpiredCode($user['code_at']);

                if ($expired_code === true) {
                    return false;
                }

                return $expired_code;
            }

            return true;
        }
    }

    /**
     * Retrieves the method used for account validation.
     *
     * @return mixed The validation method if account validation is enabled, otherwise false.
     *
     * This function checks if account validation is enabled using the `$validate_account` property. 
     * If validation is enabled, it returns the value of the `$validate_method` property, which indicates 
     * the type of validation method being used. If account validation is not enabled, the function returns false.
     */
    public function getAccountValidationType() {

        if (!$this->validate_account) {
            return false;
        }

        return $this->validate_method;
    }
    
    /**
     * Validates a user account using a provided token and verification code.
     *
     * @param string $token The token used to verify the validation request.
     * @param string $code The verification code used to validate the account.
     * 
     * @return bool True if the account is successfully validated, false otherwise.
     *
     * This function checks the provided `$token` and `$code` to verify and validate the user account. 
     * It typically involves checking the token and code against stored values, updating the account status, 
     * and possibly performing additional actions like logging or notifications. The function returns true
     * if the validation is successful, otherwise it returns false.
     */
    public function validateAccount($token, $code) {

        // Validate the code and token
        $stmt = $this->pdo->prepare('SELECT user_id FROM tokens WHERE token = :token AND status = "valid"');
        $stmt->execute(['token' => $token]);
        $tokenData = $stmt->fetch();

        if ($tokenData) {
            // Check the activation code here
            $userId = $tokenData['user_id'];
            $stmt = $this->pdo->prepare('SELECT activation_code FROM users WHERE id = :id');
            $stmt->execute(['id' => $userId]);
            $userData = $stmt->fetch();

            if ($userData && $userData['activation_code'] === $code) {
                // Activate account
                $stmt = $this->pdo->prepare('UPDATE users SET is_validated = 1 WHERE id = :id');
                $stmt->execute(['id' => $userId]);

                // Token invalidate
                $stmt = $this->pdo->prepare('UPDATE tokens SET status = "unvalid", validated_at = NOW() WHERE token = :token');
                $stmt->execute(['token' => $token]);

                return true;
            }
        }

        return false;
    }
    
    /**
     * Retrieves the validation setting based on code validation.
     *
     * @return mixed The value of the `validate_by_code` property.
     * 
     * This function returns the value of the `$validate_by_code` property, which indicates whether code-based
     * validation is enabled or configured. The returned value can be used to determine the validation method
     * employed by the application.
     */
    public function getValidationByCode() {

        return $this->validate_by_code;
    }
    
    /**
     * Resends a verification email to the specified address.
     *
     * @param string $email The email address to which the verification email will be sent.
     * 
     * @return bool True if the email was successfully sent, false otherwise.
     *
     * This function generates and sends a new verification email to the user associated with the provided
     * `$email` address. It typically involves creating a new verification token, updating the database if necessary,
     * and sending an email with the verification link or code. The function returns true if the email was sent
     * successfully, or false if there was an issue.
     */
    public function resendVerificationEmail($email) {
        // Check if the user exists and get its ID
        $stmt = $this->pdo->prepare('SELECT id, username FROM users WHERE email = :email');
        $stmt->execute(['email' => $email]);
        $user = $stmt->fetch();

        if ($user) {
            $userID = $user['id'];
            $token = $this->generateRandomToken(); // Generate a new token
            $this->storeToken($userID, $token, 'account_validate'); // Save the token to the database
            // Send the verification link by email
            $validationLink = sprintf("%svalidate.php?t=%s", $this->config['base_url'], urlencode($token));
            $subject = $this->getTranslation("email_verify_account");
            $message = sprintf("%s: %s", $this->getTranslation('email_verify_account_msg'), $validationLink);

            return mail($email, $subject, $message);
        }

        return false; // Could not find user
    }
    
    /**
     * Destroys the current session and clears all session data.
     *
     * This function performs the following actions to completely destroy the session:
     * 1. Clears all session variables by setting `$_SESSION` to an empty array.
     * 2. Deletes the session cookie if session cookies are being used, which involves
     *    - Retrieving the current cookie parameters.
     *    - Setting the cookie to expire in the past to remove it from the client's browser.
     * 3. Destroys the session using `session_destroy()`, which effectively ends the session.
     */
    public function destroySession() {
        // Clear all session variables
        $_SESSION = array();

        // Delete the session cookie if it exists
        if (ini_get("session.use_cookies")) {
            $params = session_get_cookie_params();
            setcookie(session_name(), '', time() - 42000,
                    $params["path"], $params["domain"],
                    $params["secure"], $params["httponly"]
            );
        }

        // Destroy Session
        session_destroy();
    }
    
    /**
     * Regenerates the session ID to enhance security.
     *
     * This function calls `session_regenerate_id(true)` to generate a new session ID while retaining the 
     * session data. This helps to prevent session fixation attacks by ensuring that the session ID is changed 
     * and is not predictable.
     */
    public function regenerateSession() {
        // Regenerate Session ID
        session_regenerate_id(true);
    }
    
    /**
     * Generates a password reset token for a specified user.
     *
     * @param int $user_id The ID of the user for whom the password reset token is generated.
     * 
     * @return string|false The generated reset token if successful, or false if the token could not be created.
     *
     * This function generates a unique password reset token for the user with the specified `$user_id`. 
     * The token is stored in the database with an associated timestamp and status. The function returns 
     * the generated token if the operation is successful, or false if there was an issue creating the token.
     */
    public function generatePasswordResetToken($user_id) {

        $token = $this->generateRandomToken(32);
        $stmt = $this->pdo->prepare("INSERT INTO tokens (user_id, token, generated_at, token_type, status) VALUES (:user_id, :token, NOW(), 'password_reset', 'valid')");
        $stmt->execute(['user_id' => $user_id, 'token' => $token]);

        return $token;
    }
    
    /**
     * Resets the 2FA code for a user using a provided token.
     *
     * @param string $token The token used to verify the 2FA reset request.
     * 
     * @return bool True if the 2FA code was successfully reset, false otherwise.
     *
     * This function verifies the provided token to ensure it is valid and retrieves the associated user ID.
     * If the token is valid, it would proceed with resetting the 2FA code for the user. (Additional implementation
     * details for resetting the 2FA code are not included in this snippet.)
     */
    public function reset2FACode($token) {

        $stmt = $this->pdo->prepare('SELECT user_id, generated_at FROM tokens WHERE token = :token AND status = "valid"');
        $stmt->execute(['token' => $token]);
        $tokenData = $stmt->fetch();

        if (!$tokenData) {
            return false;
        }

        try {
            // Start the transaction
            $this->pdo->beginTransaction();

            $userID = $tokenData['user_id'];

            $stmt = $this->pdo->prepare('SELECT username, email FROM users WHERE id = :userID');
            $stmt->execute(['userID' => $userID]);
            $userData = $stmt->fetch();

            if (!$userData) {
                return false;
            }

            // Mark token as used
            $this->invalidateExpiredToken($token);

            // Confirm the transaction
            $this->pdo->commit();

            $qr_data = $this->generateQR($userData['username']);

            $response = [
                'username' => $userData['username'],
                'qr_image' => $qr_data
            ];

            return $response;
        } catch (Exception $e) {
            // In case of any error, reverse the transaction
            $this->pdo->rollBack();
            throw $e;
        }
    }
    
    /**
     * Resets the user's password using a provided token.
     *
     * @param string $token The token used to verify the password reset request.
     * @param string $newPassword The new password to be set for the user.
     * 
     * @return bool True if the password was successfully reset, false otherwise.
     *
     * This function first verifies the provided token to ensure it is valid and retrieves the associated user ID. 
     * If the token is valid, it starts a database transaction to update the user's password with a hashed version 
     * of the new password, marks the token as used to prevent reuse, and commits the transaction. If any step fails, 
     * the transaction is rolled back, and an exception is thrown. The function also regenerates the session ID to 
     * prevent session fixation attacks.
     */
    public function resetPassword($token, $newPassword) {

        // Verify the token and get the associated user_id
        $stmt = $this->pdo->prepare('SELECT user_id, generated_at FROM tokens WHERE token = :token AND status = "valid"');
        $stmt->execute(['token' => $token]);
        $tokenData = $stmt->fetch();

        if (!$tokenData) {
            return false;
        }

        try {
            // Init transaction
            $this->pdo->beginTransaction();

            $userID = $tokenData['user_id'];

            // Update user password
            $hashedPassword = password_hash($newPassword, PASSWORD_BCRYPT);
            $stmt = $this->pdo->prepare('UPDATE users SET password = :password WHERE id = :id');
            $stmt->execute(['password' => $hashedPassword, 'id' => $userID]);

            // Mark token as used
            $this->invalidateExpiredToken($token);

            // Confirm the transaction
            $this->pdo->commit();

            // Regenerate session ID to prevent session fixation attacks
            session_regenerate_id(true);

            return true;
        } catch (Exception $e) {
            // In case of any error, roll back the transaction
            $this->pdo->rollBack();
            throw $e;
        }
    }
    
    /**
     * Generates RSA keys using the RSAKeyManager class.
     *
     * @return bool True if the RSA keys were generated successfully, false otherwise.
     *
     * This function creates an instance of the RSAKeyManager class with the specified keys path and keys name.
     * It then attempts to generate RSA keys by calling the `generateRSAKeys` method of the RSAKeyManager.
     * The function returns true if the key generation is successful, otherwise it returns false.
     */
    public function generateRSAKeys() {

        $keyManager = new RSAKeyManager($this->keys_path, $this->keys_name);

        if ($keyManager->generateRSAKeys()) {
            return true;
        }

        return false;
    }

    /**
     * Retrieves the global configuration settings.
     *
     * @return array The array containing all global configuration settings.
     *
     * This function returns the `$config` property, which holds an array of global configuration
     * settings for the application.
     */
    public function getGlobalConfig() {
        return $this->config;
    }
    
    /**
     * Retrieves a configuration value from the database based on the provided configuration key.
     *
     * @param string $config_key The key of the configuration setting to retrieve.
     * 
     * @return mixed The configuration value associated with the specified key, or false if the key is not found.
     *
     * This function executes a SQL query to select the configuration value from the `config` table
     * where the configuration key matches the provided `$config_key`. If a matching record is found,
     * the function returns the configuration value; otherwise, it returns false.
     */
    public function getConfigByKey($config_key) {

        $stmt = $this->pdo->prepare('SELECT conf_key, conf_value FROM config WHERE conf_key = :conf_key');
        $stmt->execute(['conf_key' => $config_key]);

        $configData = $stmt->fetch();

        if (!$configData) {
            return false;
        }

        return $configData['conf_value'];
    }

    /**
     * Calculates the expiration date based on a given interval in seconds.
     *
     * @param int $expirationInterval The expiration interval in seconds.
     * 
     * @return string The expiration date and time as a formatted string in 'Y-m-d H:i:s' format.
     *
     * This function creates a DateTime object with the current date and time, using the class's configured timezone. 
     * It then adds the specified interval in seconds to the current date and time to calculate the expiration date. 
     * The resulting expiration date is returned as a formatted string.
     */
    private function getExpirationDate($expirationInterval) {

        // Create a new DateTime instance with the correct time zone
        $dateTime = new DateTime('now', new DateTimeZone($this->timezone));

        // Añade el intervalo a la fecha actual en segundos
        $dateTime->add(new DateInterval('PT' . $expirationInterval . 'S'));

        // Format date as string
        $expiresAt = $dateTime->format('Y-m-d H:i:s');

        return $expiresAt;
    }
    
    /**
     * Converts an expiration date to a timestamp in seconds since the Unix epoch (UTC).
     *
     * @param string $expirationDate The expiration date in a format recognized by DateTime.
     * 
     * @return int The timestamp representing the expiration date in seconds since the Unix epoch (UTC).
     *
     * This function creates a DateTime object using the provided expiration date and the class's configured 
     * timezone. It then converts this DateTime to a Unix timestamp (UTC) and returns the result.
     */
    private function getExpirationDateTime($expirationDate) {

        // Create a DateTime object with the expiration date and local time zone
        $dateTime = new DateTime($expirationDate, new DateTimeZone($this->timezone));

        // Convert local date and time to time in seconds since Unix epoch (UTC)
        $timestamp = $dateTime->getTimestamp();

        return $timestamp;
    }
    
    // ================================
    // SECTION: API SIMULATION
    // ================================
    
    /**
     * Currently, its only purpose is to verify that JWTs and refresh tokens passed via cookies
     * are set correctly and handled appropriately from the server when simulating API calls using them.
     * 
     * Despite this, it is not difficult to use it depending on the main APP you are protecting.
     *
     * @param string $algo Algorithm to verify. Must be 'bcrypt' or 'argon2'.
     * @return bool Returns true if the algorithm is available, false otherwise.
     */
    public function handleRequest() {

        $access_token = (isset($_COOKIE['access_token'])) ? $_COOKIE['access_token'] : null;
        $refresh_token = (isset($_COOKIE['refresh_token'])) ? $_COOKIE['refresh_token'] : null;
        
        $headers = getallheaders();
        $jwe_token = (isset($headers['X-Jwe-Token'])) ? $headers['X-Jwe-Token'] : null;
        
        if (1!=1) {
            $access_token = (isset($headers['X-Auth-Bearer'])) ? $headers['X-Auth-Bearer'] : null;
            $refresh_token = (isset($headers['X-Refresh-Token'])) ? $headers['X-Refresh-Token'] : null;
            $jwe_token = (isset($headers['X-JWE-Token'])) ? $headers['X-JWE-Token'] : null;
        }

        if (isset($jwe_token) && $jwe_token!==null) {
            
            $jwe = new JWE($this->jwt_encrypt_key);
            $decryptedPayload = $jwe->decryptJWE($jwe_token);
            header('HTTP/1.1 200');
            return ['status' => 'success', 'deciphered' => true, 'data' => $decryptedPayload];
            
        }
        
        if ((!$access_token || !$refresh_token) ) {
            header('HTTP/1.1 401 Unauthorized');
            return ['status' => 'error', 'message' => 'Unauthorized'];
        }

        if (!$access_token || $access_token === "undefined") {

            if ($refresh_token) {

                $renew_token = $this->refreshJWT($refresh_token);

                $this->setNewCookies($renew_token['token'], $refresh_token);

                return ['status' => 'success', 'data' => $renew_token];
            }

            header('HTTP/1.1 401 Unauthorized');
            return ['status' => 'error', 'message' => 'Unauthorized: Invalid token, login again!'];
        }

        $jwtObject = $this->newJWTObject();
        $confPayload = json_decode($this->getConfigByKey('global_payload'));
        $decodedJwt = $jwtObject->verifyToken($confPayload, $access_token);

        if (isset($decodedJwt['errors']['exp'])) {

            // Invalid JWT, but there is a refresh token, try to refresh the JWT
            $new_jwt = $this->refreshJWT($refresh_token);

            if ($new_jwt) {
                $this->setNewCookies($new_jwt['token'], $refresh_token);
                unset($decodedJwt['errors']);
                return ['status' => 'success', 'new_jwt' => $new_jwt];
            }
        }

        if ($decodedJwt) {
            // Valid JWT, continue with request
            return ['status' => 'success', 'data' => $decodedJwt];
        } elseif ($refreshToken) {
            
        }

        if (isset($decodedJwt['errors'])) {
            return ['status' => 'error', 'data' => $decodedJwt['errors']];
            exit;
        }

        // Invalid JWT and no refresh token or invalid refresh token
        header('HTTP/1.1 401 Unauthorized');
        return ['status' => 'error', 'message' => 'Unauthorized'];
    }

    /**
     * Converts an object to an associative array recursively.
     *
     * @param mixed $data The data to be converted, which can be an object or an array.
     * 
     * @return mixed The converted array if the input was an object or array; otherwise, returns the input data unchanged.
     *
     * This function checks if the input data is an object and converts it into an associative array. 
     * If the input is already an array, it recursively applies the conversion to each element of the array. 
     * Non-array and non-object data is returned as-is.
     */
    function objToArray($data) {

        if (is_object($data)) {
            $data = get_object_vars($data);
        }

        if (is_array($data)) {
            return array_map(__FUNCTION__, $data);
        } else {
            return $data;
        }
    }
    
    /**
     * Retrieves the application error messages.
     *
     * @return array The array containing all the application error messages.
     * 
     * This function returns the `$app_errors` property, which holds an array of error messages 
     * generated by the application.
     */
    public function getAppErrors() {
        return $this->app_errors;
    }
    
    /**
     * Handles an exception by logging the error details and displaying an error message.
     *
     * @param LoginSkelException $e The exception to handle.
     * 
     * This function logs the exception details including the date, error code, message, file, and line number
     * to a log file named 'error_log.txt'. It also displays a general error message to the user.
     */
    public function handleException(LoginSkelException $e)
    {
        // Log the message in the log
        $logFile = '../log/error_log.txt';
        $logMessage = date('Y-m-d H:i:s') . " | Code: " . $e->getCode() . " | Message: " . $e->getMessage() . " | File: " . $e->getFile() . " | Line: " . $e->getLine() . PHP_EOL;
        file_put_contents($logFile, $logMessage, FILE_APPEND);

        // You can perform other actions here, such as displaying a general error message to the user
        echo "Error: " . $e->getMessage();
    }
}
