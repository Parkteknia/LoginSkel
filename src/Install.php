<?php

/**
 * Install.php Class
 *
 * The features included in the class have been organized by sections to facilitate understanding and navigation.
 * 
 *
 * @category   Authentication and Authorization Web Interfaces
 * @package    LoginSkel
 * @author     P3r4nd <author@example.com>
 * @copyright  2024 - Parkteknia
 * @license    http://www.php.net/license/3_01.txt  PHP License 3.01
 * @version    Release: @1.0@
 * @link       http://pear.php.net/package/PackageName
 */
class Install
{
    private $configFile = '../config/config.php';
    private $locales_folder = '../locale/';
    private $config = [];
    private $defaultLang = 'es_ES'; // Default Lang
    private $translations;
    private $pdo;

    public function __construct()
    {
        $this->config = require $this->configFile;

        if (isset($_GET['lang'])) {
            $_SESSION['lang'] = $_GET['lang'];
        }

        if (!isset($_SESSION['lang'])) {
            $_SESSION['lang'] = $this->defaultLang;
        }

        $this->loadTranslations();
    }
    
    public function checkConfig(){
        return $this->config;
    }
    
    private function areCredentialsSet()
    {
        return !empty($this->config['db_dsn']) && !empty($this->config['db_username']);
    }
    
    public function isInstalled() {
        
        if ($this->testConnection()) {
            
            if ($this->getGlobalConfig()) {
                
                return true;
            }
            
            $_SESSION['db_success'] = true;
        }
        
        return false;
    }
    
    public function testConnection($dsn = null, $username = null, $password = null)
    {
        $dsn = sprintf("mysql:host=localhost;dbname=%s", $dsn) ?: $this->config['db_dsn'];
        $username = $username ?: $this->config['db_username'];
        $password = $password ?: $this->config['db_password'];

        try {
            $pdo = new PDO($dsn, $username, $password);
            return $pdo->getAttribute(PDO::ATTR_CONNECTION_STATUS) !== false;
        } catch (PDOException $e) {
            return false;
        }
    }
    
    private function getConnection() {
        
        $dsn = (isset($_SESSION['db_dsn']))?$_SESSION['db_dsn']:$this->config['db_dsn'];
        
        $db_access = [
            'db_dsn' => sprintf("mysql:host=localhost;dbname=%s", $dsn),
            'db_username' => (isset($_SESSION['db_username'])?$_SESSION['db_username']:$this->config['db_username']),
            'db_password' => (isset($_SESSION['db_password'])?$_SESSION['db_password']:$this->config['db_password'])
        ];

        $this->pdo = new PDO($db_access['db_dsn'], $db_access['db_username'], $db_access['db_password']);
        $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
    }
    
    private function getGlobalConfig() {
        
        $this->getConnection();
        // Verificar el token y obtener el user_id asociado
        $stmt = $this->pdo->prepare('SELECT conf_key, conf_value FROM config WHERE conf_key = :conf_key');
        $stmt->execute(['conf_key' => 'global_config']);
        
        $configData = $stmt->fetch();

        if (!$configData) {
            return false;
        }
        
        return true;
    }
    
    public function prepareConfigObjects() {
        
        try {

            $confFile = [
                'db_dsn' => $_SESSION['db_dsn'],
                'db_username' => $_SESSION['db_username'],
                'db_password' => $_SESSION['db_password']
            ];

            if(!isset($_SESSION['jwt_encrypt_key'])||$_SESSION['jwt_encrypt_key']==="") {
                $encrypt_key = $this->generateRandoKey();
                $confFile['encrypt_key'] = $encrypt_key;
            }else{
                $confFile['encrypt_key'] = $_SESSION['jwt_encrypt_key'];
            }

            if(!isset($_SESSION['keys_path'])||$_SESSION['keys_path']==="") {
                $keys_path = $this->getBasePath() . '/.keys/';
                $confFile['keys_path'] = $keys_path;
            }else{
                $confFile['keys_path'] = $_SESSION['keys_path'];
            }

            if(!isset($_SESSION['qr_codes_folder'])||$_SESSION['qr_codes_folder']==="") {
                $codes_folder = $this->getBasePath() . '/.codes/';
                $confFile['codes_folder'] = $codes_folder;
            }else{
                $confFile['codes_folder'] = $_SESSION['qr_codes_folder'];
            }

            $confToDB = [
                'default_lang' => $_SESSION['lang'],
                'timezone' => $_SESSION['timezone'],
                'session_name' => 'LoginSkel',
                'cookie_domain' => $_SERVER['HTTP_HOST'],
                'app_url' => $_SESSION['app_url'],
                'app_path' => $_SESSION['app_path'],
                'max_attempts' => $_SESSION['max_attempts'],
                'max_attempts_interval' => $_SESSION['max_attempts_interval'],
                'block_duration' => $_SESSION['block_duration'], // 15 minutos
                'hash_algo' => 'bcrypt',
                'validate_account' => (isset($_SESSION['validate_account']))?true:false,
                'validate_method' => $_SESSION['validate_method'], // [code|token]
                'jwt_auth' => (isset($_SESSION['jwt_auth']))?true:false,
                'jwt_encrypt' => (isset($_SESSION['jwt_encrypt']))?true:false,
                'jwt_encrypt_key' => (isset($_SESSION['jwt_encrypt_key']))?$_SESSION['jwt_encrypt_key']:'',
                '2fa_auth' => (isset($_SESSION['2fa_auth']))?true:false,
                'ps_protect' => true,
                'delete_sessions' => false,
            ];

            $confObject = [
                'to_file' => $confFile,
                'to_db' => $confToDB
            ];

            return $confObject;
            
        } catch (Exception $exc) {
            return false;
        }

    }
    
    public function setCredentials($dsn, $username, $password)
    {
        $_SESSION['db_dsn'] = $dsn;
        $_SESSION['db_username'] = $username;
        $_SESSION['db_password'] = $password;
        
        $this->config = [];
        $this->config['db_dsn'] = $_SESSION['db_dsn'];
        $this->config['db_username'] = $_SESSION['db_username'];
        $this->config['db_password'] = $_SESSION['db_password'];
    }
    
    public function saveConfig($locate, $data) {
        
        switch ($locate) {
            case 'file':
                $this->saveConfigFile(
                    $data['db_dsn'],
                    $data['db_username'],
                    $data['db_password'],
                    $data['encrypt_key'],
                    $data['keys_path'],
                    $data['codes_folder']
                );
                
                break;
            case 'db':
                $this->saveConfigtoDB($data);
            default:
                break;
        }
    }
    private function saveConfigFile($dsn, $username, $password, $encrypt_key, $keys_path, $codes_path) {
        
        $dsn = sprintf("mysql:host=localhost;dbname=%s", $dsn);
        $configContent = "<?php\n\n";
        $configContent .= "if (!defined('SECURE_ACCESS')) {\n";
        $configContent .= "    header('HTTP/1.0 403 Forbidden', true, 403);\n";
        $configContent .= "}";
        $configContent .= "\n\nreturn [\n";
        $configContent .= "    'db_dsn' => '{$dsn}',\n";
        $configContent .= "    'db_username' => '{$username}',\n";
        $configContent .= "    'db_password' => '{$password}',\n";
        $configContent .= "    'jwt_encrypt_key' => '{$encrypt_key}',\n";
        $configContent .= "    'keys_path' => '{$keys_path}',\n";
        $configContent .= "    'keys_name' => ['private' => 'private.key','public' => 'public.key'],\n";
        $configContent .= "    'qr_codes_folder' => '{$codes_path}'\n";
        $configContent .= "];\n";

        file_put_contents($this->configFile, $configContent);
    }
    
    public function createTables($dsn, $username, $password)
    {
        $dsn = sprintf("mysql:host=localhost;dbname=%s", $dsn) ?: $this->config['db_dsn'];
        $pdo = new PDO($dsn, $this->config['db_username'], $this->config['db_password']);
        $sql = file_get_contents('../config/loginskel.sql');

        try {
            $pdo->exec($sql);
        } catch (PDOException $e) {
            echo $this->getTranslation('error_creating_tables') . ": " . $e->getMessage();
        }
    }
    
    private function saveConfigtoDB($data) {
        
        $this->getConnection();
        
        $globalConfig = json_encode($data);
        
        // Preparar la consulta
        $sql = "INSERT INTO config (`conf_key`, `conf_value`) VALUES (:conf_key, :conf_value)
                ON DUPLICATE KEY UPDATE `conf_value` = VALUES(`conf_value`)";
        
        try {
            $stmt = $this->pdo->prepare($sql);

            // Ejecutar la consulta
            $stmt->execute([
                ':conf_key' => 'global_config',
                ':conf_value' => $globalConfig
            ]);
            
            return true;
        } catch (PDOException $e) {
            echo "Error al guardar JSON: " . $e->getMessage();
            return False;
        } 
    }
    
    private function translateExists($lang) {
        
        $localeFile = $this->locales_folder . $lang . '/messages.php';
        
        if($localeFile) {
            return true;
        }
        
        return false;
    }
    
    private function loadTranslations()
    {
        $lang = $_SESSION['lang'];
        
        $localeFile = $this->locales_folder . $lang . '/messages.php';

        if (file_exists($localeFile)) {
            $this->translations = include($localeFile);
        } else {
            $this->translations = false;
        }
    }

    public function getTranslation($key)
    {
        return $this->translations[$key] ?? $key;
    }
    
    private function getLangName($lang){
        $messages = include($this->locales_folder . $lang . '/messages.php');
        return $messages[$lang];
        
    }
    
    public function getCurrentLanguage() {
        
        if(isset($_SESSION['lang'])) {
            return $_SESSION['lang'];
        }
        
        return $this->defaultLang;
    }
    
    public function setDefaultLang($lang) {
        
        if($this->translateExists($lang)) {
            $_SESSION['lang'] = $lang;
            $this->defaultLang = $_SESSION['lang'];
            $this->loadTranslations();
            return true;
        }
        
        return false;
    }
    
    private function getAvailableLangs() {
        
        $locales_path = $this->locales_folder;
        $dirs = scandir($locales_path);
        $langs = [];

        foreach ($dirs as $dir) {
            if ($dir === '.' || $dir === '..') {
                continue;
            }

            if (is_dir($locales_path . '/' . $dir)) {
                $langs[] = $dir;
            }
        }

        return $langs;
    }
    
    public function renderLangMenu($current_lang, $input_name, $event) {
        
        $event_action = '';
        
        if($event===true) {
            $event_action = 'onchange="this.form.submit()"';
        }
        
        $lang_menu = '<select id="language-select" name="' . $input_name . '" ' . $event_action .'>';
        
        $langs = $this->getAvailableLangs();
        
        foreach($langs AS $lang_key) {
            
            $lang_menu .= '<option value="' . $lang_key . '"' . (($lang_key===$current_lang) ? "selected": "") . '>' . $this->getLangName($lang_key) . '</option>';
        }
        
        $lang_menu .= '</select>';
        
        return $lang_menu;
    }
    
    public function getBaseURL() {
        $protocol = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https://' : 'http://';
        $base_url = $protocol . $_SERVER['HTTP_HOST'];
        return $base_url;
    }
    
    private function isValidURL($url) {
        return filter_var($url, FILTER_VALIDATE_URL) !== false;
    }
    
    private function getBaseDomainPath($path) {
        
        $parts = explode('/', $path);

        $lastPart = array_pop($parts);

        if (strpos($lastPart, '.') !== false) {
            $pathWithoutSubdomain = implode('/', $parts);
        } else {
            $pathWithoutSubdomain = $path;
        }

        return $pathWithoutSubdomain;
    }
    
    function getDirectoryPath() {
        // Descomponer la URL en componentes
        $parsedUrl = parse_url($this->getBaseDirURL());

        // Obtener el path de la URL
        $path = $parsedUrl['path'] ?? '';

        // Eliminar el archivo al final del path (por ejemplo, 'index.php')
        $pathWithoutFile = preg_replace('/\/[^\/]*$/', '', $path);

        return $pathWithoutFile;
    }

    public function getBaseDirURL(){
        $scheme = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http';
        $host = $_SERVER['HTTP_HOST'];
        $requestUri = $_SERVER['REQUEST_URI'];

        return $scheme . '://' . $host . $requestUri;
    }
    
    public function getBasePath() {
        $publicDir = __DIR__;
        $basePath = dirname($publicDir, 1);
        return $this->getBaseDomainPath($basePath);
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
    private function isValidTimezone($timezone) {
        $validTimezones = DateTimeZone::listIdentifiers();

        return in_array($timezone, $validTimezones);
    }

    public function validateConfig($data) {
                
        foreach($data AS $key => $value) {
            
            switch ($key) {
                
                case 'timezone':
                    
                    unset($_SESSION['errors']['timezone']);
                    
                    if (!$this->isValidTimezone($data['timezone'])) {
                        $_SESSION['errors']['timezone'] = $this->getTranslation('invalid_timezone');
                    }else{
                       $_SESSION['timezone'] = $data['timezone'];
                    }
                    
                    break;
                
                case 'app_url':
                    
                    unset($_SESSION['errors']['appurl']);
                    
                    if (!$this->isValidURL($data['app_url'])) {
                        $_SESSION['errors']['appurl'] = $this->getTranslation('invalid_url');
                    }else{
                        $_SESSION['app_url'] = rtrim($data['app_url'], "/");
                    }
                    break;
                    
                case 'app_path':
                    
                    unset($_SESSION['errors']['apppath']);
                    
                    if ($this->getDirectoryPath()!==$data['app_path']) {
                        $_SESSION['errors']['apppath'] = $this->getTranslation('invalid_app_path');
                    }else{
                        $_SESSION['app_path'] = $data['app_path'];
                    }
                    
                case 'max_attempts':
                    
                    unset($_SESSION['errors']['max_attempts']);
                    
                    if (!filter_var($data['max_attempts'], FILTER_VALIDATE_INT)) {
                        $_SESSION['errors']['max_attempts'] = $this->getTranslation('invalid_max_attempts');
                    }else{
                       $_SESSION['max_attempts'] = $data['max_attempts'];
                    }
                    break;
                    
                case 'max_attempts_interval':
                    
                    $intervals = ['second', 'minute', 'hour', 'day', 'week', 'month', 'year'];
                    $interval = explode(" ", $data['max_attempts_interval']);
                    
                    unset($_SESSION['errors']['max_attempts_interval']);
                    
                    if (!filter_var((int) $interval[0], FILTER_VALIDATE_INT) || !in_array($interval[1], $intervals)) {
                        $_SESSION['errors']['max_attempts_interval'] = $this->getTranslation('invalid_interval');
                    }else{
                       $_SESSION['max_attempts_interval'] = $data['max_attempts_interval'];
                    }
                    break;
                    
                case 'block_duration':
                    
                    unset($_SESSION['errors']['block_duration']);
                    
                    if (!filter_var($data['block_duration'], FILTER_VALIDATE_INT)) {
                        $_SESSION['errors']['block_duration'] = $this->getTranslation('invalid_interval');
                    }else{
                       $_SESSION['block_duration'] = $data['block_duration'];
                    }
                    break;
                    
                case 'toggle_validate':
                    
                    if ($data['toggle_validate']) {
                        
                        $_SESSION['validate_account'] = true;
                    }
                    break;
                    
                case 'validate_method':
                    
                    if($_SESSION['validate_account']){
                        if ($data['validate_method']==='code' || $data['validate_method']==='token') {
                            $_SESSION['validate_method'] = $data['validate_method'];
                        }else{
                            $_SESSION['errors']['validate_method'] = $this->getTranslation('invalid_validate_method');
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
                        unset($_SESSION['errors']['jwt_keys_path']);
                        $check_path = $this->checkDirectory($data['keys_path']);
                        if(true!==$check_path) {
                            $_SESSION['errors']['jwt_keys_path'] = $check_path;
                        }else{
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
                        if(true!==$check_path) {
                            $_SESSION['errors']['2fa_codes_path'] = $check_path;
                        }else{
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
                        
                        unset($_SESSION['errors']['no_encryption_key']);
                                
                        if(empty($data['encryption_key'])) {
                            $_SESSION['errors']['no_encryption_key'] = $this->getTranslation('no_encryption_key');
                        }else{
                            $_SESSION['jwt_encrypt_key'] = $data['encryption_key'];
                        }
                    }
                    
                default:
                    break;
            }
        }
        
        if(empty($_SESSION['errors'])) {
            return true;
        }
        
        return false;
    }
    
    private function generateRandoKey() {
        
        $key = random_bytes(32);
        $encodedKey = base64_encode($key);
        return $encodedKey;
    }
}