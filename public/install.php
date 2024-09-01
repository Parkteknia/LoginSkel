<?php

session_start();

require_once '../Install.php';

$loginskel = new Install();

$global_config_success = $loginskel->isInstalled();

if ($global_config_success) {
    // Redirect to the installation page if the installation is not complete
    header('Location: login');
    exit();
}

$body_class = 'admin-page';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    
    if (isset($_POST['db_config'])) {

        $dsn = $_POST['dsn'];
        $db_username = $_POST['db_username'];
        $db_password = $_POST['db_password'];
        
        unset($_SESSION['errors']['db']);
        
        if ($loginskel->testConnection($dsn, $db_username, $db_password)) {
            $loginskel->setCredentials($dsn, $db_username, $db_password);
            $loginskel->createTables($dsn, $db_username, $db_password);
            $_SESSION['db_success'] = true;
        } else {
            $_SESSION['errors']['db'] = [$loginskel->getTranslation('wrong_db')];
        }
        
    } elseif (isset($_POST['lang_config'])) {
        $loginskel->setDefaultLang($_POST['default_lang']);
        $_SESSION['lang_config_success'] = true;
        
    } elseif (isset($_POST['global_config'])) {
        $validate_config = $loginskel->validateConfig($_POST);
        if($validate_config) {
            $_SESSION['app_config_success'] = true;
        }
        
    } elseif (isset($_POST['secu_config'])) {
        
        $validate_config = $loginskel->validateConfig($_POST);
        
        if($validate_config) {
            //$install->saveConfigFile();
            $confObject = $loginskel->prepareConfigObjects();            
            if ($confObject) {
               $loginskel->saveConfig('file', $confObject['to_file']);
               $loginskel->saveConfig('db', $confObject['to_db']);
            }
            $_SESSION['secu_success'] = true;
        }  
    }
}

// Show errors and success messages
$errors = $_SESSION['errors'] ?? [];
$db_success = $_SESSION['db_success'] ?? false;
$lang_success = $_SESSION['lang_config_success'] ?? false;
$app_success = $_SESSION['app_config_success'] ?? false;
$secu_success = $_SESSION['secu_success'] ?? false;
//unset($_SESSION['errors'], $_SESSION['config_success'], $_SESSION['other_config_success']);

$lang = $loginskel->getCurrentLanguage();

include '../template/header.php';
?>

<div class="install-container">
    <div class="lang-header">
        <div class="language-menu">
            <form method="get" action="install">
                <?php echo $loginskel->renderLangMenu($lang, 'lang', true); ?>
            </form>
        </div>
    </div>
    <h1>LoginSkel</h1>
    <h2 class="sub-title"><?= $loginskel->getTranslation('installer'); ?></h2>
    <?php if (!$global_config_success && !$db_success && empty($_POST['other_config'])): ?>
        <h3 style="text-align: left;"><?= $loginskel->getTranslation('db_configuration'); ?></h3>
        <?php if (isset($errors['db'])): ?>
            <ul class="list-errors">
                <?php foreach ($errors['db'] as $error): ?>
                    <li class="error"><?php echo htmlspecialchars($error); ?></li>
                <?php endforeach; ?>
            </ul>
        <?php endif; ?>

        <form class="form-config" id="connection-form" method="post">
            <input type="hidden" name="db_config" value="1">
            <label><?= $loginskel->getTranslation('dsn'); ?>:</label>
            <input type="text" name="dsn" required><br>
            <label><?= $loginskel->getTranslation('username'); ?>:</label>
            <input type="text" name="db_username" required><br>
            <label><?= $loginskel->getTranslation('password'); ?>:</label>
            <input type="password" name="db_password" required><br>
            <button type="submit" id="submit-button-db"><?= $loginskel->getTranslation('save_credentials'); ?></button>
        </form>
    <?php elseif (!$global_config_success && !$lang_success): ?>
        <h3><?= $loginskel->getTranslation('default_lang'); ?></h3>
        <form method="post">
            <div class="lang-config">
                <div class="language-menu">
                    <?php echo $loginskel->renderLangMenu($lang, 'default_lang', false); ?>
                </div>
            </div>
            <button type="submit" ><?= $loginskel->getTranslation('save_lang'); ?></button>

            <input type="hidden" name="lang_config" value="1">
        </form>
    <?php elseif (!$global_config_success && !$app_success): ?>
        <h3><?= $loginskel->getTranslation('global_config'); ?></h3>
        <p class="paragrah-install"><?= $loginskel->getTranslation('global_config_info'); ?></p>
        <?php if ($errors): ?>
            <ul class="list-errors">
                <?php foreach ($errors as $error): ?>
                    <li class="error"><?php echo htmlspecialchars($error); ?></li>
                <?php endforeach; ?>
            </ul>
        <?php endif; ?>
        <form method="post" id="configure-form">
            <table id="default-table" class="install_table">
                <tbody>
                    <!-- Predefined global fields -->
                    <tr>
                        <td><label for="timezone"><?= $loginskel->getTranslation('time_zone'); ?></label></td>
                        <td><input type="text" class="input-tool" id="timezone" name="timezone" placeholder="3" value="3" /></td>
                    </tr>
                    <tr>
                        <td><label for="app_url">App url</label></td>
                        <td><input type="text" class="input-tool" id="app_url" name="app_url" value="<?= $loginskel->getBaseURL(); ?>"/></td>
                    </tr>
                    <tr>
                        <td><label for="app_url">App path</label></td>
                        <td><input type="text" class="input-tool" id="app_path" name="app_path" value="<?= $loginskel->getDirectoryPath(); ?>"/></td>
                    </tr>
                </tbody>
            </table>
            <h4><?= $loginskel->getTranslation('login_attempts'); ?></h4>
            <table id="default-table" class="install_table">
                <tbody>
                    <!-- Predefined global fields -->
                    <tr>
                        <td><label for="max_attempts"><?= $loginskel->getTranslation('max_attempts'); ?></label></td>
                        <td><input type="text" class="input-tool" id="max_attempts" name="max_attempts" value="3" /></td>
                    </tr>
                </tbody>
            </table>
            <p class="paragrah-install"><?= $loginskel->getTranslation('max_interval_info'); ?></p>
            <table id="default-table" class="install_table">
                <tbody>
                    <!-- Predefined global fields -->
                    <tr>
                        <td><label for="max_attempts_interval"><?= $loginskel->getTranslation('max_interval'); ?></label></td>
                        <td><input type="text" class="input-tool" id="max_attempts_interval" name="max_attempts_interval" value="1 hour" /></td>
                    </tr>
                </tbody>
            </table>
            <table id="default-table" class="install_table">
                <tbody>
                    <!-- Predefined global fields -->
                    <tr>
                        <td><label for="block_duration"><?= $loginskel->getTranslation('block_duration'); ?></label></td>
                        <td><input type="text" class="input-tool" id="block_duration" name="block_duration" value="3600" /></td>
                    </tr>
                </tbody>
            </table>
            <button type="submit" id="submit-button-conf"><?= $loginskel->getTranslation('save_global'); ?></button>
            <input type="hidden" name="global_config" value="1">
        </form>
        <?php elseif (!$global_config_success && !$secu_success): ?>
        <h4><?= $loginskel->getTranslation('validate_account'); ?></h4>
        <p class="paragrah-install"><?= $loginskel->getTranslation('validate_account_info'); ?></p>
        <form method="post">
            <input type="hidden" name="secu_config" value="1">
            <table id="default-table" class="install_table">
                <tbody>
                    <!-- Predefined global fields -->
                    <tr>
                        <td>
                            <div class="switch">
                                <input type="checkbox" name="toggle_validate" id="toggle_validate" <?=(isset($_SESSION['validate_account'])) ? "checked": ""; ?>/>
                                <label for="toggle_validate"></label>
                            </div>
                        </td>
                        <td>
                            <div class="hidden-content" data-for="toggle_validate">
                                <select name="validate_method" id="validate_method">
                                    <option value="token"<?=(isset($_SESSION['validate_method'])&&$_SESSION['validate_method']==='token') ? " selected": ""; ?>>Token</option>
                                    <option value="code"<?=(isset($_SESSION['validate_method'])&&$_SESSION['validate_method']==='code') ? " selected": ""; ?>><?= $loginskel->getTranslation('code'); ?></option>
                                </select>
                                <label><?= $loginskel->getTranslation('validate_method'); ?></label>
                            </div>
                        </td>
                    </tr>
                </tbody>
            </table>
            <h4><?= $loginskel->getTranslation('2fa_auth'); ?></h4>
            <p class="paragrah-install"><?= $loginskel->getTranslation('2fa_auth_info'); ?></p>
            <table id="default-table" class="install_table">
                <tbody>
                    <!-- Predefined global fields -->
                    <tr>
                        <td><label for="toggle_2fa">2FA</label></td>
                        <td>
                            <div class="switch">
                                <input type="checkbox" name="toggle_2fa" id="toggle_2fa"<?=(isset($_SESSION['2fa_auth'])) ? " checked": ""; ?>/>
                                <label for="toggle_2fa"></label>
                            </div>
                        </td>
                    </tr>
                </tbody>
            </table>
            <div class="hidden-content" data-for="toggle_2fa">
                <?php if (isset($_SESSION['errors']['2fa_codes_path'])): ?>
                    <ul class="list-errors">
                            <li class="error"><?php echo htmlspecialchars($_SESSION['errors']['2fa_codes_path']); ?></li>
                    </ul>
                <?php endif; ?>
                <p class="paragrah-install"><span class="proposed"><b><?= $loginskel->getTranslation('default_codes_path'); ?>: </b><?= $loginskel->getBasePath(); ?>/.codes/</span></p>
                <table id="default-table" class="install_table">
                    <tbody>
                        <!-- Predefined global fields -->
                        <tr>
                            <td><label for="codes_path"><?= $loginskel->getTranslation('codes_path'); ?></label></td>
                            <td><input type="text" class="input-tool key_field" id="codes_path" name="codes_path" value="<?= $loginskel->getBasePath(); ?>/.codes/" /></td>
                        </tr>
                    </tbody>
                </table>
            </div>
            <h4><?= $loginskel->getTranslation('jwt_enable'); ?></h4>
            <p class="paragrah-install"><?= $loginskel->getTranslation('jwt_enabled_info'); ?></p>

            <table id="default-table" class="install_table">
                <tbody>
                    <!-- Predefined global fields -->
                    <tr>
                        <td><label for="toggle_jwt">JWT</label></td>
                        <td>
                            <div class="switch">
                                <input type="checkbox" name="toggle_jwt" id="toggle_jwt"<?=(isset($_SESSION['jwt_auth'])) ? " checked": ""; ?>/>
                                <label for="toggle_jwt"></label>
                            </div>
                        </td>
                    </tr>
                </tbody>
            </table>
            <div class="hidden-content" data-for="toggle_jwt">
                <h4><?= $loginskel->getTranslation('rsa_keys'); ?></h4>
                <p class="paragrah-install"><?= $loginskel->getTranslation('rsa_keys_info'); ?></p>
                
                <?php if (isset($_SESSION['errors']['jwt_keys_path'])): ?>
                    <ul class="list-errors">
                            <li class="error"><?php echo htmlspecialchars($_SESSION['errors']['jwt_keys_path']); ?></li>
                    </ul>
                <?php endif; ?>
                <p class="paragrah-install"><span class="proposed"><b><?= $loginskel->getTranslation('default_keys_path'); ?></b><?= $loginskel->getBasePath(); ?>/.keys/</span></p>
                <table id="default-table" class="install_table">
                    <tbody>
                        <!-- Predefined global fields -->
                        <tr>
                            <td><label for="keys_path"><?= $loginskel->getTranslation('keys_path'); ?></label></td>
                            <td><input type="text" class="input-tool key_field" id="keys_path" name="keys_path" value="<?= $loginskel->getBasePath(); ?>/.keys/" /></td>
                        </tr>
                    </tbody>
                </table>
                <h4><?= $loginskel->getTranslation('jwt_encrypted'); ?></h4>
                <p class="paragrah-install"><?= $loginskel->getTranslation('jwt_encrypted_info'); ?></p>
                <table id="default-table" class="install_table">
                    <tbody>
                        <!-- Predefined global fields -->
                        <tr>
                            <td><label for="toggle_jwt">Encrypted JWT</label></td>
                            <td>
                                <div class="switch">
                                    <input type="checkbox" name="toggle_jwt_encrypted" id="toggle_jwt_encrypted"<?=(isset($_SESSION['jwt_encrypt'])) ? " checked": ""; ?> />
                                    <label for="toggle_jwt_encrypted"></label>
                                </div>
                            </td>
                        </tr>
                    </tbody>
                </table>   
                <?php if (isset($_SESSION['errors']['no_encryption_key'])): ?>
                    <ul class="list-errors">
                        <li class="error"><?php echo htmlspecialchars($_SESSION['errors']['no_encryption_key']); ?></li>
                    </ul>
                <?php endif; ?>
                <div class="hidden-content" data-for="toggle_jwt_encrypted">
                    <table id="default-table" class="install_table">
                        <tbody>
                            <!-- Predefined global fields -->
                            <tr>
                                <td><label for="encryption_key"><?= $loginskel->getTranslation('encryption_key'); ?></label></td>
                                <td><input type="text" class="input-tool key_field" id="encryption_key" name="encryption_key" value="<?= (isset($_SESSION['jwt_encrypt_key'])&&!empty($_SESSION['jwt_encrypt_key']))?$_SESSION['jwt_encrypt_key']:"";?>" /></td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
            
            <button type="submit" ><?= $loginskel->getTranslation('save_security'); ?></button>
        </form>
    <?php else: ?>
        <h3 class="success"><?= $loginskel->getTranslation('installation_completed'); ?></h3>
        <p><?= $loginskel->getTranslation('installation_instructions'); ?></p>
        <a class="admin-link" href="register"><?= $loginskel->getTranslation('register_admin'); ?></a>
    <?php endif; ?>
</div>
<script>
    const userTimezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
    
    const timezoneElement = document.getElementById('timezone');
    
    if (timezoneElement) {
        document.getElementById('timezone').value = userTimezone;
    }

    document.addEventListener('DOMContentLoaded', () => {
        
        const form_db = document.getElementById('connection-form');
        const submitButtonDB = document.getElementById('submit-button-db');
        
        if (form_db) {
            form_db.addEventListener('submit', function (e) {
                // Change the button text and disable it
                submitButtonDB.innerHTML = '<div class="loader"></div>';
                submitButtonDB.disabled = true;
            });
        }
        
        const form_conf = document.getElementById('configure-form');
        const submitButtonConf = document.getElementById('submit-button-conf');
        
        if (form_conf) {
            form_conf.addEventListener('submit', function (e) {
                // Cambia el texto del botón y desactívalo
                submitButtonConf.innerHTML = '<div class="loader"></div>';
                submitButtonConf.disabled = true;
            });
        }
        
        // Get all switches
        const switches = document.querySelectorAll('.switch input');

        // Function to update the visibility of associated content
        function updateContentVisibility() {
            switches.forEach(switchElem => {
                const contentId = switchElem.id;
                const content = document.querySelector(`.hidden-content[data-for="${contentId}"]`);

                if (switchElem.checked) {
                    content.style.display = 'block';
                } else {
                    content.style.display = 'none';
                }
            });
        }

        // Add events to update visibility when the state of any switch changes
        switches.forEach(switchElem => {
            switchElem.addEventListener('change', updateContentVisibility);
        });

        // Initialize state on page load
        updateContentVisibility();
    });
</script>
<?php
include '../template/footer.php';
?>
 

