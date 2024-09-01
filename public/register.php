<?php
require '../src/LoginSkel.php';

$loginskel = new LoginSkel();

if (!empty($loginskel->getAppErrors())) {
    
    if ($loginskel->getAppErrors()[0] === "db_error") {
        header('Location: install');
        exit();
    }
}

if ($loginskel->isLoggedIn()) {
    header('Location: admin');
    exit();
}

$isHttpsEnabled = $loginskel->isHttpsEnabled();
$success_message = '';

$userConnection = $loginskel->getUserConnectionData();
        
if ($loginskel->isIpBlocked($userConnection['ip'])) {
    header("HTTP/1.1 401 Unauthorized");
    header("Location: banned");
    exit;
}

$lang = $loginskel->getCurrentLanguage();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    
    if ($loginskel->verifyCSRFToken($_POST['csrf_token'])) {
        
        $username = $loginskel->sanitizeInput($_POST['username']);
        $email = $loginskel->sanitizeInput($_POST['email']);
        $password = $loginskel->sanitizeInput($_POST['password']);
        
        if (!$loginskel->validateUsername($username)) {
            $reg_error = $loginskel->getTranslation('invalid_username');
        }
        
        if (!$loginskel->validateEmail($email)) {
            $reg_error = $loginskel->getTranslation('invalid_email');
        }
        
        $validate_ps = $loginskel->validatePassword($password);
        
        if(!is_int($validate_ps)||$validate_ps!==1) {
            if(isset($validate_ps['error'])&&$validate_ps['error']==='ps_known') {
                $reg_error = $loginskel->getTranslation('known_password');
            }elseif(!$validate_ps){ 
                $reg_error = $loginskel->getTranslation('password_not_validated');
            }
        }
       
        if (empty($reg_error) && empty($error)) {
            
            if($loginskel->register($userConnection['ip'], $userConnection['user_agent'], $username, $email, $password)) {
        
                $validation_method = $loginskel->getAccountValidationType();

                if ($validation_method) {

                    $_SESSION['validate_account_process'] = true;

                    $validation_in_time = $loginskel->isValidationInTime($username, $validation_method);

                    if($validation_in_time) {

                        $_SESSION['remaining_activation_time'] = $loginskel->getRemainingTime($validation_in_time);
                        $_SESSION['code_generated_at'] = time();
                        $_SESSION['valid_interval'] = 60 * 60;
                    }

                    if ($validation_method === "code") {
                        $_SESSION['account_validating_code'] = true;
                        header("Location: validate");
                        exit;
                    }

                    if ($validation_method === "token") {
                        $_SESSION['account_validating_token'] = true;
                        header("Location: validate");
                        exit;
                    }
                }

                if ($loginskel->get2Factor()) {
                
                    $qr_data = $loginskel->generateQR($username);

                    if ($qr_data) {
                        $_SESSION['user'] = $username;
                        $_SESSION['qr_image'] = $qr_data;
                        header("Location: 2fa_setup");
                        exit();
                    }
                }
                
                header("Location: success?username=" . urlencode($username));
                exit();
            
            } else {
                
                $error = $loginskel->getTranslation('register_failed');
            }
        } else {
            if ($loginskel->isIpBlocked($userConnection['ip'])) {
                header("HTTP/1.1 401 Unauthorized");
                header("Location: banned");
                exit;
            }
            
            $error = $loginskel->getTranslation('identifier_exists');
        }
    } else {
        $error = $loginskel->getTranslation('invalid_csrf');
    }
}

$csrf_token = $loginskel->generateCSRFToken();

include '../template/header.php';

?>
<?php $ps_field = 'password'; include 'assets/password_strength.php'; ?>    
    <div class="container">
        <div class="lang-header">
            <div class="language-menu">
                <form method="get" action="login">
                     <?php   echo $loginskel->renderLangMenu($lang); ?>
                </form>
            </div>
        </div>
        <?php if (!$isHttpsEnabled): ?>
        <div class="https-warning">
            <p><?= $loginskel->getTranslation('no_https'); ?></p>
        </div>
        <?php endif; ?>
        <h1>LoginSkel</h1>
        <h2 class="sub-title"><?= $loginskel->getTranslation('register_title'); ?></h2>
        <?php if (isset($reg_error)): ?>
            <p class="error"><?php echo $reg_error; ?></p>
        <?php endif; ?>
        <?php if (isset($error) && !isset($reg_error)): ?>
            <p class="error"><?php echo $error; ?></p>
        <?php endif; ?>
        <form method="post" action="">
            <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
            <label for="username"><?php echo $loginskel->getTranslation('username'); ?>:</label>
            <div class="input-container">
                <div class="input-icon">
                    <i class="fas fa-user"></i>
                </div>
                <input type="text" id="username" name="username" required>
            </div>
            <label for="email"><?php echo $loginskel->getTranslation('email'); ?>:</label>
            <div class="input-container">
                <div class="input-icon">
                    <i class="fas fa-envelope"></i>
                </div>
                <input type="text" id="email" name="email" required>
            </div>
            <label for="password"><?php echo $loginskel->getTranslation('password'); ?>:</label>
            <div class="input-container">
                <div class="input-icon">
                    <i class="fas fa-lock"></i>
                </div>
                <span id="password-strength" class="strength-indicator"></span>
                <input type="password" id="password" name="password" onkeyup="checkPasswordStrength()" required>
            </div>
            
            <div class="button-container">
                <button class="primary-button" type="submit"><?php echo $loginskel->getTranslation('register_button'); ?></button>
                <a class="secondary-button button-secondary" href="login"><?php echo $loginskel->getTranslation('login_button'); ?></a>
            </div>
        </form>
    </div>
<?php
include '../template/footer.php';
?>