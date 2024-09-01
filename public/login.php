<?php

require '../src/LoginSkel.php';

$loginskel = new LoginSkel();

if ($loginskel->getAppErrors()) {
    
    if ($loginskel->getAppErrors()[0] === "db_error") {
        header('Location: install');
        exit();
    }
}

$isHttpsEnabled = $loginskel->isHttpsEnabled();

$userConnection = $loginskel->getUserConnectionData();

if ($loginskel->isIpBlocked($userConnection['ip'])) {
    header("HTTP/1.1 401 Unauthorized");
    header("Location: banned");
    exit;
}

unset($_SESSION['banned']);

$error = '';

$lang = $loginskel->getCurrentLanguage();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    if ($loginskel->verifyCSRFToken($_POST['csrf_token'])) {

        $identifier = $loginskel->sanitizeInput($_POST['identifier']);
        $password = $loginskel->sanitizeInput($_POST['password']);
        
        if (!$loginskel->isUserAccountActive($identifier)) {
                
            $validation_method = $loginskel->getAccountValidationType();    
            
            $validation_in_time = $loginskel->isValidationInTime($identifier, $validation_method);

            if($validation_in_time) {

                $_SESSION['remaining_activation_time'] = $loginskel->getRemainingTime($validation_in_time);

                if ($validation_method === "code") {
                    $_SESSION['validate_code'] = true;
                    header("Location: validate.php");
                    exit;
                }

                if ($validation_method === "token") {
                    $_SESSION['validate_token'] = true;
                    header("Location: validate.php");
                    exit;
                }
            }
        }
            
        if ($loginskel->login($userConnection['ip'], $userConnection['user_agent'], $identifier, $password)) {
            
            $user = $loginskel->getUser();  
            
            if($loginskel->get2Factor()) {
                                
                $user_secret_key = $loginskel->getTOTPSecret($user['username']);
                
                if (!$user_secret_key) {
                    $_SESSION['user'] = $user['username'];
                    $loginskel->genAndUpdateUserTotp($user['username']);
                    $qr_data = $loginskel->generateQR($user['username']);
                    
                    if ($qr_data) {
                        
                        $_SESSION['qr_image'] = $qr_data;
                        header("Location: 2fa_setup");
                        exit();
                    }
                    
                }else{
                  
                    $loginskel->reset2fa();
                    header("Location: 2fa_validate");
                    exit;
                }
            }
            
            $header_loc = sprintf('Location: %s', $loginskel->getAdminPath());

            if(!$loginskel->isUserAdmin($user['username'])) {
                $header_loc = sprintf('Location: %s', $loginskel->getAppURL());
            }
            
            header($header_loc);
            exit();
            
            
        } else {
            header("HTTP/1.1 401 Unauthorized");
            $error = $loginskel->getTranslation('wrong_identifier');
        }
    } else {
        $error = $loginskel->getTranslation('invalid_csrf');
    }
}

$csrf_token = $loginskel->generateCSRFToken();

include '../template/header.php';

?>

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
        <h2 class="sub-title"><?= $loginskel->getTranslation('login_title'); ?></h2>
        <?php if ($error): ?>
            <p class="error"><?php echo $error; ?></p>
        <?php endif; ?>
        <form method="post" action="">
            <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
            <label for="identifier"><?php echo $loginskel->getTranslation('identifier'); ?>:</label>
            <div class="input-container">
                <div class="input-icon">
                    <i class="fas fa-user"></i>
                </div>
                <input type="text" id="identifier" name="identifier" required>
            </div>
            <label for="username"><?php echo $loginskel->getTranslation('password'); ?>:</label>
            <div class="input-container">
                <div class="input-icon">
                    <i class="fas fa-lock"></i>
                </div>
                <input type="password" id="password" name="password" required autocomplete="off">
                <div id="caps-lock-warning" class="caps-warning"><i class="fas fa-exclamation-triangle"></i> ¡Mayúsculas activas!</div>
                <br>
            </div>
            <div class="button-container">
                <button type="submit" class="primary-button"><?php echo $loginskel->getTranslation('login_button'); ?></button>
                <a class="secondary-button button-secondary" href="register"><?php echo $loginskel->getTranslation('register_button'); ?></a>
            </div>
            
        </form>
        <p></p>
        <p class="lost-pass"><a href="forgot_pass"><?php echo $loginskel->getTranslation('forgot_password'); ?></a></p>
    </div>
    <script>
        const passwordInput = document.getElementById('password');
        const capsLockWarning = document.getElementById('caps-lock-warning');
        
        passwordInput.addEventListener('keyup', (event) => {
            if (event.getModifierState('CapsLock')) {
                capsLockWarning.style.display = 'block';
            } else {
                capsLockWarning.style.display = 'none';
            }
        });

        passwordInput.addEventListener('focus', (event) => {
            if (event.getModifierState('CapsLock')) {
                capsLockWarning.style.display = 'block';
            }
        });

        passwordInput.addEventListener('blur', () => {
            capsLockWarning.style.display = 'none';
        });
    </script>
<?php

include '../template/footer.php';

?>