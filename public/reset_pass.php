<?php

require '../src/LoginSkel.php';

$loginskel = new LoginSkel();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    
    if ($loginskel->verifyCSRFToken($_POST['csrf_token'])) {
                
        if (isset($_POST['reset_2fa']) && $_POST['reset_2fa']) {
            
            $token = $_POST['token'];
            
            if ($loginskel->isExpiredToken($token)!==true) {
                
                $reset_2fa = $loginskel->reset2FACode($token);
                    
                if ($reset_2fa) {

                    if ($reset_2fa) {
                        $_SESSION['user'] = $reset_2fa['username'];
                        $_SESSION['qr_image'] = $reset_2fa['qr_image'];
                        header("Location: 2fa_setup.php");
                        exit();
                    }
                }
            }
        }
            
        $new_password = $loginskel->sanitizeInput($_POST['new_password']);
        $confirm_password = $loginskel->sanitizeInput($_POST['confirm_password']);
        
        if ($new_password !== $confirm_password) {

            $error = $loginskel->getTranslation('passwords_not_match');
        }

        if (!isset($error)) {

            if (!$loginskel->validatePassword($new_password)) {
                $error = $loginskel->getTranslation('password_not_validated');
            }
        }

        if (!isset($error)) {

            $token = filter_input(INPUT_POST, 'token', FILTER_SANITIZE_SPECIAL_CHARS);

            if ($loginskel->isExpiredToken($token)!==true) {
                if ($loginskel->resetPassword($token, $new_password)) {
                    $message = $loginskel->getTranslation('pass_reset_ok');
                    $login_process = true;
                } else {
                    $error = $loginskel->getTranslation('wrong_pass_reset_link');
                }
            }else{
                $loginskel->invalidateExpiredToken($token);
                $error = $loginskel->getTranslation('expired_token');
                $restart_process = true;
            }
        }
    }
}

if(isset($_GET['t'])) {
    // Getting and sanitizing the URL token
    $token = filter_input(INPUT_GET, 't', FILTER_SANITIZE_SPECIAL_CHARS);
}else{
    header("Location: login");
    exit;
}

$csrf_token = $loginskel->generateCSRFToken();

include '../template/header.php';

?>
<?php $ps_field = 'new_password'; include 'assets/password_strength.php'; ?> 
<div class="container">
    <h2>Restore password</h2>
    <?php if(isset($message)){ ?>
    <div class="message">
        <p><?php echo $message; ?></p>
    </div>
    <?php } ?>
    <?php if(isset($error)){ ?>
    <div class="error">
        <p><?php echo $error; ?></p>
    </div>
    <?php } ?>
    <?php if (!isset($restart_process) && !isset($login_process)) { ?>
    <form method="POST">
        <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
        <input type="hidden" name="token" value="<?php echo htmlspecialchars($token, ENT_QUOTES, 'UTF-8'); ?>">
        <label for="new_password"><?php echo $loginskel->getTranslation('new_password'); ?>:</label>
        <div class="input-container">
            <div class="input-icon">
                <i class="fas fa-lock"></i>
            </div>
            <span id="password-strength" class="strength-indicator"></span>
            <input type="password" id="new_password" name="new_password" onkeyup="checkPasswordStrength()" required autocomplete="off">
        </div>
        <label for="confirm_password"><?php echo $loginskel->getTranslation('confirm_password'); ?>:</label>
        <div class="input-container">
            <div class="input-icon">
                <i class="fas fa-lock"></i>
            </div>
            <input type="password" id="confirm_password" name="confirm_password" required autocomplete="off">
            <div id="caps-lock-warning" class="caps-warning"><i class="fas fa-exclamation-triangle"></i> ¡<?= $loginskel->getTranslation('active_caps'); ?>!</div>
            <div id="password-match-warning" class="match-warning"><i class="fas fa-exclamation-triangle"></i> ¡<?= $loginskel->getTranslation('passwords_not_match'); ?>!</div>
            <br>
        </div>
        <button type="submit"><?= $loginskel->getTranslation('reset_password'); ?></button>
        <p><a href="index.php"><?php echo $loginskel->getTranslation('login_back'); ?></a></p>
    </form>
    <?php if($loginskel->get2Factor()): ?>
    <div class="align-center">
        <p class="paragraph-bolder"><?php echo $loginskel->getTranslation('2fa_trouble'); ?></p>
        <form method="POST">
            <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
            <input type="hidden" name="token" value="<?php echo htmlspecialchars($token, ENT_QUOTES, 'UTF-8'); ?>">
            <input type="hidden" name="reset_2fa" value="true">
            <button type="submit" class="link-button"><?php echo $loginskel->getTranslation('reset_2fa'); ?></button>
        </form>    
    </div>
    <?php endif; ?>    
    </form>
    <?php } ?>
    <?php if(isset($restart_process)) { ?>
    <a class="button" href="forgot_pass"><?= $loginskel->getTranslation('reset_password'); ?></a>
    <?php } ?>
    <?php if (isset($login_process) && $login_process) { ?>
    <p><a href="index.php"><?php echo $loginskel->getTranslation('login_back'); ?></a></p>
    <?php } ?>

</div>
<script>
        document.addEventListener('DOMContentLoaded', function() {
            const passwordInput = document.getElementById('new_password');
            const capsLockWarning = document.getElementById('caps-lock-warning');
            const form = document.querySelector('form');
            const passwordMatchWarning = document.getElementById('password-match-warning');
            
            form.addEventListener('submit', function(event) {
                const newPassword = document.getElementById('new_password').value;
                const confirmPassword = document.getElementById('confirm_password').value;

                if (newPassword !== confirmPassword) {
                    passwordMatchWarning.style.display = 'block';
                    event.preventDefault();
                } else {
                    passwordMatchWarning.style.display = 'none';
                }
            });

            const checkCapsLock = (event) => {
                if (event.getModifierState && event.getModifierState('CapsLock')) {
                    capsLockWarning.style.display = 'block';
                } else {
                    capsLockWarning.style.display = 'none';
                }
            };

            passwordInput.addEventListener('keyup', checkCapsLock);
            passwordInput.addEventListener('focus', checkCapsLock);
            passwordInput.addEventListener('blur', () => {
                capsLockWarning.style.display = 'none';
            });
        });
    </script>
<?php
include '../template/footer.php';
?>