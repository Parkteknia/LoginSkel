<?php

require '../src/LoginSkel.php';

$loginskel = new LoginSkel();

$ip = $_SERVER['REMOTE_ADDR'];

if ($loginskel->isIpBlocked($ip)) {
    header("HTTP/1.1 401 Unauthorized");
    header("Location: banned");
    exit;
}

if(!isset($_SESSION['validate_account_process']) || $_SESSION['validate_account_process'] !== true) {
    header("Location: login");
    exit;
}

if ($_SERVER['REQUEST_METHOD'] == 'POST') {

    if ($loginskel->verifyCSRFToken($_POST['csrf_token'])) {
    
        $activation_code = implode('', $_POST['activation_code']);
        
        if ($loginskel->validateActivationCode($activation_code)) {
            
            //$user = $ls->activateAccountByCode($activation_code);
            $user = $loginskel->getUserByName('salmon');
            
            if ($user) {
                
                if ($loginskel->get2Factor()) {
                
                    $qr_data = $loginskel->generateQR($user['username']);

                    if ($qr_data) {
                        $_SESSION['user'] = $user['username'];
                        $_SESSION['qr_image'] = $qr_data;
                        header("Location: 2fa_setup.php");
                        exit();
                    }
                }
                
                header("Location: success.php?username=" . $user['username']);
                exit();
                
            } else {
                $validation_error = $loginskel->getTranslation('invalid_code');
            }
            
        }else{
            $validation_error = $loginskel->getTranslation('invalid_code');
        }
    }
    
} elseif (isset($_GET['t'])) {
    
    $token = $_GET['token'] ?? null;
    // We check if the token has expired

    if ($loginskel->isExpiredToken($token)===true) {
        $loginskel->invalidateExpiredToken($token); // Invalida el token expirado
        $loginskel->destroySession();
        $loginskel->regenerateSession();
        header("Location: resend.php");
        exit;
    }
    
    $userID = $loginskel->activateAccountByToken($token);
    
    if ($userID) {
        
        if($loginskel->get2Factor()) {
            
            $user = $loginskel->getUser2faConf($userID['user_id']);

            if (!isset($user['2fa_conf']) || $user['2fa_conf']===0) {
               
               
                
                    $_SESSION['user'] = $user['username'];
                    $loginskel->genAndUpdateUserTotp($user['username']);
                    $qr_data = $loginskel->generateQR($user['username']);
                    
                    if ($qr_data) {
                        
                        $_SESSION['qr_image'] = $qr_data;
                        header("Location: 2fa_setup");
                        exit();
                    }
                /*    
                }else{
                  
                    $ls->reset2fa();
                    header("Location: 2fa_validate");
                    exit;*/
                }
            }else{
                header("Location: login");
                exit();
            }
        
        header("Location: login");
        exit;
    } else {
        echo $loginskel->getTranslation('invalid_token');
    }
}


if (isset($_SESSION['remaining_activation_time']) && isset($_SESSION['code_generated_at']) && isset($_SESSION['valid_interval'])) {
    
    $code_generated_at = $_SESSION['code_generated_at'];
    $code_interval = $_SESSION['valid_interval'];
    $current_time = time();
    
    // Calculate the remaining time
    $time_remaining = ($code_generated_at + $code_interval) - $current_time;
    $time_remaining = max($time_remaining, 0); // Asegurarse de que no sea negativo
    
    if($time_remaining > 0 && $time_remaining < 2) {
        $time_key = 'minute';
    }elseif($time_remaining > 1) {
        $time_key = 'minutes';
    }
    
    // Convert to minutes and seconds
    $minutes = floor($time_remaining / 60);
    $seconds = $time_remaining % 60;
    
    // For informational purposes of the session 
    echo "<pre>";
    var_dump($time_remaining, $minutes, $seconds);
    echo "</pre>";
     echo "<pre>";
    print_r($_SESSION);
    echo "</pre>";
}

$csrf_token = $loginskel->generateCSRFToken();

include '../template/header.php';

?>
<div class="container">

    <h1>Account Activation</h1>
    
    <?php if(isset($validation_error)){ ?>
    <p class="error"><?php echo $validation_error; ?></p>
    <?php } ?>
    <?php if(isset($_SESSION['account_validating_code']) && $_SESSION['account_validating_code']) { ?>
    <p><?= $loginskel->getTranslation('email_code_sended'); ?></p>

    <p><?= $loginskel->getTranslation('code_invalidated_in'); ?> <span class="remaining_time"><?php echo $minutes.":".$seconds; ?> <?= $loginskel->getTranslation($time_key); ?></span>.</p>
    <form class="form-code" id="codeForm" method="post">
        <div class="code-input-container">
            <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
            <input type="text" name="activation_code[]" class="code-input" maxlength="1">
            <input type="text" name="activation_code[]" class="code-input" maxlength="1">
            <input type="text" name="activation_code[]" class="code-input" maxlength="1">
            <input type="text" name="activation_code[]" class="code-input" maxlength="1">
            <input type="text" name="activation_code[]" class="code-input" maxlength="1">
            <input type="text" name="activation_code[]" class="code-input" maxlength="1">
        </div>
        <div class="info-container"><button class="validate-button"><?= $loginskel->getTranslation('validate'); ?></button></div>
    </form>
    <?php } ?>
    <?php if(isset($_SESSION['account_validating_token']) && $_SESSION['account_validating_token']) { ?>
    <p><?= $loginskel->getTranslation('email_link_sended'); ?></p>
    <p><?= $loginskel->getTranslation('link_invalidated_in'); ?> <span class="remaining_time"><?php echo $minutes.":".$seconds; ?> <?= $loginskel->getTranslation($time_key); ?></span></p>
    <?php } ?>
<?php if (isset($error)): ?>
        <p class="error"><?php echo $error; ?></p>
<?php endif; ?>

</div>
<script>
    document.querySelectorAll('.code-input').forEach((input, idx, inputs) => {
        input.addEventListener('input', (e) => {
            if (!/^\d$/.test(e.data)) {
                input.value = '';
            } else if (idx < inputs.length - 1) {
                inputs[idx + 1].focus();
            }
        });
    });
    
    const code_form = document.getElementById('codeForm');
    
    if (code_form) {
        code_form.addEventListener('paste', (e) => {
            const pastedData = e.clipboardData.getData('Text');
            if (/^\d{6}$/.test(pastedData)) {
                document.querySelectorAll('.code-input').forEach((input, idx) => {
                    input.value = pastedData[idx] || '';
                });
                e.preventDefault();
            }
        });
    }
    
    function startCountdown() {
        // Select the <span> element with the class 'remaining time'
        const timeElement = document.querySelector('.remaining_time');
        let totalSeconds = parseInt(timeElement.textContent, 10) * 60; // Convertir minutos a segundos

        // Function to update the counter display
        function updateDisplay(seconds) {
            const mins = Math.floor(seconds / 60);
            const secs = seconds % 60;
            const formattedMins = String(mins).padStart(2, '0');
            const formattedSecs = String(secs).padStart(2, '0');
            timeElement.textContent = `${formattedMins}:${formattedSecs}`;
        }

        // Update the initial display
        updateDisplay(totalSeconds);

        // Setting the interval for the counter
        const intervalId = setInterval(() => {
            if (totalSeconds <= 0) {
                clearInterval(intervalId); // Stop the counter when it reaches 00:00
                return;
            }
            totalSeconds--;
            updateDisplay(totalSeconds);
        }, 1000);
    }

    // Start counter when page is ready
    document.addEventListener('DOMContentLoaded', startCountdown);
</script>
<?php
include '../template/footer.php';
?>

