<?php

require '../src/LoginSkel.php';

$loginskel = new LoginSkel();

$ip = $_SERVER['REMOTE_ADDR'];

if ($loginskel->isIpBlocked($ip)) {
    header("HTTP/1.1 401 Unauthorized");
    header("Location: banned");
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    
    $email = $_POST['email'];

    // Validar el correo electrónico
    if (!$loginskel->validateEmail($email)) {
        
        $errors = "Invalid email address";
        
    }else{

        if ($loginskel->resendVerificationEmail($email)) {
            $success = $loginskel->getTranslation('resend_verification_success');
        } else {
            $errors = $loginskel->getTranslation('resend_verification_error');
        }
    }
}

$csrf_token = $loginskel->generateCSRFToken();

include '../template/header.php';

?>
<div class="container">
    <h1><?= $loginskel->getTranslation('account_activation'); ?></h1>
    <p><?= $loginskel->getTranslation('email_code_sended'); ?></p>
    <?php if (isset($errors)) { ?>
        <p class="error"><?php echo $validation_error; ?></p>
    <?php } ?>
    <form method="post" action="">
        <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
        <label for="email"><?= $loginskel->getTranslation('email_address'); ?>:</label>
        <input type="email" name="email" required>
        <button type="submit"><?= $loginskel->getTranslation('resend_verification_link'); ?></button>
    </form>
</div>

<?php
include '../template/footer.php';
?>