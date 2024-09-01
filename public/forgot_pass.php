<?php

require '../src/LoginSkel.php';

$loginskel = new LoginSkel();

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    
    $identifier = $loginskel->sanitizeInput($_POST['identifier']);
    
    $user = $loginskel->findUserByIdentifier($identifier);

    if ($user) {
        $token = $loginskel->generatePasswordResetToken($user['id']);
        if ($loginskel->sendMail($user['email'], "pass_reset", $token)) {
            $message = $loginskel->getTranslation('password_reset_email_link');
            $form_hide = true;
        }
    } else {
        $error = $loginskel->getTranslation('password_reset_email_link');
    }
}

include '../template/header.php';

?>
<div class="container">
    <h1>Reset password</h1>
    <?php if(isset($message)){ ?>
    <div class="message">
        <p><?php echo $message; ?></p>
    </div>
    <?php } else { ?>
    <p><?= $loginskel->getTranslation('password_reset_action'); ?></p>
    <?php } ?>
    <?php if(isset($error)){ ?>
    <div class="error">
        <p><?php echo $error; ?></p>
    </div>
    <?php } ?>
    <?php if(!isset($form_hide)) { ?>
    <form method="post" action="">
        <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
        <label for="identifier"><?php echo $loginskel->getTranslation('identifier'); ?>:</label>
        <div class="input-container">
            <div class="input-icon">
                <i class="fas fa-user"></i>
            </div>
            <input type="text" id="identifier" name="identifier" required>
        </div>
        <button type="submit"><?= $loginskel->getTranslation('reset_password'); ?></button>
    </form>
    <p><a href="login"><?php echo $loginskel->getTranslation('login_back'); ?></a></p>
    <?php } ?>
</div>
<?php
include '../template/footer.php';
?>

