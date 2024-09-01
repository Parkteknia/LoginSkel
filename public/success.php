<?php

require '../src/LoginSkel.php';

$loginskel = new LoginSkel();

$ip = $_SERVER['REMOTE_ADDR'];

if ($loginskel->isIpBlocked($ip)) {
    header("HTTP/1.1 401 Unauthorized");
    header("Location: banned.php");
    exit;
}

$username = isset($_GET['username']) ? htmlspecialchars($_GET['username']) : 'Usuario';

include '../template/header.php'
?>

    <div class="container">
        <h1><?= $loginskel->getTranslation('successful_registration'); ?></h1>
        <p class="success"><?= $loginskel->getTranslation('successful_registration_user'); ?>: <?php echo $username; ?>.</p>
        <?php
        if (isset($_SESSION['account_validating_token'])) {
        ?>    
        <p class="success"><?= $loginskel->getTranslation('email_link_sended'); ?></p>  
        
        <?php } 
        
        if (isset($_GET['qr_path'])) {
            echo '<img src="' . htmlspecialchars($_GET['qr_path']) . '" alt="'.$loginskel->getTranslation('qr_code').'">';
        }
        
        ?>
        <p><a href="login"><?= $loginskel->getTranslation('login_back'); ?></a></p>
    </div>

<?php
include "../template/footer.php";
?>
