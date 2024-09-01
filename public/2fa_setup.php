<?php
require '../src/LoginSkel.php';

$loginskel = new LoginSkel();

require_once '../lib/phpqrcode/qrlib.php';
require_once '../config/config.php';

$user = $_SESSION['user'];
$qrCodeImage = $_SESSION['qr_image'];

if (!$user || !$qrCodeImage) {
    header('Location: login');
    exit();
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        
    if ($loginskel->verifyCSRFToken($_POST['csrf_token'])) {
        
        if(isset($_POST['2fa_conf'])&&($_POST['2fa_conf']==="true")) {
            
            $loginskel->updateUser2faConf($user, true);
            $loginskel->destroySession();
            header('Location: login');
        }
    }
}

$csrf_token = $loginskel->generateCSRFToken();

include '../template/header.php';

// URL of the PHP script that serves the image with the parameter
$qrCodeUrl = '/LoginSkel/lib/serveQRImage.php?image=' . urlencode($qrCodeImage);

?>

    <div class="container">
        <h1><?= $loginskel->getTranslation('successful_registration'); ?></h1>
        <p class="success"><?= $loginskel->getTranslation('successful_registration_user'); ?>: <?php echo $user; ?>.</p>
        <p class="info"><?= $loginskel->getTranslation('2fa_info'); ?></p>
        <h2><?= $loginskel->getTranslation('configure_2fa'); ?></h2>
        <p><?= $loginskel->getTranslation('scan_qr'); ?></p>
        <img src="<?php echo $qrCodeUrl; ?>" alt="QR Code">
    
    <form method="post">
        <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
        <input type="hidden" name="2fa_conf" value="true">
        <button type="submit"><?= $loginskel->getTranslation('scanned_qr'); ?></button>
    </form>
    </div>
<?php

include '../template/header.php';
