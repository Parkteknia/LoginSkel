<?php

require '../src/LoginSkel.php';
$loginskel = new LoginSkel();

if (!isset($_SESSION['banned']) || $_SESSION['banned'] !== true) {
    header("Location: login");
    exit;
}

$ip = $_SERVER['REMOTE_ADDR'];

if (!$loginskel->isIpBlocked($ip)) {
    unset($_SESSION['banned']);
    header("Location: index.php");
    exit;
}
include '../template/header.php';
?>

    <div class="container">
        <h1><?= $loginskel->getTranslation('denied_access'); ?></h1>
        <p><?= $loginskel->getTranslation('blocked_ip'); ?></p>
    </div>
<?php
include '../template/footer.php';
?>
