<?php
require '../src/LoginSkel.php';

$loginskel = new LoginSkel();

if (!$loginskel->isLoggedIn()) {
    header('Location: login');
    exit();
}

$userConnection = $loginskel->getUserConnectionData();

if ($loginskel->isIpBlocked($userConnection['ip'])) {
    header("HTTP/1.1 401 Unauthorized");
    header("Location: banned.php");
    exit;
}

$user = $loginskel->getUser();

$csrf_token = $loginskel->generateCSRFToken();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    
    if ($loginskel->verifyCSRFToken($_POST['csrf_token'])) {
    
        $code = implode('', $_POST['code']);
    
        if($loginskel->validate2faCode($code)){

            $totp_secret = $loginskel->getTOTPSecret($user['username']);
            $totp = $loginskel->getTOPT();
            $totp->verifyCode($totp_secret, $code, 2);

            if($totp->verifyCode($totp_secret, $code, 2)) {
                $loginskel->mark2faValidated();
                // Redirigir a la página protegida
                if($loginskel->isUserAdmin($user['username'])) {
                    header('Location: /LoginSkel/admin');
                    exit();
                }else{
                    header('Location: /');
                    exit();
                }
            }else{
                
                $loginskel->publicRecordLoginAttempt($userConnection['ip'], $userConnection['user_agent']);
                
                $error = $loginskel->getTranslation('incorrect_2fa');
            }
        } else {
            $error = $loginskel->getTranslation('incorrect_2fa');
        }
    }
}

include '../template/header.php';
?>
<div class="container">

    <h1><?= $loginskel->getTranslation('hello'); ?>, <?= $user['username']; ?></h1>
    <p><?= $loginskel->getTranslation('gauthenticator_get'); ?>!</p>
    <form class="form-code" id="codeForm" method="post">
        <div class="code-input-container">
            <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
            <input type="text" name="code[]" class="code-input" maxlength="1">
            <input type="text" name="code[]" class="code-input" maxlength="1">
            <input type="text" name="code[]" class="code-input" maxlength="1">
            <input type="text" name="code[]" class="code-input" maxlength="1">
            <input type="text" name="code[]" class="code-input" maxlength="1">
            <input type="text" name="code[]" class="code-input" maxlength="1">
        </div>
        <div class="info-container"><button class="validate-button"><?= $loginskel->getTranslation('validate'); ?></button></div>
    </form>

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

    document.getElementById('codeForm').addEventListener('paste', (e) => {
        const pastedData = e.clipboardData.getData('Text');
        if (/^\d{6}$/.test(pastedData)) {
            document.querySelectorAll('.code-input').forEach((input, idx) => {
                input.value = pastedData[idx] || '';
            });
            e.preventDefault();
        }
    });
</script>
<?php
include '../template/footer.php';
?>
