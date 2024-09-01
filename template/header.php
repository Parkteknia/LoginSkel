<?php
/* 
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
if (basename(__FILE__) === basename($_SERVER['SCRIPT_FILENAME'])) {
    http_response_code(403);
    exit;
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
    <link rel="stylesheet" href="assets/styles.css">
    
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const password_input = document.getElementById('password');
            const new_password = document.getElementById('new_password');
            const repeat_password = document.getElementById('repeat_password');
            if(password_input) {
                password_input.value = '';
            }
            if(new_password) {
                new_password.value = '';
            }
            if(repeat_password) {
                repeat_password.value = '';
            }
        });
    </script>
</head>
<body class="<?php echo isset($body_class) ? htmlspecialchars($body_class) : ''; ?>">
    <div id="js-warning" class="js-warning">
        <p><?= $loginskel->getTranslation('javascript_warning'); ?></p>
    </div>
    <noscript>
        <style>
            #js-warning {
                display: block;
            }
        </style>
    </noscript>

