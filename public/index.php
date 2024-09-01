<?php

session_start();

require_once '../src/Install.php';

$loginskel = new Install();

$global_config_success = $loginskel->isInstalled();

if (!$global_config_success) {
    // Redirect to the installation page if the installation is not complete
    header('Location: install');
    exit();
}

// Rest of the logic for authenticated users
$_SESSION = [];
session_destroy();
if (isset($_COOKIE[session_name()])) {
    // Delete the cookie from the previous session
    setcookie(session_name(), '', time() - 42000, '/');
}
header("HTTP/1.1 401 Unauthorized");
header('Location: login');
exit();
