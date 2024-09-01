<?php
session_start();// Debugging: Print session ID
echo 'Session ID in error.php: ' . session_id();
$errorMessage = $_SESSION['error_message'] ?? 'Unknown error';
$errorCode = $_SESSION['error_code'] ?? 500;

// Clear session error data
unset($_SESSION['error_message']);
unset($_SESSION['error_code']);

include '../template/header.php'
?>

    <div class="container">
        <h1>Error <?php echo $errorCode; ?></h1>
        <p><?php echo htmlspecialchars($errorMessage, ENT_QUOTES, 'UTF-8'); ?></p>
        <a href="/">Go back to home</a>
    </div>

<?php
include "../template/footer.php";
?>


