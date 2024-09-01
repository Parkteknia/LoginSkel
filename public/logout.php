<?php
require '../src/LoginSkel.php';

$loginskel = new LoginSkel();

$loginskel->logout();

header('Location: index');

exit();
