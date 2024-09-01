<?php

require '../src/LoginSkel.php';

$loginskel = new LoginSkel();

$response = $loginskel->handleRequest();

// Send the response in JSON format
header('Content-Type: application/json');
echo json_encode($response);

