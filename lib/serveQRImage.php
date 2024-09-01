<?php
$config = require '../config/config.php';
require 'qrServer.php';
// Get the 'image' parameter from the URL
$imageParam = isset($_GET['image']) ? $_GET['image'] : '';
// Read base path from configuration
$baseDir = rtrim($config['qr_codes_folder'], '/') . '/';
// Build the full path to the image
$imageParam = basename($imageParam);
$imagePath = realpath($baseDir . $imageParam);
// Check if the full path is valid and points to a real file
if ($imagePath && file_exists($imagePath) && strpos($imagePath, $baseDir) === 0) {
    // Call static method to serve the image
    QRImageServer::serveQRImage($imagePath);
} else {
    // Handle case where file is not found or path is invalid
    header("HTTP/1.0 404 Not Found");
    echo "Image not found or invalid path.";
}