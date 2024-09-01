<?php

class QRImageServer
{
    /**
     * Serves a QR image from a specific route.
     *
     * @param string $imagePath Full path to the QR file.
     * @return void
     */
    public static function serveQRImage($imagePath)
    {
        // Check if the file exists
        if (file_exists($imagePath)) {
            // Get the content type (MIME type)
            $mimeType = mime_content_type($imagePath);
            // Make sure the MIME type is appropriate for the image
            if (in_array($mimeType, ['image/jpeg', 'image/png', 'image/gif'])) {
                ob_end_clean();
                header('Content-Type: ' . $mimeType);
                header('Content-Length: ' . filesize($imagePath));
                // Read and send the contents of the file
                $file = fopen($imagePath, 'rb');
                if ($file) {
                    while (!feof($file)) {
                        echo fread($file, 8192);
                        flush(); // Ensure content is delivered immediately
                    }
                    fclose($file);
                } else {
                    // Handle the case where the file cannot be opened
                    header("HTTP/1.0 500 Internal Server Error");
                    echo "Cannot open file.";
                }
            } else {
                // Handling unsupported MIME type
                header("HTTP/1.0 415 Unsupported Media Type");
                echo "Image type not supported.";
            }
        } else {
            // Handling the case where the file is not found
            header("HTTP/1.0 404 Not Found");
            echo "Image not found.";
        }
    }
}