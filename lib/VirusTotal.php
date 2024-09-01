<?php

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 * Description of VirusTotal
 *
 * @author P3r4nd
 */
class VirusTotal {
    
    private $apiKey;
    private $baseUrlFileScan;
    private $baseUrlFileReport;

    public function __construct($apiKey) {
        $this->apiKey = $apiKey;
        $this->baseUrlFileScan = "https://www.virustotal.com/api/v3/files";
        $this->baseUrlFileReport = "https://www.virustotal.com/api/v3/analyses";
    }
    
    
    function scanFile($filePath) {
        $url = 'https://www.virustotal.com/api/v3/files';
        $fileData = file_get_contents($filePath);

        $boundary = '----WebKitFormBoundary' . md5(time());

        $headers = [
            'Content-Type: multipart/form-data; boundary=' . $boundary,
            'x-apikey: ' . $this->apiKey
        ];

        $body = "--" . $boundary . "\r\n";
        $body .= "Content-Disposition: form-data; name=\"file\"; filename=\"" . basename($filePath) . "\"\r\n";
        $body .= "Content-Type: application/octet-stream\r\n\r\n";
        $body .= $fileData . "\r\n";
        $body .= "--" . $boundary . "--\r\n";

        $context = stream_context_create([
            'http' => [
                'method'  => 'POST',
                'header'  => implode("\r\n", $headers),
                'content' => $body,
                'ignore_errors' => true
            ]
        ]);

        $response = file_get_contents($this->baseUrlFileScan, false, $context);

        if ($response === false) {
            throw new Exception('Error al enviar el archivo a VirusTotal.');
        }


        return $response;
        
    }

    // Función para obtener el reporte de un análisis basado en un id
    function getFileReport($analysisId) {
        $url = "{$this->baseUrlFileReport}/{$analysisId}";

        $headers = [
            'x-apikey: ' . $this->apiKey,
        ];

        $context = stream_context_create([
            'http' => [
                'method'  => 'GET',
                'header'  => implode("\r\n", $headers),
                'ignore_errors' => true
            ]
        ]);

        $response = file_get_contents($url, false, $context);

        if ($response === false) {
            throw new Exception('Error al consultar los resultados del análisis en VirusTotal.');
        }

        return json_decode($response, true);
    }
    
    // Función para verificar si un archivo está limpio
    public function isFileClean($fileReport) {
        if (isset($fileReport['data']['attributes']['stats'])) {
            $stats = $fileReport['data']['attributes']['stats'];
            return $stats['malicious'] == 0 && $stats['suspicious'] == 0;
        }

        // Si no hay 'stats', comprueba el campo 'results'
        if (isset($fileReport['data']['attributes']['results'])) {
            $results = $fileReport['data']['attributes']['results'];

            foreach ($results as $engine => $details) {
                if (isset($details['category']) && $details['category'] === 'malicious') {
                    return false;
                }
            }

            // Si ningún motor detecta como malicioso
            return true;
        }

        // Si ninguna de las estructuras anteriores está presente, asume que no está limpio
        return false;
    }
}
