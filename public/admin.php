<?php

require '../src/LoginSkel.php';
require '../lib/VirusTotal.php';

$loginskel = new LoginSkel();

if (!$loginskel->isLoggedIn() || ($loginskel->get2Factor() && !$loginskel->has2faValidated())) {
    header('Location: login');
    exit();
}

$user = $loginskel->getUser();
$filters = $loginskel->getActivatedFilters();

if(!$loginskel->isUserAdmin($user['username'])) {
    header('Location: index');
    exit();  
}

$activeTab = '#config-global';
$globalTab = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    
    try {
        $post_json = file_get_contents('php://input');
        $post_data = json_decode($post_json);
    } catch (Exception $exc) {
       $post_data = false;
    }

    if(!empty($post_data)) {
        
        if (isset($post_data->gen_qr) && $post_data->gen_qr===true) {
            
            if ($loginskel->verifyCSRFToken($post_data->csrf_token)) {
            
                if ($loginskel->generateQR($user['username'], true, false)) {
                    echo json_encode(["success" => true]);
                    exit;
                }
                
                echo json_encode(["success" => false]);
                exit;
            }
            
            return false;
        }
    }

    if ($loginskel->verifyCSRFToken($_POST['csrf_token'])) {
                
        $errors = [];
        
        if (isset($_POST['gen_keys']) && $_POST['gen_keys']==="true") {
            
            $loginskel->generateRSAKeys();
        }
        
        if (isset($_POST['jwt_active']) && $_POST['jwt_active']==="true") {
            $loginskel->enableJWT();
        }
        
        if (isset($_POST['save_global_payload']) && $_POST['save_global_payload']==="true") {
            
            $globalTab = '#jwt-info';
            
            $keys = $_POST['key'] ?? [];
            
            $unwantedKeys = ['csrf_token' => '', 'save_global_payload' => ''];
            
            $payloadData = array_diff_key($_POST, $unwantedKeys);

            $validatePayload = $loginskel->valdiatePayloadJWT($payloadData);
            
            if($validatePayload!==true) {
                $errors['global_payload'] = $validatePayload;
            }else{
                $savePayloadData = $loginskel->saveGlobalPayloadJWT($payloadData);
            }
        }
        
        if (isset($_POST['gen_qr']) && $_POST['action']===true) {
            
            $activeTab = '#config-2fa';
            
            if ($loginskel->generateQR($username, false, false)) {
                echo json_encode(["sucess" => true]);
                exit;
            }
            
            echo json_encode(["sucess" => false]);
            exit;
        }
        
        if (isset($_POST['2fa_config']) && filter_var($_POST['2fa_config'], FILTER_VALIDATE_BOOLEAN) && $_POST['2fa_config'] === "true") {
            
            $activeTab = '#config-2fa';
            
            if (!isset($_POST['toggle_2fa'])) {
                            
                $loginskel->disable2FA();
               
            }else{
                            
                $loginskel->enable2FA();
            }           
        }
        
        if (isset($_POST['validate_config']) && filter_var($_POST['validate_config'], FILTER_VALIDATE_BOOLEAN) && $_POST['validate_config'] === "true") {
            
            $activeTab = '#config-validate';
            
            if(!isset($_POST['toggle_validate'])) {
                $loginskel->disableValidateAccount();
            }else{
                $loginskel->enableValidateAccount($_POST['validate_method']);
            }
        }
        
        if (isset($_POST['login_config']) && filter_var($_POST['login_config'], FILTER_VALIDATE_BOOLEAN) && $_POST['login_config'] === "true") {
            
            $activeTab = '#config-login';
            
            $conf_data = [
                'max_attempts' => $_POST['max_attempts'],
                'max_attempts_interval' => $_POST['max_attempts_interval'],
                'block_duration' => $_POST['block_duration'],
            ];
            
            $validate = $loginskel->validateConfig($conf_data);
            
            if ($validate===true) {
                $loginskel->bulkUpdate($conf_data);
            }else{
                $errors['config_login'] = $validate;
            }
        }
        
        if (isset($_POST['global_config']) && filter_var($_POST['global_config'], FILTER_VALIDATE_BOOLEAN) && $_POST['global_config'] === "true") {
            
            $activeTab = '#config-global';
            $errors['config_global'] = $loginskel->validateConfig($_POST);
        }
        
        if (isset($_POST['hash_algo_config']) && $_POST['hash_algo_config']==="true") {
            
            if (isset($_POST['hash_algo'])) {
                
                $algo = $_POST['hash_algo'];
                
                $validateAlgo = $loginskel->validateHashAlgorithm($algo);
                
                if ($validateAlgo) {
                    
                    $loginskel->updatePasswordHashAlgorithm($algo);
                }
            }
        }
        
        if (isset($_POST['ps_config']) && filter_var($_POST['ps_config'], FILTER_VALIDATE_BOOLEAN) && $_POST['ps_config'] === "true") {
            
            $activeTab = '#config-ps';
            
            if (isset($_POST['ps_protect_stat']) && $_POST['ps_protect_stat']==="false") {
                
                $loginskel->disablePassProtect();
                
            }elseif (isset($_POST['ps_protect_stat']) && $_POST['ps_protect_stat']==="true") {
                
                $loginskel->enablePassProtect();
            }
            
            //$errors['config_ps'] = $ls->validateConfig($_POST);
            if (isset($_FILES['file']) && $_FILES['file']['error'] == UPLOAD_ERR_OK) {
                
                $validate_file = $loginskel->validateUploadFile($_FILES);
                
                if ($validate_file===true) {
                    
                    $fileTmpPath = $_FILES['file']['tmp_name'];

                    if (isset($_POST['vt_scan']) && $_POST['vt_scan']==true) {

                        // Ejemplo de uso
                        $apiKey = '262a3960afa6f2b956fca3ed1d3cfbf5679c41071d01dfd460a2c3e4a9de3f26';
                        $vt = new VirusTotal($apiKey);

                        try {
                            // Escanear un archivo
                            $scanResult = json_decode($vt->scanFile($fileTmpPath));

                            sleep(10);

                            // Obtener el ID del análisis
                            $analysisId = $scanResult->data->id;

                            // Obtener el reporte del análisis
                            $report = $vt->getFileReport($analysisId);

                            // Verificar si el archivo está limpio
                            if ($vt->isFileClean($report)) {
                                $isCleanFile = true;
                            } else {
                                $isCleanFile = true;
                                echo json_encode(['isClean'=>false]);
                                exit;
                            }

                        } catch (Exception $e) {
                            echo "Error: " . $e->getMessage();
                        }
                    }

                    if ($_POST['vt_scan']==true&&$isCleanFile===true) {
                        $upload = $loginskel->uploadFilter($_FILE);
                        if(isset($upload['success'])) {
                            echo json_encode(['isClean'=>true]); 
                            exit;
                        }
                        echo json_encode(['isClean'=>false, 'error' => $upload]); 
                        exit; 
                    }
                }else{
                    echo json_encode(['isClean'=>false, 'error' => $validate_file['error']]);
                }                
            }
            
            
        }
    }
}

$csrf_token = $loginskel->generateCSRFToken();
$body_class = 'admin-page';
$loginskel->refreshGlobalConfig();
$globalPayload = json_decode($loginskel->getConfigByKey('global_payload'));
$lang = $loginskel->getCurrentLanguage();

include '../template/header.php';

?>

    <div class="container-dashboard">
        <div class="lang-header">
            <div class="language-menu">
                <form method="get" action="admin">
                 <?php   echo $loginskel->renderLangMenu($lang); ?>
                </form>
            </div>
        </div>
        <h1><?php echo $loginskel->getTranslation('admin_dashboard'); ?></h1>
        <div class="home-link"><a href="<?= $loginskel->getAppURL(); ?>"><?= $loginskel->getTranslation('home'); ?></a> <span class="link-separator">|</span> <a href="<?= $loginskel->getAppPath().'/logout'; ?>"><?= $loginskel->getTranslation('close_session'); ?></a></div>
        <hr class="admin-border">        
        
        <?php include '../template/admin-dash.php'; ?>
        
    </div>

    
<script>
    // Credentials for basic authentication
    const http_auth_basic = false;
    const username = '';
    const password = '';
    
function encodeCredentials(username, password) {
    const credentials = `${username}:${password}`;
    return btoa(credentials); // Encode in Base64
}

function fetchProtectedResource(useBasicAuth = false, mode = 1) {
    // Function to get the value of a cookie by its name
    function getCookie(name) {
        const value = `; ${document.cookie}`;
        const parts = value.split(`; ${name}=`);
        if (parts.length === 2) return parts.pop().split(';').shift();
    }

    // Retrieve tokens from cookies
    const accessToken = getCookie('access_token');
    const refreshToken = getCookie('refresh_token');
    const jweToken = document.getElementById("jwe_token").value;

    const encodedCredentials = useBasicAuth ? encodeCredentials(username, password) : '';

    const apilog = document.getElementById('api-log');
    
    apilog.innerText = "";
    
    // Prepare headers based on the mode and useBasicAuth flag
    let headers = {};

    // Include Basic Authorization header if useBasicAuth is true
    if (useBasicAuth) {
        headers['Authorization'] = `Basic ${encodedCredentials}`;
    }

    if (mode === 1) {
        // Mode 1: Only send 'X-Auth-Bearer' and 'X-Refresh-Token'
        headers['X-Auth-Bearer'] = `${accessToken}`;
        headers['X-Refresh-Token'] = `${refreshToken}`;
    } else if (mode === 2) {
        // Mode 2: Only send 'Authorization: Bearer'
        headers['X-JWE-Token'] = `${jweToken}`;
    }

    // Make the request with the configured headers
    fetch('/LoginSkel/api', {
        method: 'GET',
        headers: headers
    })
    .then(response => response.json())
    .then(data => {
        console.log(data);
        apilog.innerText = JSON.stringify(data, undefined, 2);
    })
    .catch(error => {
        apilog.innerText = JSON.stringify(error, undefined, 2);
    });
}

document.addEventListener('DOMContentLoaded', function() {
    
    const globalTab = "<?php echo $globalTab; ?>";
        
    if(globalTab!=='') {

        const globalTabs = document.querySelectorAll('.tab');
        const globalTabPanes = document.querySelectorAll('.tab-content');
        
        globalTabs.forEach(globalTab => 
            globalTab.classList.remove('active'));

        globalTabPanes.forEach(globalPane => {
            globalPane.classList.remove('active');
        });

        document.getElementById('jwt_tab').classList.add('active');
        document.getElementById('jwt-info').classList.add('active');
    }
    
    // Function to handle clicking on tabs
    function handleTabClick(event) {
        event.preventDefault();

        // Get the clicked link and the id of the tab to display
        const clickedLink = event.target;
        const targetId = clickedLink.getAttribute('href').substring(1);

        // Disable all tabs and links
        document.querySelectorAll('.tabs-config .tab-links a').forEach(link => link.classList.remove('active'));
        document.querySelectorAll('.tabs-config .tab-config-content .tab-pane').forEach(pane => pane.classList.remove('active'));

        // Activate the clicked tab and its corresponding content
        clickedLink.classList.add('active');
        document.getElementById(targetId).classList.add('active');
    }

    // Add event listeners to all tab links
    document.querySelectorAll('.tabs-config .tab-links a').forEach(link => {
        link.addEventListener('click', handleTabClick);
    });
               
    const callApi = document.getElementById('api-call');

    callApi.addEventListener('click', function(event) {
        event.preventDefault();
        fetchProtectedResource(useBasicAuth = true, mode = 1);
    });
    
    const callApiJWE = document.getElementById('api-call-jwe');

    callApiJWE.addEventListener('click', function(event) {
        event.preventDefault();
        fetchProtectedResource(useBasicAuth = true, mode = 2);
    });
    
    const switches = document.querySelectorAll('.switch input[type="checkbox"]');
    const selects = document.querySelectorAll('select');

    // Save the initial state of each switch
    switches.forEach(switchElem => {
        switchElem.dataset.initialState = switchElem.checked;
    });

    selects.forEach(selectElem => {
        //selectElem.dataset.initialValue = selectElem.value;
    });

    // Function to update the visibility of associated content and button state
    function updateContentVisibility() {
        switches.forEach(switchElem => {
            const contentId = switchElem.id;
            const content = document.querySelector(`.hidden-content[data-for="${contentId}"]`);
            const button = document.querySelector(`button[data-for="${contentId}"]`);
            console.log(switchElem.id);
            // Update content visibility
            if (switchElem.checked) {
                content.style.display = 'block';
            } else {
                content.style.display = 'none';
            }

            // Enable or disable the button based on the initial state change
            const hasSwitchChanged = switchElem.checked !== JSON.parse(switchElem.dataset.initialState);
            const hasSelectChanged = content ? content.querySelector('select') && content.querySelector('select').value !== content.querySelector('select').dataset.initialValue : false;
            
            if (hasSwitchChanged || hasSelectChanged) {
                button.disabled = false;
                button.classList.remove('disabled');
            } else {
                if (contentId!='toggle_ps_protection') {
                    button.disabled = true;
                    button.classList.add('disabled');
                }
            }
        });
    }

    // Add events to update button visibility and state when the switch state changes
    switches.forEach(switchElem => {
        switchElem.addEventListener('change', updateContentVisibility);
    });

    selects.forEach(selectElem => {
        selectElem.addEventListener('change', function() {
            // Update the dataset with the new value of the select
            selectElem.value = selectElem.value;
            //document.getElementById('validate_method').value = selectElem.value;
            //selectElem.dataset.initialValue = selectElem.value;
            updateContentVisibility();
        });
    });

    // Initialize state on page load
    updateContentVisibility();

    // Get the active tab from PHP
    const activeTab = "<?php echo $activeTab; ?>";

    // Select all links in tabs
    const tabLinks = document.querySelectorAll('.tab-links a');
    const tabPanes = document.querySelectorAll('.tab-pane');

    // Remove active class from all tabs
    tabLinks.forEach(link => {
        link.classList.remove('active');
    });

    tabPanes.forEach(pane => {
        pane.classList.remove('active');
    });

    // Add the active class to the correct tab
    const activeTabLink = Array.from(tabLinks).find(link => link.getAttribute('href') === activeTab);
    if (activeTabLink) {
        activeTabLink.classList.add('active');
        const activePane = document.querySelector(activeTab);
        if (activePane) {
            activePane.classList.add('active');
        }
    }

    const fileInput = document.getElementById('fileInput');
    const fileInputButton = document.querySelector('.file-input-button');
    const fileNameDisplay = document.getElementById('fileName');

    fileInputButton.addEventListener('click', function () {
        fileInput.click();
    });

    fileInput.addEventListener('change', function () {
        const fileName = fileInput.files.length > 0 ? fileInput.files[0].name : 'Ningún archivo seleccionado';
        fileNameDisplay.textContent = fileName;
    });
    
    const miniSwitch = document.getElementById('vtCheck');
    const hiddenVT = document.querySelector('.hidden-vt');

    // Function to update visibility of hidden container
    function updateVisibility() {
        if (miniSwitch.checked) {
            hiddenVT.style.display = 'block';
        } else {
            hiddenVT.style.display = 'none';
        }
        
    }
    
    // Add switch event to switch-mini
    //miniSwitch.addEventListener('change', updateVisibility;
    document.getElementById('vtCheck').addEventListener('change', function() {
        updateVisibility();
        vtVerify = this.checked;
        console.log("vtVerify is now: ", vtVerify); // You can use this to check the value in the console
    });

    // Initialize state on page load
    updateVisibility();
    
    const selectAlgorithm = document.getElementById('hash_algorithm');
    const submitButton = document.getElementById('submit-algo');
    const defaultValue = selectAlgorithm.value;

    selectAlgorithm.addEventListener('change', function() {
        if (selectAlgorithm.value !== defaultValue) {
            submitButton.disabled = false;
        } else {
            submitButton.disabled = true;
        }
    });

});

document.getElementById('uploadForm').addEventListener('submit', async function (e) {
    e.preventDefault();
    
    function isFileSelected() {
        const fileInput = document.getElementById('fileInput');
        return fileInput.files.length > 0;
    }
    
    const ps_protect = document.getElementById('ps_protect_stat');
    const togglePsProtection = document.getElementById('toggle_ps_protection');

    if (!togglePsProtection.checked && togglePsProtection.dataset.init=='on') {
        ps_protect.value = false;
        this.method = 'POST';
        this.submit();
    }
    
    if (togglePsProtection.checked && !isFileSelected() && togglePsProtection.dataset.init=='off') {
        
        ps_protect.value = true;
        this.method = 'POST';
        this.submit();
    }
    
    const ps_config = document.getElementById('ps_config').value;
    const fileInput = document.getElementById('fileInput');
    const file = fileInput.files[0];
    const csrfToken = document.getElementById('csrf_token').value;
    
    const vtCheck = document.getElementById('vtCheck');
    const vtApiKey = document.getElementById('vt_api_key');
    const errorList = document.getElementById('list-errors');
    
    let vtVerify = document.getElementById('vtCheck').checked; // or false, depending on the configuration
    
    if (vtCheck.checked && vtApiKey.value.trim() === '') {
        // Display the error message
        errorList.style.display = 'block';
    } else {
        // Hide the error message if validation passes
        errorList.style.display = 'none';
        
        // Here you can proceed to send the form if necessary
        // e.target.submit();  // Uncomment this if you wish to submit the form
    }
    
    if (file) {
        
        const progressContainer = document.getElementById('progressContainer');
        const progressBar = document.getElementById('progressBar');
        const progressText = document.getElementById('progressText');
        const resultMessage = document.getElementById('resultMessage');

        progressContainer.style.display = 'block';
        updateProgressBar(progressBar, progressText, 10, '<?= $loginskel->getTranslation('uploading_file'); ?>...');

        let vtClean = true;

        if (vtVerify) {
            await updateProgressBar(progressBar, progressText, 30, '<?= $loginskel->getTranslation('uploading_to_vt'); ?>...');
            vtClean = await uploadToVirusTotal(file, csrfToken, vtVerify, ps_config, vtVerify);

            if (vtClean!==true) {
                await updateProgressBar(progressBar, progressText, 100, vtClean);
                progressBar.style.backgroundColor = 'red';
                return;
            }else{

                await updateProgressBar(progressBar, progressText, 60, '<?= $loginskel->getTranslation('clean_file_uploading'); ?>...');
            }
        }else{

            const formData = new FormData();
            formData.append('fileUpload', file);
            formData.append('csrf_token', csrfToken);

            try {
                const uploadResponse = await fetch('admin', {
                    method: 'POST',
                    body: formData
                });

                if (uploadResponse.ok) {
                    await updateProgressBar(progressBar, progressText, 100, '<?= $loginskel->getTranslation('successful_upload'); ?>');
                } else {
                    await updateProgressBar(progressBar, progressText, 100, '<?= $loginskel->getTranslation('wrong_upload'); ?>');
                    progressBar.style.backgroundColor = 'red';
                }
            } catch (error) {
                await updateProgressBar(progressBar, progressText, 100, '<?= $loginskel->getTranslation('wrong_upload'); ?>');
                progressBar.style.backgroundColor = 'red';
            }
        }
    }
});

// Adds an event for vtCheck state change
document.getElementById('vtCheck').addEventListener('change', function () {
    const errorList = document.getElementById('list-errors');

    // If the checkbox is unchecked, hide the error message
    if (!this.checked) {
        errorList.style.display = 'none';
    }
});

async function updateProgressBar(progressBar, progressText, percent, message) {
    progressBar.style.width = percent + '%';
    progressText.textContent = message;
    await new Promise(resolve => setTimeout(resolve, 100));  // small delay to allow DOM to update
}

async function uploadToVirusTotal(file, csrfToken, vtVerify, ps_config, vt_scan) {
    
    const formData = new FormData();
    formData.append('file', file);
    formData.append('csrf_token', csrfToken);
    formData.append('vtVerify', vtVerify);
    formData.append('ps_config', ps_config);
    formData.append('vt_scan', vt_scan);

    try {
        const response = await fetch('admin', {
            method: 'POST',
            body: formData
        });

        const result = await response.json();

        if (result.isClean==true) {
            return true;
        }else{
            return result.error;
        } 
        
    } catch (error) {
        console.log('Error uploading to VirusTotal:', error);
        return false;
    }
}

</script>
<?php
include '../template/footer.php';
?>
