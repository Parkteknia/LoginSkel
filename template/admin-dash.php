        <script>
            function openTab(event, tabId) {
                const tabs = document.querySelectorAll('.tab');
                tabs.forEach(tab => tab.classList.remove('active'));

                const tabContents = document.querySelectorAll('.tab-content');
                tabContents.forEach(content => content.classList.remove('active'));

                event.currentTarget.classList.add('active');
                document.getElementById(tabId).classList.add('active');
            }

            function updateSelect(input) {
                
                const row = input.closest('tr');
                const select = row.querySelector('.select-payload-type');
                const key = input.value.trim();
                const validKeys = {
                    user_id: 'int',
                    username: 'text',
                    role: 'int',
                    email: 'email'
                };

                // Si la clave está en la lista de claves válidas
                if (validKeys.hasOwnProperty(key)) {
                    // Cambia el valor del select al tipo correspondiente
                    select.value = validKeys[key];
                    // Desactiva el select
                    select.disabled = true;
                    select.classList.add("select-disabled");
                } else {
                    // Habilita el select
                    select.disabled = false;
                    select.classList.remove("select-disabled");
                }
            }

            function addRow() {
                // Create a new row
                var tableBody = document.querySelector('#data-table tbody');
                var newRow = document.createElement('tr');

                newRow.innerHTML = `
                    <td><input type="text" class="input-tool" name="key[]" placeholder="Enter key" oninput="updateSelect(this)"></td>
                    <td>
                        <select  class="select-payload-type" name="type[]">
                            <option value="" disabled selected><?= $loginskel->getTranslation('select_type'); ?></option>
                            <option value="text">text</option>
                            <option value="int">int</option>
                            <option value="email">email</option>
                            <option value="double">double</option>
                        </select>
                    </td>
                    <td>
                        <button type="button" class="icon-button plus" onclick="addRow()"><i class="fas fa-plus"></i></button>
                        <button type="button" class="icon-button minus" onclick="removeRow(this)"><i class="fas fa-minus"></i></button>
                    </td>
                `;

                tableBody.appendChild(newRow);
            }

            function removeRow(button) {
                var row = button.closest('tr');
                row.remove();
            }
            
            function reloadQR() {
                // URL del archivo PHP que procesa el efecto
                const url = 'admin';
                const csrft = document.getElementById("csrf_token").value; 
                // Enviar el nombre del efecto al servidor usando fetch
                fetch(url, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ gen_qr: true, csrf_token: csrft})
                })
                .then(response => response.json())
                .then(data => {
                    // Si la respuesta del PHP es true
                    if (data.success) {
                        // Obtener la imagen y recargarla
                        const img = document.getElementById('qr_img');
                        // Añadir un timestamp a la URL para forzar la recarga de la imagen
                        img.src = img.src.split('?')[0] + '?' + new Date().getTime();
                    } else {
                        console.error('<?= $loginskel->getTranslation('error_loading_qr'); ?>');
                    }
                })
                .catch(error => {
                    console.error('Error en la solicitud:', error);
                });
            }
        </script>
        <div class="container-config">
            <div class="tabs">
                <div class="tab active" onclick="openTab(event, 'basic-conf')"><?= $loginskel->getTranslation('configuration'); ?></div>
                <div class="tab" onclick="openTab(event, 'users-info')"><?= $loginskel->getTranslation('users'); ?></div>
                <div class="tab" onclick="openTab(event, 'session-info')"><?= $loginskel->getTranslation('session'); ?></div>
                <div id="jwt_tab" class="tab" onclick="openTab(event, 'jwt-info')">JWT</div>
                <div class="tab" onclick="openTab(event, 'api-info')">API</div>
            </div>
            <div class="tab-content active" id="basic-conf">
                <!-- HTML para los tabs horizontales dentro del tab vertical -->
                <div class="tabs-config">
                    <ul class="tab-links">
                        <li><a href="#config-global" <?= (!isset($_POST)&&empty($_POST))?'active':''; ?>>Global</a></li>
                        <li><a href="#config-login">Login</a></li>
                        <li><a href="#config-validate"><?= $loginskel->getTranslation('validation'); ?></a></li>
                        <li><a href="#config-2fa"><?= $loginskel->getTranslation('two_factor'); ?></a></li>
                        <li><a href="#config-ps"><?= $loginskel->getTranslation('password'); ?></a></li>
                    </ul>
                    <div class="tab-config-content">
                        <div id="config-global" class="tab-pane <?= (!isset($_POST)&&empty($_POST))?'active':''; ?>">
                            <?php if (isset($errors['config_global'])): ?>
                                <ul class="list-errors">
                                    <?php foreach ($errors['config_global'] as $error): ?>
                                        <li class="error"><?php echo htmlspecialchars($error); ?></li>
                                    <?php endforeach; ?>
                                </ul>
                            <?php endif; ?>
                            <form method="post">
                                <table id="default-table" class="config_table">
                                    <tbody>
                                        <!-- Campos globales predefinidos -->
                                        <tr>
                                            <td><label for="timezone">Time zone</label></td>
                                            <td><input type="text" class="input-tool" id="timezone" name="timezone" value="<?= $loginskel->getGlobalConfig()['timezone']; ?>" /></td>
                                        </tr>
                                        <tr>
                                            <td><label for="app_url">App url</label></td>
                                            <td><input type="text" class="input-tool" id="app_url" name="app_url" value="<?= $loginskel->getGlobalConfig()['app_url']; ?>"/></td>
                                        </tr>
                                        <tr>
                                            <td><label for="app_url">App path</label></td>
                                            <td><input type="text" class="input-tool" id="app_path" name="app_path" value="<?= $loginskel->getGlobalConfig()['app_path']; ?>"/></td>
                                        </tr>
                                    </tbody>
                                </table>
                                
                                <button type="submit" ><?= $loginskel->getTranslation('save_global'); ?></button>
                                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                                <input type="hidden" name="global_config" value="true">
                            </form>
                        </div>
                        <div id="config-login" class="tab-pane">
                            <!-- Contenido para el tab "Login" -->
                            <h4><?= $loginskel->getTranslation('login_attempts'); ?></h4>
                            <?php if (isset($errors['config_login'])): ?>
                                <ul class="list-errors">
                                    <?php foreach ($errors['config_login'] as $error): ?>
                                        <li class="error"><?php echo htmlspecialchars($error); ?></li>
                                    <?php endforeach; ?>
                                </ul>
                            <?php endif; ?>
                            <form method="post">
                                <table id="default-table" class="config_table">
                                    <tbody>
                                        <!-- Campos globales predefinidos -->
                                        <tr>
                                            <td><label for="max_attempts"><?= $loginskel->getTranslation('max_attempts'); ?></label></td>
                                            <td><input type="text" class="input-tool" id="max_attempts" name="max_attempts" value="<?= $loginskel->getGlobalConfig()['max_attempts']; ?>" /></td>
                                        </tr>
                                    </tbody>
                                </table>
                                <p class="paragrah-install"><?= $loginskel->getTranslation('max_interval_info'); ?></p>
                                <table id="default-table" class="config_table">
                                    <tbody>
                                        <!-- Campos globales predefinidos -->
                                        <tr>
                                            <td><label for="max_attempts_interval"><?= $loginskel->getTranslation('max_interval'); ?></label></td>
                                            <td><input type="text" class="input-tool" id="max_attempts_interval" name="max_attempts_interval" value="<?= $loginskel->getGlobalConfig()['max_attempts_interval']; ?>" /></td>
                                        </tr>
                                    </tbody>
                                </table>
                                <table id="default-table" class="config_table">
                                    <tbody>
                                        <!-- Campos globales predefinidos -->
                                        <tr>
                                            <td><label for="block_duration"><?= $loginskel->getTranslation('block_duration'); ?></label></td>
                                            <td><input type="text" class="input-tool" id="block_duration" name="block_duration" value="<?= $loginskel->getGlobalConfig()['block_duration']; ?>" /></td>
                                        </tr>
                                    </tbody>
                                </table>
                                <button type="submit" ><?= $loginskel->getTranslation('save_login'); ?></button>
                                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                                <input type="hidden" name="login_config" value="true">
                            </form>
                        </div>
                        <div id="config-validate" class="tab-pane">
                            <!-- Contenido para el tab "Validate" -->
                            <h4><?= $loginskel->getTranslation('validate_account'); ?></h4>
                            <p class="paragrah-install"><?= $loginskel->getTranslation('validate_account_info'); ?></p>
                            <form method="post">
                                <table id="default-table" class="config_table">
                                    <tbody>
                                        <!-- Campos globales predefinidos -->
                                        <tr>
                                            <td>
                                                <div class="switch">
                                                    <input type="checkbox" name="toggle_validate" data-for="btn_conf_validate" id="toggle_validate" <?=($loginskel->getGlobalConfig()['validate_account']) ? "checked": ""; ?>/>
                                                    <label for="toggle_validate"></label>
                                                </div>
                                            </td>
                                            <td>
                                                <div class="hidden-content hidden-validate" data-for="toggle_validate">
                                                    <select name="validate_method" data-for="btn_conf_validate" id="validate_method">
                                                        <option value="token"<?=($loginskel->getGlobalConfig()['validate_method']==='token') ? " selected='selected'": ""; ?>>Token</option>
                                                        <option value="code"<?=($loginskel->getGlobalConfig()['validate_method']==='code') ? " selected='selected'": ""; ?>><?= $loginskel->getTranslation('code'); ?></option>
                                                    </select>
                                                    <label><?= $loginskel->getTranslation('validate_method'); ?></label>
                                                </div>
                                            </td>
                                        </tr>
                                    </tbody>
                                </table>
                                <button id="btn_conf_validate" type="submit" data-for="toggle_validate"><?= $loginskel->getTranslation('save_validate'); ?></button>
                                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                                <input type="hidden" name="validate_config" value="true">
                            </form>
                        </div>
                        <div id="config-2fa" class="tab-pane">
                            <h4><?= $loginskel->getTranslation('2fa_auth'); ?></h4>
                            <p class="paragrah-install"><?= $loginskel->getTranslation('2fa_auth_info'); ?></p>
                            <form method="post">
                                <table id="default-table" class="config_table">
                                    <tbody>
                                        <!-- Campos globales predefinidos -->
                                        <tr>
                                            <td><label for="toggle_2fa">2FA</label></td>
                                            <td>
                                                <div class="switch">
                                                    <input type="checkbox" name="toggle_2fa" data-for="btn_conf_validate" id="toggle_2fa"<?=($loginskel->getGlobalConfig()['2fa_auth']) ? " checked": ""; ?>/>
                                                    <label for="toggle_2fa"></label>
                                                </div>
                                            </td>
                                        </tr>
                                    </tbody>
                                </table>
                                <div class="hidden-content" data-for="toggle_2fa">


                                <?php if (!$loginskel->get2Factor()) { ?>

                                    <p class="info"><?= $loginskel->getTranslation('save_2fa_info'); ?></p>

                                <?php }else{ $qrCodeUrl = '/LoginSkel/lib/serveQRImage.php?image=' . urlencode($user['username'].".png");?>
                                    <div class="qr_container">   
                                        <img src="<?php echo $qrCodeUrl; ?>" class="qr_image" alt="QR Code">
                                    </div>
                                    <button class="link-button" onclick="reloadQR()"><?= $loginskel->getTranslation('regenerate_qr'); ?></button>
                                <?php } ?>
                                </div>    
                                <button type="submit" data-for="toggle_2fa" id="btn_conf_2fa"><?= $loginskel->getTranslation('save_2fa'); ?></button>
                                <input type="hidden" name="2fa_config" value="true">
                                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                            </form>
                        </div>
                        <div id="config-ps" class="tab-pane">
                            <h4><?= $loginskel->getTranslation('hashing_password_algorithm'); ?></h4>
                            <form method="post">
                                <table id="default-table" class="config_table">
                                    <tbody>
                                        <!-- Campos globales predefinidos -->
                                        <tr>
                                            <td>
                                                <div class="hidden-content hidden-validate" style="display: block;">
                                                    <select name="hash_algo" id="hash_algorithm">
                                                        <option value="bcrypt"<?=($loginskel->getGlobalConfig()['hash_algo']==='bcrypt') ? ' selected="selected"': ""; ?>>Bcrypt</option>
                                                        <option value="argon2"<?=($loginskel->getGlobalConfig()['hash_algo']==='argon2') ? ' selected="selected"': ""; ?>>Argon2</option>
                                                    </select>
                                                    <label><?= $loginskel->getTranslation('hash_algorithm'); ?></label>

                                                </div>
                                            </td>
                                            <td><button type="submit" id="submit-algo" class="mini-button align-right" disabled><?= $loginskel->getTranslation('save'); ?></button></td>
                                        </tr>
                                    </tbody>
                                </table>
                                <input type="hidden" id="hash_algo_config" name="hash_algo_config" value="true">
                                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                            </form>
                            <h4><?= $loginskel->getTranslation('bad_password_protection'); ?></h4>
                            <p></p>
                            <form id="uploadForm" enctype="multipart/form-data">
                                <table id="default-table" class="config_table">
                                    <tbody>
                                        <!-- Campos globales predefinidos -->
                                        <tr>
                                            <td><label for="toggle_ps_protection">Password protection</label></td>
                                            <td>
                                                <div class="switch">
                                                    <input type="checkbox" name="toggle_ps_protection" data-init="<?=($loginskel->getGlobalConfig()['ps_protect']==='true') ? "on": "off"; ?>" data-for="btn_conf_validate" id="toggle_ps_protection"<?=($loginskel->getGlobalConfig()['ps_protect']==='true') ? " checked": ""; ?>/>
                                                    <label for="toggle_ps_protection"></label>
                                                </div>
                                            </td>
                                        </tr>
                                    </tbody>
                                </table>
                                <div class="hidden-content" data-for="toggle_ps_protection">
                                    <h4><?= $loginskel->getTranslation('available_filters'); ?></h4>
                                    <table>
                                    <?php foreach($filters AS $filter){ ?>
                                        <tr>
                                            <td><?= $filter['filter_file'];?></td>
                                            <td style="text-align:center;">
                                                <div class="switch-mini">
                                                    <input type="checkbox" id="filter-<?= $filter['filter_file']; ?>"<?=($filter['enabled']==='on')?' checked':''; ?>>
                                                    <label for="filter-<?= $filter['filter_file']; ?>"></label>
                                                </div>
                                            </td>
                                        </tr>
                                    <?php } ?>
                                    </table>
                                    <h4><?= $loginskel->getTranslation('upload_filters'); ?></h4>
                                    <div class="switch-vt-container ">
                                        <div class="switch-mini">
                                            <input type="checkbox" name="vtCheck" id="vtCheck">
                                            <label for="vtCheck"></label>
                                        </div>
                                        <label for="vtCheck" class="switch-text">Enable VirusTotal check</label>
                                    </div>
                                    <ul class="list-errors" id="list-errors" style="display:none;">
                                        <li class="error"><?= $loginskel->getTranslation('no_vt_apikey'); ?></li>
                                    </ul>
                                    <div class="hidden-vt" style="display: none;">
                                        <input class="input-vt-key" name="vt_api_key" id="vt_api_key" placeholder="Enter API Key">
                                    </div>
                                    <div class="upload-form-container">
                                        
                                        <div class="form-group">
                                            <label for="fileUpload" class="form-label">Seleccionar archivo (.txt)</label>
                                            <div class="file-input-wrapper">
                                                <input type="file" id="fileInput" name="fileInput" class="form-input-file" accept=".txt">
                                                <button type="button" class="file-input-button">Examinar...</button>
                                                <span id="fileName" class="file-name"></span>
                                            </div>
                                        </div>
                                        
                                        <input type="hidden" id="ps_config" name="ps_config" value="true">
                                        <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                                    </div>
                                    <div id="progressContainer" style="display: none;">
                                        <p id="progressText">Iniciando...</p>
                                        <div style="border: 1px solid #ddd; width: 100%; margin: 10px 0;">
                                            <div id="progressBar" style="width: 0%; height: 20px; background-color: #4caf50;"></div>
                                        </div>
                                    </div>

                                    <p id="resultMessage"></p>
                                </div>
                                <button type="submit" data-for="toggle_ps_protection" id="btn_conf_ps"><?= $loginskel->getTranslation('save_2fa'); ?></button>
                                <input type="hidden" name="ps_config" value="true">
                                <input type="hidden" id="ps_protect_stat" name="ps_protect_stat" value="<?=($loginskel->getGlobalConfig()['ps_protect']) ? " true": "false"; ?>">
                                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                            </form>
                        </div>
                    </div>
                </div>
            </div>
            <div class="tab-content" id="users-info">
                <div>
                    <table class="users-table">
                        <thead>
                            <tr>
                                <th>User</th>
                                <th>Email</th>
                                <th>Role</th>
                                <th>Last Online</th>
                                <th>Online</th>
                            </tr>
                        </thead>
                        <tbody>
                        <?php foreach ((array) $loginskel->getUsers() as $user) { ?>
                            <tr>
                                <td><?= htmlspecialchars($user['username']); ?></td>
                                <td><?= htmlspecialchars($user['email']); ?></td>
                                <td><?= htmlspecialchars($user['role_name']); ?></td>
                                <td><?= htmlspecialchars($user['last_activity']); ?></td>
                                <td><?= htmlspecialchars($user['session_status']); ?></td>
                            </tr>
                        <?php } ?>
                        </tbody>
                        </table>
                </div>
            </div>
            <div class="tab-content" id="session-info">
                <div class="api-log"><pre><?= print_r($_SESSION); ?></pre></div>
            </div>

            <div class="tab-content" id="jwt-info">
                <?php if (isset($errors['global_payload'])): ?>
                    <ul class="list-errors">
                        <?php foreach ($errors['global_payload'] as $error): ?>
                            <li class="error"><?php echo htmlspecialchars($error); ?></li>
                        <?php endforeach; ?>
                    </ul>
                <?php endif; ?>
                <?php if (isset($savePayloadData)&&$savePayloadData===true): ?>
                <p class="info"><?= $loginskel->getTranslation('saved_payload_success'); ?></p>
                <?php endif; ?>
                <?php
                if (!$loginskel->JWTisActive()) { ?>
                <h4><?= $loginskel->getTranslation('jwt_enable'); ?></h4>
                <p class="paragrah-install"><?= $loginskel->getTranslation('jwt_enabled_info'); ?></p>
                <form method="post" action="">
                    <table id="default-table" class="install_table">
                        <tbody>
                            <!-- Campos globales predefinidos -->
                            <tr>
                                <td><label for="toggle_jwt">JWT</label></td>
                                <td>
                                    <div class="switch">
                                        <input type="checkbox" name="toggle_jwt" id="toggle_jwt"<?=(null!==$loginskel->JWTisActive()&&$loginskel->JWTisActive()) ? " checked": ""; ?>/>
                                        <label for="toggle_jwt"></label>
                                    </div>
                                </td>
                            </tr>
                        </tbody>
                    </table>
                    <div class="hidden-content hidden-validate" data-for="toggle_jwt"></div>
                    <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                    <input type="hidden" name="jwt_active" value="true">
                    <button type="submit" data-for="toggle_jwt" id="btn_conf_jwt"><?= $loginskel->getTranslation('jwt_enable_button'); ?></button>
                </form>
                <?php }
                if ($loginskel->JWTisActive()) {
                    
                    $jwtConfig = $loginskel->configJWT();
                
                    $conf = true;
                    
                    echo '<h2>' . $loginskel->getTranslation('jwt_config') . '</h2>';
                    
                    foreach ($jwtConfig AS $config_option) {
                        
                        if(!$config_option){
                            $conf = false;
                        }
                    }
                    
                    if(!isset($jwtConfig['global_payload']) || !$jwtConfig['global_payload']) { ?>
                
                        <p class="error"><?= $loginskel->getTranslation('gp_not_configured'); ?></p>
                    
                    <?php }
                    
                    if($conf===true) {  ?>
                        
                        <p class='success align-center'><?= $loginskel->getTranslation('jwt_configured'); ?>.</p>          
                    <?php } ?>
                        
                        <p class="align-left"><a href="#" id="toggle-conf"><?= $loginskel->getTranslation('show_config'); ?></a></p>
                        <div id="config-div" style="display: none;">
                            <p class="align-left"><?= $loginskel->getTranslation('exp_info'); ?>:</p>
                            <ul class="align-left">
                                <li>[num]min (<?= $loginskel->getTranslation('exp_info_min'); ?>))</li>
                                <li>[num]h (<?= $loginskel->getTranslation('exp_info_hour'); ?>))</li>
                                <li>[num]w (<?= $loginskel->getTranslation('exp_info_week'); ?>))</li>
                                <li>[num]y (<?= $loginskel->getTranslation('exp_info_year'); ?>))</li>
                                <li>inf (<?= $loginskel->getTranslation('exp_info_infinite'); ?>)</li>
                            </ul>
                            <form id="dynamic-form" method="post" action="admin">
                                <input type="hidden" id="csrf_token" name="csrf_token" value="<?php echo $csrf_token; ?>">
                                <input type="hidden" name="save_global_payload" value="true">
                                <table id="default-table">
                                    <thead>
                                        <tr>
                                            <th>Claim</th>
                                            <th><?= $loginskel->getTranslation('value'); ?></th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <!-- Campos globales predefinidos -->
                                        <tr>
                                            <td><label for="iss">iss (<?= $loginskel->getTranslation('issuer'); ?>)</label></td>
                                            <td><input type="text" class="input-tool" id="iss" name="iss" placeholder="Issuer" value="<?= (isset($jwtConfig['payload']->iss)&&!empty($jwtConfig['payload']->iss)) ? $jwtConfig['payload']->iss: ''; ?>" /></td>
                                        </tr>
                                        <tr>
                                            <td><label for="sub">sub (<?= $loginskel->getTranslation('subject'); ?>)</label></td>
                                            <td><input type="text" class="input-tool" id="sub" name="sub" placeholder="Subject" value="<?= (isset($jwtConfig['payload']->sub)&&!empty($jwtConfig['payload']->sub)) ? $jwtConfig['payload']->sub: ''; ?>" /></td>
                                        </tr>
                                        <tr>
                                            <td><label for="aud">aud ()</label></td>
                                            <td><input type="text" class="input-tool" id="aud" name="aud" placeholder="Audience" value="<?= (isset($jwtConfig['payload']->aud)&&!empty($jwtConfig['payload']->aud)) ? $jwtConfig['payload']->aud: ''; ?>" /></td>
                                        </tr>
                                        <tr>
                                            <td><label for="exp">exp (<?= $loginskel->getTranslation('expiration_time'); ?>)</label></td>
                                            <td><input type="text" class="input-tool" id="exp" name="exp" placeholder="Expiration time" value="<?= (isset($jwtConfig['payload']->exp)&&!empty($jwtConfig['payload']->exp)) ? $jwtConfig['payload']->exp: ''; ?>" /></td>
                                        </tr>
                                        <tr>
                                            <td><label for="nbf">nbf (<?= $loginskel->getTranslation('not_before'); ?>)</label></td>
                                            <td><input type="datetime-local" class="input-tool" id="nbf" name="nbf" placeholder="Not before" value="<?= (isset($jwtConfig['payload']->nbf)&&!empty($jwtConfig['payload']->nbf)) ? $jwtConfig['payload']->nbf: ''; ?>" /></td>
                                        </tr>
                                        <tr>
                                            <td><label for="jti">jti (JWT ID)</label></td>
                                            <td>
                                                <input type="checkbox" id="jti" name="jti" value="true" <?= (isset($jwtConfig['payload']->jti)&&$jwtConfig['payload']->jti==="true") ? 'checked': ''; ?> >
                                                <label for="checkbox"><?= $loginskel->getTranslation('enable_jti'); ?></label>
                                            </td>
                                        </tr>
                                    </tbody>
                                </table>
                                <p class="align-left"><?= $loginskel->getTranslation('custom_jwt_keys_info'); ?>.</p>    
                                <table id="data-table">
                                    <thead>
                                        <tr>
                                            <th><?= $loginskel->getTranslation('key'); ?></th>
                                            <th><?= $loginskel->getTranslation('type'); ?></th>
                                            <th><?= $loginskel->getTranslation('actions'); ?></th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php if (isset($jwtConfig['payload']->key) && !empty($jwtConfig['payload']->key) ) { 
                                            
                                        foreach($jwtConfig['payload']->key AS $key => $value) { ?>
                                            <!-- Campos globales predefinidos -->
                                            <tr>
                                                <td><input type="text" class="input-tool" name="key[]" placeholder="Enter key" oninput="updateSelect(this)" value="<?= $key; ?>" ></td>
                                                <td>
                                                    <select class="select-payload-type" name="type[]" required>
                                                        <option value="" disabled selected>Select type</option>
                                                        <option value="text"<?=($value==='text')?' selected':'';?>>text</option>
                                                        <option value="int"<?=($value==='int')?' selected':'';?>>int</option>
                                                        <option value="email"<?=($value==='email')?' selected':'';?>>email</option>
                                                        <option value="double"<?=($value==='double')?' selected':'';?>>double</option>
                                                    </select>
                                                </td>
                                                <td>
                                                    <button type="button" class="icon-button plus" onclick="addRow()"><i class="fas fa-plus"></i></button>
                                                </td>
                                            </tr>
                                        <?php } }else{ ?>
                                            <tr>
                                                <td><input type="text" class="input-tool" name="key[]" placeholder="Enter key" oninput="updateSelect(this)"></td>
                                                <td>
                                                    <select class="select-payload-type" name="type[]" required>
                                                        <option value="" disabled selected><?= $loginskel->getTranslation('select_type'); ?></option>
                                                        <option value="text">text</option>
                                                        <option value="int">int</option>
                                                        <option value="email">email</option>
                                                        <option value="double">double</option>
                                                    </select>
                                                </td>
                                                <td>
                                                    <button type="button" class="icon-button plus" onclick="addRow()"><i class="fas fa-plus"></i></button>
                                                </td>
                                            </tr>
                                        <?php } ?>
                                    </tbody>
                                </table>
                                <button type="submit" class="button-tool"><?= $loginskel->getTranslation('save_jwt_payload'); ?></button>
                            </form>
                          <?php   echo "<pre class='align-left'>"; print_r($jwtConfig); echo "</pre>"; ?>
                        </div>
                    <?php 
                    
                    if(isset($jwtConfig['encrypted'])) {
                        
                        if($jwtConfig['encrypt_key']==='error') { ?>
                
                            <p class="error"><?= $loginskel->getTranslation('no_encrypt_key'); ?></p>
                            
                    <?php  
                    
                        }
                        
                        echo "<h2>RSA Keys</h2>";
                        
                        if ($jwtConfig['enabled'] && isset($jwtConfig['error'])) { ?>
                            
                            <p class="error"><?= $loginskel->getTranslation('no_rsa_keys_found'); ?></p>
                            
                    <?php }elseif ($jwtConfig['enabled'] && $jwtConfig['keys']) { ?>
                            
                            <p class="success"><?= $loginskel->getTranslation('rsa_keys_found'); ?></p>
                            
                    <?php } ?> 
                            
                            <form method="post" action="">
                                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                                <input type="hidden" name="gen_keys" value="true">
                                <button type="submit" class="button-secondary button-small"><?= ($jwtConfig['keys']) ? $loginskel->getTranslation('regenerate_keys'): $loginskel->getTranslation('generate_keys'); ?></button>
                            </form>
                    <?php   } 
                }
                
                  // Generar y guardar las claves
            $privateKeyPath = 'private.key'; // Cambia esto a la ruta deseada
            $publicKeyPath = 'public.key';   // Cambia esto a la ruta deseada
            $encryptionKey = 'ZHnIVyDn6+lxLzQSjB8Jah08RIvSf3THIBEtoJW/Lec=';
            //generateRSAKeys($privateKeyPath, $publicKeyPath);
            
            // Uso de la clase
            //$privateKeyPath = '/path/to/private.key'; // Cambia esto a la ruta de tu clave privada
            //$publicKeyPath = '/path/to/public.key';   // Cambia esto a la ruta de tu clave pública
            
            
            ?>
            </div>
            <div class="tab-content" id="api-info">
                <div class="api-log"><pre id="api-log"></pre></div>
                <button type="button" class="button-api-small" id="api-call"><?= $loginskel->getTranslation('api_call'); ?></button>
                <?php if($loginskel->JWEisEnabled()) {  ?>
                <input type="hidden" id="jwe_token" value="<?= $loginskel->getJWE(); ?>">
                <button type="button" class="button-api-small" id="api-call-jwe"><?= $loginskel->getTranslation('api_call_jwe'); ?></button>
                <?php } ?>
            </div>
        </div>
        <script>
            
            document.getElementById('dynamic-form').addEventListener('submit', function(event) {
                // Habilitar todos los selects antes de enviar el formulario
                enableAllSelects();
            });

            function enableAllSelects() {
                // Seleccionar todos los selects que están deshabilitados
                const disabledSelects = document.querySelectorAll('select[disabled]');
                disabledSelects.forEach(select => {
                    // Habilitar cada select antes de enviar el formulario
                    select.disabled = false;
                });
            }

                const toggleLink = document.getElementById('toggle-conf');
                const configDiv = document.getElementById('config-div');

                toggleLink.addEventListener('click', function(event) {
                    event.preventDefault(); // Evita el comportamiento por defecto del enlace

                    if (configDiv.style.display === 'none') {
                        // Mostrar el div y cambiar el texto del enlace
                        configDiv.style.display = 'block';
                        toggleLink.textContent = 'Ocultar configuración';
                    } else {
                        // Ocultar el div y cambiar el texto del enlace
                        configDiv.style.display = 'none';
                        toggleLink.textContent = 'Mostrar configuración';
                    }
                });
                
                
        </script>
