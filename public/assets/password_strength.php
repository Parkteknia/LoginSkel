<script>

    function checkPasswordStrength() {
        const password = document.getElementById('<?= $ps_field; ?>').value;
        const strengthIndicator = document.getElementById('password-strength');
        let strength = 0;

        if (password.length >= 8) strength += 1;
        if (/[A-Z]/.test(password)) strength += 1;
        if (/[a-z]/.test(password)) strength += 1;
        if (/[0-9]/.test(password)) strength += 1;
        if (/[\W]/.test(password)) strength += 1;

        switch (strength) {
            case 1:
            case 2:
                strengthIndicator.textContent = '<?= $loginskel->getTranslation('pass_very_weak'); ?>';
                strengthIndicator.style.color = '#d95757';
                break;
            case 3:
                strengthIndicator.textContent = '<?= $loginskel->getTranslation('pass_weak'); ?>';
                strengthIndicator.style.color = 'orange';
                break;
            case 4:
                strengthIndicator.textContent = '<?= $loginskel->getTranslation('pass_good'); ?>';
                strengthIndicator.style.color = '#e3c315';
                break;
            case 5:
                strengthIndicator.textContent = '<?= $loginskel->getTranslation('pass_strong'); ?>';
                strengthIndicator.style.color = 'green';
                break;
            default:
                strengthIndicator.textContent = '';
        }
    }

</script>

