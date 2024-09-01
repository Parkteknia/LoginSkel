<?php
if (basename(__FILE__) === basename($_SERVER['SCRIPT_FILENAME'])) {
    http_response_code(403);
    exit;
}
?>
<script>
document.addEventListener('DOMContentLoaded', function() {
    // Añadir una clase al body cuando JavaScript esté habilitado
    document.body.classList.add('js-enabled');
});
</script>
</body>
</html>

