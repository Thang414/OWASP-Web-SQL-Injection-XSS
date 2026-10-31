<?php
session_start();
session_destroy();
setcookie("session_token", "", [
    'expires'  => time() - 3600,
    'path'     => '/',
    'httponly' => true,
    'samesite' => 'Lax'
]);
header("Location: index.php");
exit();
?>
