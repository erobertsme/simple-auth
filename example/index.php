<?php
$config = require_once '../config.example.php';
require_once '../auth.php';
$auth = new Auth($config);

if ( !$auth->is_logged_in() ) return header('Location: /login.php');

?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Secure Page</title>
</head>
<body style="text-align: center;">
  <h1>Success!</h1>
  <a href="/login.php?logout">Logout</a>
</body>
</html>