<?php
$config = require_once 'config.php';
require_once '../simple_auth.php';
$auth = new Simple_Auth($config);

return $auth;