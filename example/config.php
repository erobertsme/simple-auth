<?php
return [
  'jwt_secret' => 'hunter2',
  'validate_function' => function($login_hash, $instance, $secret) {
    $login = [ 
      'username' => 'admin',
      'password' => 'pass'
    ];
    $valid_credentials = $instance->generate_credentials_hash($login['username'], $login['password'], $secret);
    return $login_hash === $valid_credentials;
  }
];