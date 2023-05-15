<?php
return [
  'jwt_secret' => 'hunter2',
  'validate_function' => function($login_hash, $instance) {
    $login = [ 
      'username' => 'admin',
      'password' => 'pass'
    ];
    $stored_credentials = $instance->generate_credentials_hash($login['username'], $login['password']);
    return $login_hash === $stored_credentials;
  }
];