<?php

class Auth {
  private $config;

  public function __construct($config) {
    $this->config = $config;
  }

  private function generate_credentials_hash($username, $password) {
    return base64_encode( hash_hmac('sha256', $username.'|'.$password, $this->config['jwt_secret'], true) );
  }

  public function validate_credentials($login_hash) {
    // This can be changed to use any method of retrieving login credentials for validation 
    $stored_credentials = $this->generate_credentials_hash($this->config['username'],$this->config['password']);

    return $login_hash === $stored_credentials;
  }

  public function validate_jwt($jwt) {
    // Verify signature and decode JWT payload
    $parts = explode('.', $jwt);
    $header = base64_decode($parts[0]);
    $payload = base64_decode($parts[1]);

    // Validate signature
    $signature = base64_decode($parts[2]);
    $valid_signature = hash_hmac('sha256', $parts[0] . '.' . $parts[1], $this->config['jwt_secret'], true);
    if ($signature !== $valid_signature) return false;

    // Verify algorithm and type
    $header = json_decode($header, true);
    if (!isset($header['alg']) || $header['alg'] !== 'HS256' || !isset($header['typ']) || $header['typ'] !== 'JWT') return false;

    $data = json_decode($payload, true);

    // Validate JWT data against stored credentials
    if( !$this->validate_credentials($data->user) ) return false;

    // Check for JWT expiration
    if (isset($data['exp']) && $data['exp'] < time()) return false;

    return true;
  }

  public function create_jwt($username, $password, $expiration_hours) {
    // Create JWT header
    $header = [
      'alg' => 'HS256',
      'typ' => 'JWT'
    ];
    $header_encoded = base64_encode( json_encode($header) );

    // Create JWT payload with user data and expiration time
    $payload = [
      'user' => base64_encode( hash_hmac('sha256', "{$username}|{$password}",$this->config['jwt_secret'], true) ),
      'exp' => time() + ($expiration_hours * 3600)
    ];
    $payload_encoded = base64_encode( json_encode($payload) );

    // Create JWT signature
    $signature = base64_encode( hash_hmac('sha256', "{$header_encoded}.{$payload_encoded}", $this->config['jwt_secret'], true) );
    $signature_encoded = base64_encode($signature);

    // Create JWT by concatenating header, payload, and signature with periods
    $jwt = "{$header_encoded}.{$payload_encoded}.{$signature_encoded}";

    return $jwt;
  }

  public function is_logged_in() {
    // Check for jwt in cookie
    if ( !isset($_COOKIE['jwt']) ) return false;
    // Validate JWT. Can't just let anyone with any "jwt" cookie in, can we?
    if ( !$this->validate_jwt($_COOKIE['jwt']) ) return false;

    return true;
  }

  public function login($username, $password) {
    if ( empty($username) || empty($password) ) return ['error' => 'incomplete'];

    $login_hash = $this->generate_credentials_hash($username, $password);

    if ( !$this->validate_credentials($login_hash) ) return ['error' => 'invalid'];

    // Successful login
    if ( $this->validate_credentials($login_hash) ) { // Redundant, but why not?
      // Credentials are valid, create JWT token
      $expiration_time = time() + (20 * 3600); // 20 hours from now
      $jwt = $this->create_jwt($username, $password, 20);
      setcookie('token', $jwt, $expiration_time, '/');

      return ['success'];
    }
  }

  public function logout($redirect = '/') {
    setcookie('token', '', time() - 3600, '/');
    return header('Location: '.$redirect);
  }
}
