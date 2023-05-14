<?php

class Auth {
  private $config;

  public function __construct($config) {
    $this->config = $config;
  }

  public function validate_credentials($username, $password) {
    // This can be changed to use any method of retrieving login credentials for validation
    if ($username === $this->config['username'] && $password === $this->config['password']) return true;

    return false;
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
    if( !$this->validate_credentials($data['username'], $data['password']) ) return false;

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
      'username' => $username,
      'password' => $password,
      'exp' => time() + ($expiration_hours * 3600)
    ];
    $payload_encoded = base64_encode( json_encode($payload) );

    // Create JWT signature
    $signature = hash_hmac('sha256', $header_encoded . '.' . $payload_encoded, $this->config['jwt_secret'], true);
    $signature_encoded = base64_encode($signature);

    // Create JWT by concatenating header, payload, and signature with periods
    $jwt = "{$header_encoded}.{$payload_encoded}.{$signature_encoded}";

    return $jwt;
  }

  public function is_logged_in() {
    // Check for jwt in cookie
    if ( !isset($_COOKIE['jwt']) ) return false;
    // Validate JWT. Can't just let anyone with any "jwt" cookie in, can we?
    if ( !$this->validate_jwt($_COOKIE['jwt']) ) return $this->logout();

    return true;
  }

  public function login($username, $password) {
    if ( empty($username) || empty($password) ) return ['error' => 'incomplete'];

    if ( !$this->validate_credentials($username, $password) ) return ['error' => 'invalid'];

    // Successful login
    if ( $this->validate_credentials($username, $password) ) { // Redundant, but why not?
      // Credentials are valid, create JWT token
      $expiration_time = time() + (20 * 3600); // 20 hours from now
      $jwt = $this->create_jwt($username, $password, 20);
      setcookie('jwt', $jwt, $expiration_time, '/');

      return ['success'];
    }
  }

  public function logout($redirect = '/') {
    setcookie('jwt', '', time() - 3600, '/');
    return header('Location: '.$redirect);
  }
}
