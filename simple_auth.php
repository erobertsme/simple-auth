<?php
/**
 * Simple_Auth is a PHP class that provides a simple and secure way to handle user authentication and authorization using JSON Web Tokens (JWTs).
 *
 * @package Simple_Auth
 */
class Simple_Auth {

  /**
   * The secret key used to sign and encrypt JWTs.
   *
   * @var string
   */
  private $secret;

  /**
   * Defines which method the token will be stored. Options: 'cookie' or 'session'
   *
   * @var string
   */
  private $expiration_hours;

  /**
   * A function that validates a user's credentials.
   *
   * @var callable
   */
  private $validate_user;

  /**
   * A function that retrieves a user's password.
   *
   * @var callable
   */
  private $get_password;

  /**
   * Creates a new instance of the Simple_Auth class.
   *
   * @param array $config An array of configuration options for the Simple_Auth class.
   *   - storage_method: Defines which method the token will be stored.
   *   - expiration: Defines how many hours the token will be valid.
   *   - validate_user: A function that validates a user's credentials.
   *   - get_password: A function that retrieves a user's password.
   */
  function __construct($config) {
    [
      'secret'           => $this->secret,
      'expiration_hours' => $this->expiration_hours,
      'validate_user'    => $this->validate_user,
      'get_password'     => $this->get_password
    ] = $config;
  }

  /**
   * Return a padding removed base64 string.
   *
   * @param string $string
   * @return string Base64 encoded string with the padding removed
   */
  private function get_trim_base64($string) {
    return rtrim( base64_encode($string), '=' );
  }

  /**
   * Encrypts password using the AES-256-CBC encryption algorithm and $this->secret.
   *
   * @param string $password
   * @return string AES-256-CBC encrypted password string
   */
  private function encrypt_password($password) {
    $key = hash('sha256', $this->secret, true);
    $initialization_vector = openssl_random_pseudo_bytes( openssl_cipher_iv_length('aes-256-cbc') );
    $encrypted = openssl_encrypt($password, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $initialization_vector);

    return $this->get_trim_base64($initialization_vector . $encrypted);
  }

  /**
   * Decrypts password using the AES-256-CBC encryption algorithm and the secret defined in the config on initialization.
   *
   * @param string $encrypted_password
   * @return string Unencrypted password
   */
  private function decrypt_password($encrypted_password) {
    $key = hash('sha256', $this->secret, true);
    $data = base64_decode($encrypted_password);
    $initialization_vector = substr( $data, 0, openssl_cipher_iv_length('aes-256-cbc') );
    $encrypted = substr( $data, openssl_cipher_iv_length('aes-256-cbc') );

    return openssl_decrypt($encrypted, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $initialization_vector);
  }

  /**
   * Validates the login using validate_user() defined in the config on initialization and password_verify()
   *
   * @param string $username
   * @param string $password_hash
   * @return bool Boolean result of validating the credentials
   */
  private function validate_credentials($username, $password_hash) {
    return ( $this->validate_user($username) && password_verify( $this->get_password($username), $password_hash) );
  }

    /**
   * Creates a JSON Web Token (JWT) based on the provided username, password hash, and expiration hours.
   *
   * @param string $username The username associated with the JWT.
   * @param string $password_hash The hashed password associated with the JWT.
   * @param int $expiration_hours The number of hours the JWT will remain valid. Default is 20 hours.
   *
   * @return string The generated JWT.
   */
  private function create_jwt($username, $password_hash, $expiration_hours = 20) {
    $header = [
      'alg' => 'HS256',
      'typ' => 'JWT'
    ];
    $header_encoded = $this->get_trim_base64( json_encode($header) );

    $payload = [
      'user' => $username,
      'auth' => $this->encrypt_password($password_hash),
      'exp' => time() + ($expiration_hours * 3600)
    ];
    $payload_encoded = $this->get_trim_base64( json_encode($payload) );

    $signature_encoded = $this->get_trim_base64( hash_hmac('sha256', $header_encoded . '.' . $payload_encoded, $this->secret, true) );

    $jwt = "{$header_encoded}.{$payload_encoded}.{$signature_encoded}";

    return $jwt;
  }

  /**
   * Validates a JWT token and returns the user's ID.
   *
   * @param string $token The JWT token to validate.
   * @return int|null The user's ID, or null if the token is invalid.
   */
  public function validate_token($token) {
    $parts = explode('.', $token);
    $header = base64_decode($parts[0]);
    $payload = base64_decode($parts[1]);

    $signature = base64_decode($parts[2]);
    $valid_signature = hash_hmac('sha256', $parts[0].'.'.$parts[1], $this->secret, true);
    if ($signature !== $valid_signature) return false;

    $header = json_decode($header, true);
    if (!isset($header['alg']) || $header['alg'] !== 'HS256' || !isset($header['typ']) || $header['typ'] !== 'JWT') return false;

    $data = json_decode($payload, true);

    if( !$this->validate_credentials( $data['user'], $this->decrypt_password($data['auth']) ) ) return false;

    if (isset( $data['exp']) && $data['exp'] < time( )) return false;

    return true;
  }

  /**
   * Logs in a user and returns a JWT token.
   *
   * @param string $username The user's username.
   * @param string $password The user's password.
   * @return array An array containing the JWT token and a success flag.
   */
  public function login($username, $password) {
    if ( empty($username) || empty($password) ) return ['error' => 'incomplete'];

    $password_hash = password_hash($password, PASSWORD_DEFAULT);

    if ( !$this->validate_credentials($username, $password_hash) ) return ['error' => 'invalid'];

    $jwt = $this->create_jwt($username, $password_hash, 20);

    return ['success' => $jwt];
  }
}
