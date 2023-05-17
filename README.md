# Simple Auth

Simple Auth is a single file class that provides a simple and secure way to handle user authentication and authorization using JSON Web Tokens (JWTs). It is designed to be easy to use and integrate into any PHP application. Simple Auth does not handle account creation, password management, token storage/management, or .

## Installation

To use Simple Auth, simply include the Simple_Auth.php file in your PHP project:

```php
require_once 'path/to/Simple_Auth.php';
```

## Usage

To use the Simple_Auth class, create a new instance of the class with a configuration array:

```php
$config = [
  'secret' => 'your_secret_key',
  'expiration_hours' => 24, // Default 20
  'validate_user' => function($username) {
    // validate user function
  },
  'get_password' => function($username) {
    // get password function
  }
];

$auth = new Simple_Auth($config);
```

### Login
To log in a user, call the login method with the user's username and password:
```php
$result = $auth->login($username, $password);

if ($result['success']) {
  // User is logged in
} else {
  // Login failed
}

$auth->login('correct', 'login'); // returns ['success' => {token}]

$auth->login('wrong', 'login'); // returns ['error' => 'invalid']

$auth->login('user', ''); // returns ['error' => 'incomplete']
```

---

### Security
Simple Auth uses JWTs to securely authenticate and authorize users. JWTs are signed and encrypted using a secret key, which is only known to the server. This ensures that the JWT cannot be tampered with or forged by an attacker.

Simple Auth also uses strong encryption algorithms (AES-256-CBC) to encrypt user authentication data, which adds an extra layer of security to the authentication process.

### Contributing
Contributions to Simple Auth are welcome! If you find a bug or have a feature request, please open an issue on the GitHub repository. If you would like to contribute code, please fork the repository and submit a pull request.