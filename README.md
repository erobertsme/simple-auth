
## Simple JWT Auth
This is a very basic implementation of a simple JWT (JSON Web Token) authentication. When used it stores a JWT in a cookie. The stored auth token is encrypted using sha256 in the `generate_credentials_hash()` method which uses the `jwt_secret` encoded with base64 as the key.

This was made to use a single set of login credentials, but was designed so the `validate_credentials()` function can be changed to retrieve credentials using another method like from a database.

---

### Example Usage

```php
require_once  'auth.php';

$config = [
  'username'    =>  'admin',
  'password'    =>  'pass',
  'jwt_secret'  =>  'hunter2'
];

$auth =  new  Auth($config);

$auth->login('admin', 'pass')  // returns ['success']
$auth->login('wrong', 'login') // returns ['error' => 'invalid']
$auth->login('user', '')       // returns ['error' => 'incomplete']

$auth->is_logged_in(); // returns true if valid token stored in cookie

$auth->logout('/login.php'); // forces cookie expiration and redirects to argument or '/' if left empty

```

---
### Notes

`validate_credentials()` can be changed to use any method of retrieving login credentials for validation, but must use `generate_credentials_hash()` to validate and take one argument that is the result of using `generate_credentials_hash($username, $password)`. I would like to change this to use a `validation` function passed in the `$config` during instantiation.


`login()` and `logout()` must be called before any headers are sent.


Run `php -S 0.0.0.0:80 -t ./example/` to view example login pages.