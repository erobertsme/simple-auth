
## Simple JWT Auth
This is a very basic implementation of a simple JWT authentication.

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

```

---
### Notes

`validate_credentials()` can be changed to use any method of retrieving login credentials for validation, but must use `generate_credentials_hash()` to validate and take one argument that is the result of using `generate_credentials_hash($username, $password)`.


`login()` and `logout()` must be called before any headers are sent.


Run `php -S 0.0.0.0:80 -t ./example/` to view example login pages.