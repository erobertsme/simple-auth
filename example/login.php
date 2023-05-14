<?php
$config = require_once '../config.example.php';
require_once '../auth.php';
$auth = new Auth($config);

if ( isset($_GET['logout']) ) {
  $auth->logout('/login.php');
}

if( $auth->is_logged_in() ) return header('Location: /example/');

// Handle POST and login attempt
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
  $login_result = $auth->login($_POST['username'], $_POST['password']);
  // If login error then redirect with error param
  if ( isset($login_result['error']) ) return header('Location: /login.php?error='.$login_result['error']);

  // Login successful
  header('Location: /example/');
  exit();
}

function error_alert() {
  if (empty($_GET['error'])) return;
  ob_start();

  ?>
  <div class="alert alert-danger alert-dismissible fade show w-100 position-fixed text-center align-items-center" role="alert">
    <strong>Error:</strong> Login <?php echo $_GET['error']; ?>
    <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
  </div>
  <?php

  echo ob_get_clean();
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Login</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-KK94CHFLLe+nY2dmCWGMq91rCGa5gtU4mk92HdvYe+M/SXH301p5ILy+dN9+nJOZ" crossorigin="anonymous">
</head>
<body>

  <?php error_alert(); ?>

  <div class="container d-flex justify-content-center align-items-center" style="height: 100vh">
    <div class="row d-flex text-center">

      <div class="mb-4">
        <h1>Login</h1>
      </div>

      <form method="POST" action="">
        <div class="mb-3">
        <label for="username" class="form-label">Username</label>
          <input type="text" name="username" required>
        </div>

        <div class="mb-3">
          <label for="password" class="form-label">Password</label>
          <input type="password" name="password" required>
        </div>
        <button type="submit" class="btn btn-primary">Login</button>
      </form>

    </div>
  </div>

  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha3/dist/js/bootstrap.bundle.min.js" integrity="sha384-ENjdO4Dr2bkBIFxQpeoTz1HIcje39Wm4jDKdf19U8gI4ddQ3GYNS7NTKfAdVQSZe" crossorigin="anonymous"></script>
</body>
</html>
