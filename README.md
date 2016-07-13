# nginx_php_session_module

##what's this module for?

this module is used for protect static resource(like *.mp4, *.jpg) access for nginx server, 
when a php start a session , it set a cookie name PHPSESSID, and set some session context on session.


php session context is stored in a text file, this module read the session file and check if the use has
already login, if not login, it will deny the access.

## configure example

###nginx.conf
```bash
location ~ \.mp4${
  php_session_check on;
  php_session_save_path /tmp/php-session/;
  php_session_save_depth 0;
  php_session_cookie  PHPSESSID;
  php_session_key  user;
  php_session_retcode 403;

}

config items:
php_session_check:  if session check is turn on ,  on/offf
php_session_save_path:  where the session file store, this must be same as session.save_path in /etc/php.ini
php_session_save_depth: the store directory depth of session file, for example , if session id is rdeoraoarehl5jd91morivgn66,
                        the session file will be /tmp/php-session/r/d/sess_rdeoraoarehl5jd91morivgn66, default value is 0.
php_session_cookie:     the cookie name of php session id, default vlaue is "PHPSESSID"
php_session_key:        the key of value in php $_SESSION[] variable
php_session_retcode:    the http response code if access is denied, default is 403;
```
###/etc/php.ini
```bash
[Session]
session.save_path="/tmp/php-session/";
session.save_handler = files
```

###php code
login_process.php
```php
<?php
  $id = $_REQUEST["id"];
  $passwd = $_REQUEST["passwd"];
  
  if( check_user_login( $id, $passwd ) )
    die( "invalid user/pass!" );
  
  session_start();
  $_SESSION["user"] = $id;  // the 'user' is same  php_session_key in nginx.conf
  header( "Location: /user_profile.php" );
?>
```
