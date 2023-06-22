Yii2 Basic App Template with JWT 
================================

It's a skeleton based on [Yii 2](http://www.yiiframework.com/) application.
Made for rapidly creating secure apps.

There is already a component for JWT authorization.


Installation
------

~~~
composer install
~~~


Fill your DB connection information in `config/db.php` with real data, for example:

```php
return [
    'components' => [
        'db' => [
            'dsn' => 'mysql:host=localhost;dbname=yii2b4_site',
            'username' => 'project_user',
            'password' => 'userPASw5',
            'tablePrefix' => '',
        ],
    ...
];
```


Configure JWT 'secretKey', 'issuer' and 'audience' in config/web.php:

```php
$config = [
    'components' => [
        'jwt' => [
            'class' => 'app\components\jwt\JwtService',
            'tokenClass' => 'app\components\jwt\tokens\JwtHs256Token',
            'secretKey' => 'IU4-6Gftr*Huy41K72p',
            'issuer' => 'your-project.com',
            'audience' => ['your-project.com'],
        ],
    ],
];
```

Execute migrations:

~~~
php yii migrate
~~~

After create user table you can acces to Admin:
* username: admin
* password: !qaZse$32i  


DIRECTORY STRUCTURE
-------------------

    commands/           contains Console controller classes
    components/         contains components (jwt)
    config/             contains application configurations
    controllers/        contains Web frontend controller classes
    mail/               contains view files for e-mails
    migrations/         contains database migrations
    models/             contains common model classes
    runtime/            contains files generated during runtime
    tests/              contains tests for all classes
    uploads/            contains files for user-access downloads
    vendor/             contains dependent 3rd-party packages
    web/                contains the entry script and Web resources


REQUIREMENTS
------------

The minimum requirement by this project template that your Web server supports PHP 7.4.0.