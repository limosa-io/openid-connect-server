![](https://github.com/arietimmerman/openid-server/workflows/CI/badge.svg)
![](https://img.shields.io/badge/license-AGPL--3.0-green)
[![Latest Stable Version](https://poser.pugx.org/nl.idaas/openid-server/v/stable)](https://packagist.org/packages/nl.idaas/openid-server)
[![Total Downloads](https://poser.pugx.org/nl.idaas/openid-server/downloads)](https://packagist.org/packages/nl.idaas/openid-server)

# PHP OpenID Connect Server

This is an OpenID Connect Server written in PHP, built on top of [thephpleague/oauth2-server](https://github.com/thephpleague/oauth2-server).

It is used by [idaas.nl](https://www.idaas.nl/): (not) yet another identity as a service platform.

This library supports everything that is supported by `thephpleague/oauth2-server`, plus the following specifications

* [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html)

This library was created by [Arie Timmerman](https://github.com/arietimmerman).

## Installation

~~~
composer require nl.idaas/openid-server
~~~

## Example

This example implements show how to implement an authorization server with support for an authorization grant, including OpenID Connect support.

~~~.php
// Init our repositories
$scopeRepository = new ScopeRepository(); // instance of ScopeRepositoryInterface
$authCodeRepository = new AuthCodeRepository(); // instance of AuthCodeRepositoryInterface
$refreshTokenRepository = new RefreshTokenRepository(); // instance of RefreshTokenRepositoryInterface

// Specific to this module
$clientRepository = new ClientRepository(); // instance of \Idaas\OpenID\Repositories\ClientRepositoryInterface
$accessTokenRepository = new AccessTokenRepository(); // instance of \Idaas\OpenID\Repositories\AccessTokenRepositoryInterface
$claimRepository = new ClaimRepository(); // instance of ClaimRepositoryInterface

$privateKey = 'file://path/to/private.key';
//$privateKey = new CryptKey('file://path/to/private.key', 'passphrase'); // if private key has a pass phrase
$encryptionKey = 'lxZFUEsBCJ2Yb14IF2ygAHI5N4+ZAUXXaSeeJm6+twsUmIen'; // generate using base64_encode(random_bytes(32))

// Setup the authorization server
$server = new \League\OAuth2\Server\AuthorizationServer(
    $clientRepository,
    $accessTokenRepository,
    $scopeRepository,
    $privateKey,
    $encryptionKey
);

// OpenID Connect Authorization Code Grant
$grant = new \Idaas\OpenID\Grant\AuthCodeGrant(
    $authCodeRepository,
    $refreshTokenRepository,
    $claimRepository,
    new \Idaas\OpenID\Session,
    new DateInterval('PT10M'), // authorization codes will expire after 10 minutes
    new DateInterval('PT10M') // ID Token will expire after 10 minutes
);

$grant->setRefreshTokenTTL(new \DateInterval('P1M')); // refresh tokens will expire after 1 month

// Enable the authentication code grant on the server
$server->enableGrantType(
    $grant,
    new \DateInterval('PT1H') // access tokens will expire after 1 hour
);
~~~

## Usages

* [Laravel OpenID Connect Server](https://github.com/arietimmerman/laravel-openid-connect-server)
