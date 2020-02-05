<?php

namespace Idaas\OpenID;

use League\OAuth2\Server\AuthorizationValidators\AuthorizationValidatorInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\ResourceServer;

class AdvancedResourceServer extends ResourceServer
{

    /**
     * @var null|AuthorizationValidatorInterface
     */
    private $authorizationValidator;

    /**
     * New server instance.
     *
     * @param AccessTokenRepositoryInterface       $accessTokenRepository
     * @param CryptKey|string                      $publicKey
     * @param null|AuthorizationValidatorInterface $authorizationValidator
     */
    public function __construct(
        AccessTokenRepositoryInterface $accessTokenRepository,
        AuthorizationValidatorInterface $authorizationValidator = null
    ) {
        $this->accessTokenRepository = $accessTokenRepository;
        $this->authorizationValidator = $authorizationValidator;
    }

    /**
     * @return AuthorizationValidatorInterface
     */
    protected function getAuthorizationValidator()
    {
        return $this->authorizationValidator;
    }
}
