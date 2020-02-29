<?php

namespace Idaas\OpenID;

use Idaas\OpenID\Repositories\AccessTokenRepositoryInterface;
use Idaas\OpenID\Repositories\UserRepositoryInterface;
use League\OAuth2\Server\ResourceServer;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

class UserInfo
{

    protected $userRepository;
    protected $tokenRepository;
    protected $resourceServer;

    public function __construct(
        UserRepositoryInterface $userRepository,
        AccessTokenRepositoryInterface $tokenRepository,
        ResourceServer $resourceServer
    ) {
        $this->userRepository = $userRepository;
        $this->tokenRepository = $tokenRepository;
        $this->resourceServer = $resourceServer;
    }

    public function respondToUserInfoRequest(
        ServerRequestInterface $request,
        ResponseInterface $response
    ) {

        $validated = $this->resourceServer->validateAuthenticatedRequest($request);

        $validated->getAttribute('oauth_access_token_id');
        $validated->getAttribute('oauth_user_id');

        $token = $this->tokenRepository->getAccessToken($validated->getAttribute('oauth_access_token_id'));

        return $response->getBody()->write(\json_encode(
            $this->userRepository->getAttributes(
                $this->userRepository->getUserByIdentifier(
                    $validated->getAttribute('oauth_user_id')
                ),
                $token->getClaims(),
                $token->getScopes()
            )
        ));
    }
}
