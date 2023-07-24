<?php

namespace Idaas\OpenID;

use Idaas\OpenID\RequestTypes\AuthenticationRequest;
use Idaas\OpenID\ResponseHandlers\RedirectResponseHandler;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest;

class ResponseHandler
{

    protected $handlers;

    public function __construct()
    {
        $this->handlers = [
            new RedirectResponseHandler()
        ];
    }

    public function getResponse(AuthenticationRequest $authenticationRequest, $code)
    {
        foreach ($this->handlers as $handler) {
            if ($handler->canRespondToAuthorizationRequest($authenticationRequest)) {
                return $handler->generateResponse($authenticationRequest, $code);
            }
        }

        throw OAuthServerException::invalidRequest('response_mode', 'No valid response_mode provided');
    }
}
