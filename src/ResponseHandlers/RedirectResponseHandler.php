<?php

namespace Idaas\OpenID\ResponseHandlers;

use Idaas\OpenID\RequestTypes\AuthenticationRequest;
use League\OAuth2\Server\ResponseTypes\RedirectResponse;

class RedirectResponseHandler
{

    public function canRespondToAuthorizationRequest(AuthenticationRequest $authenticationRequest)
    {
        return
            $authenticationRequest->getResponseMode() == null ||
            $authenticationRequest->getResponseMode() == 'redirect';
    }

    public function generateResponse(AuthenticationRequest $authenticationRequest, $code)
    {
        $response = new RedirectResponse();
        $response->setRedirectUri(
            $this->makeRedirectUri(
                $authenticationRequest->getRedirectUri(),
                [
                    'code'  => $code,
                    'state' => $authenticationRequest->getState(),
                ]
            )
        );
        return $response;
    }

    public function makeRedirectUri($uri, $params = [], $queryDelimiter = '?')
    {
        $uri .= (\strstr($uri, $queryDelimiter) === false) ? $queryDelimiter : '&';

        return $uri . \http_build_query($params);
    }
}
