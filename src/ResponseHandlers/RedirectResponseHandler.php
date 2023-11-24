<?php

namespace Idaas\OpenID\ResponseHandlers;

use Idaas\OpenID\RequestTypes\AuthenticationRequest;
use League\OAuth2\Server\ResponseTypes\RedirectResponse;

class RedirectResponseHandler
{
    public function canRespondToAuthorizationRequest(AuthenticationRequest $authenticationRequest)
    {
        return
            $authenticationRequest->getResponseMode() === null ||
            $authenticationRequest->getResponseMode() === 'fragment' ||
            $authenticationRequest->getResponseMode() === 'query';
    }

    public function generateResponse(AuthenticationRequest $authenticationRequest, $code)
    {
        $queryDelimiter = '?';

        if ($authenticationRequest->getResponseMode() === 'fragment' ||
            strpos($authenticationRequest->getResponseType(), 'code') === false
        ) {
            $queryDelimiter = '#';
        }

        if ($authenticationRequest->getResponseMode() === 'query') {
            $queryDelimiter = '?';
        }

        $response = new RedirectResponse();
        $response->setRedirectUri(
            $this->makeRedirectUri(
                $authenticationRequest->getRedirectUri(),
                [
                    'code'  => $code,
                    'state' => $authenticationRequest->getState(),
                ],
                $queryDelimiter
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
