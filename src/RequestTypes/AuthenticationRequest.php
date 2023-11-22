<?php

namespace Idaas\OpenID\RequestTypes;

use Idaas\OpenID\SessionInformation;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest;

class AuthenticationRequest extends AuthorizationRequest
{
    protected $nonce;
    protected $prompt;
    protected $maxAge;
    protected $uiLocates = []; //(space-separated list of BCP47 [RFC5646] language tag)
    protected $idTokenHint;
    protected $loginHint;
    protected $display;
    protected $acrValues = [];
    protected $responseType = null;
    protected $responseMode = null; // query, fragment,
    protected $claims = [];

    protected $sessionInformation;

    /**
     * @return AuthenticationRequest
     */
    public static function fromAuthorizationRequest(AuthorizationRequest $authorizationRequest)
    {
        if ($authorizationRequest instanceof AuthenticationRequest) {
            return $authorizationRequest;
        }

        $result = new self();

        $result->setClient($authorizationRequest->getClient());
        $result->setCodeChallenge($authorizationRequest->getCodeChallenge());
        $result->setCodeChallengeMethod($authorizationRequest->getCodeChallengeMethod());
        $result->setGrantTypeId($authorizationRequest->getGrantTypeId());
        $result->setRedirectUri($authorizationRequest->getRedirectUri());
        $result->setScopes($authorizationRequest->getScopes());
        $result->setState($authorizationRequest->getState());

        if ($authorizationRequest->getUser() !== null) {
            $result->setUser($authorizationRequest->getUser());
        }

        return $result;
    }

    public function setSessionInformation(SessionInformation $sessionInformation)
    {
        $this->sessionInformation = $sessionInformation;

        return $this;
    }

    public function getSessionInformation()
    {
        return $this->sessionInformation ?? new SessionInformation();
    }

    public function getNonce()
    {
        return $this->nonce;
    }

    /**
     * @param string $nonce
     */
    public function setNonce($nonce)
    {
        $this->nonce = $nonce;
    }

    public function setPrompt($prompt)
    {
        $this->prompt = $prompt;
    }

    public function getPrompt()
    {
        return $this->prompt;
    }

    public function setMaxAge($maxAge)
    {
        $this->maxAge = $maxAge;
    }

    public function getMaxAge()
    {
        return $this->maxAge;
    }

    public function setUILocales(array $uiLocales)
    {
        $this->uiLocates = $uiLocales;
    }

    public function getUILocales()
    {
        return $this->uiLocates;
    }

    public function setIDTokenHint($idTokenHint)
    {
        $this->idTokenHint = $idTokenHint;
    }

    public function getIDTokenHint()
    {
        return $this->idTokenHint;
    }

    public function setLoginHint($loginHint)
    {
        $this->loginHint = $loginHint;
    }

    public function getLoginHint()
    {
        return $this->loginHint;
    }

    public function setDisplay($display)
    {
        $this->display = $display;
    }

    public function getDisplay()
    {
        return $this->display;
    }

    public function setAcrValues(array $acrValues)
    {
        $this->acrValues = $acrValues;
    }

    public function getAcrValues()
    {
        return $this->acrValues;
    }

    public function setClaims(?array $claims)
    {
        $this->claims = $claims;
    }

    public function getClaims()
    {
        return $this->claims;
    }

    /**
     * Get the value of responseType
     */
    public function getResponseType()
    {
        return $this->responseType;
    }

    /**
     * Set the value of responseType
     *
     * @return  self
     */
    public function setResponseType($responseType)
    {
        $this->responseType = $responseType;

        return $this;
    }

    /**
     * Get the value of responseType
     */
    public function getResponseMode()
    {
        return $this->responseMode;
    }

    /**
     * Set the value of responseType
     *
     * @return  self
     */
    public function setResponseMode($responseMode)
    {
        $this->responseMode = $responseMode;

        return $this;
    }
}
