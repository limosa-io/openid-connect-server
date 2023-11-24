<?php

namespace Idaas\OpenID\ResponseTypes;

use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\ResponseTypes\BearerTokenResponse as LeagueBearerTokenResponse;

class BearerTokenResponse extends LeagueBearerTokenResponse implements ResponseTypeInterface
{
    protected $idToken = null;

    /**
     * @return IdToken
     */
    public function setIdToken($idToken)
    {
        $this->idToken = $idToken;
    }

    public function getIdToken()
    {
        return $this->idToken;
    }

    public function getAccessToken()
    {
        return $this->accessToken;
    }

    protected function getExtraParams(AccessTokenEntityInterface $accessToken)
    {
        /*
         The Claims requested by the profile, email, address, and phone scope values
         are returned from the UserInfo Endpoint, as described in Section 5.3.2,
         when a response_type value is used that results in an Access Token being issued.
         However, when no Access Token is issued (which is the case for the response_type
         value id_token), the resulting Claims are returned in the ID Token.
         */
        if ($this->getIdToken() != null) {
            $idToken = $this->getIdToken()->convertToJWT($this->privateKey);

            // FIXME: Since an AuthorizationServer does not get re-created for every call, the BearerTokenResponse object does not either.
            // Clear the IdToken since it should be set seperatly for every request
            $this->setIdToken(null);

            return [
                'id_token' => $idToken->toString()
            ];
        } else {
            return [];
        }
    }
}
