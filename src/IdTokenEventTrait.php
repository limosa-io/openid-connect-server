<?php

namespace Idaas\OpenID;

use Idaas\OpenID\Entities\IdToken;
use League\OAuth2\Server\Grant\GrantTypeInterface;

trait IdTokenEventTrait
{
    /**
     * @var IdToken
     */
    private $idToken;

    /**
     * @var GrantTypeInterface
     */
    private $grantType;

    public function getIdToken()
    {
        return $this->idToken;
    }

    public function getGrantType()
    {
        return $this->grantType;
    }
}
