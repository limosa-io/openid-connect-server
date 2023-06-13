<?php

namespace Idaas\OpenID;

use Idaas\OpenID\Entities\IdToken;
use League\Event\Event;
use League\OAuth2\Server\Grant\GrantTypeInterface;

class IdTokenEvent extends Event
{
    const TOKEN_POPULATED = 'id_token.populated';

    /**
     * @var IdToken
     */
    private $idToken;

    /**
     * @var GrantTypeInterface
     */
    private $grantType;

    public function __construct($name, IdToken $idToken, GrantTypeInterface $grantType)
    {
        parent::__construct($name);
        $this->idToken = $idToken;
        $this->grantType = $grantType;
    }

    public function getIdToken()
    {
        return $this->idToken;
    }

    public function getGrantType()
    {
        return $this->grantType;
    }
}
