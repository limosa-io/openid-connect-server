<?php

namespace Idaas\OpenID\Entities;

use League\OAuth2\Server\Entities\AccessTokenEntityInterface as LeagueAccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;

interface AccessTokenEntityInterface extends LeagueAccessTokenEntityInterface
{
    /**
     * Return an array of claims associated with the token.
     *
     * @return ClaimEntityInterface[]
     */
    public function getClaims();
}
