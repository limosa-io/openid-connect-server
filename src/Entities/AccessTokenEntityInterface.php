<?php

namespace Idaas\OpenID\Entities;

use League\OAuth2\Server\Entities\AccessTokenEntityInterface as LeagueAccessTokenEntityInterface;

interface AccessTokenEntityInterface extends LeagueAccessTokenEntityInterface
{
    /**
     * Associate a scope with the token.
     *
     * @param ScopeEntityInterface $scope
     */
    public function addClaim(ClaimEntityInterface $claim);

    /**
     * Return an array of scopes associated with the token.
     *
     * @return ClaimEntityInterface[]
     */
    public function getClaims();
}
