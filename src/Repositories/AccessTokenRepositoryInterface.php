<?php

namespace Idaas\OpenID\Repositories;

use Idaas\OpenID\Entities\AccessTokenEntityInterface;
use Laravel\Passport\Bridge\AccessToken;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface as LeagueAccessTokenRepositoryInterface;

interface AccessTokenRepositoryInterface extends LeagueAccessTokenRepositoryInterface
{

    /**
     * @param array $claims ClaimEntityInterface[]
     */
    public function storeClaims(AccessToken $token, array $claims);

    /**
     * Retrieve an access token.
     *
     * @param string $tokenId
     * @return AccessTokenEntityInterface
     */
    public function getAccessToken($tokenId);

}
