<?php

namespace Idaas\OpenID\Repositories;

use Idaas\OpenID\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface as EntitiesAccessTokenEntityInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface as LeagueAccessTokenRepositoryInterface;

interface AccessTokenRepositoryInterface extends LeagueAccessTokenRepositoryInterface
{

    /**
     * @param array $claims ClaimEntityInterface[]
     */
    public function storeClaims(EntitiesAccessTokenEntityInterface $token, array $claims);

    /**
     * Retrieve an access token.
     *
     * @param string $tokenId
     * @return AccessTokenEntityInterface
     */
    public function getAccessToken($tokenId);
}
