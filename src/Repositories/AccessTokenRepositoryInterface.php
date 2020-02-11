<?php

namespace Idaas\OpenID\Repositories;

use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface as LeagueAccessTokenRepositoryInterface;

interface AccessTokenRepositoryInterface extends LeagueAccessTokenRepositoryInterface
{
    public function storeClaims($id, array $claims);

    /**
     * Retrieve an access token.
     *
     * @param string $tokenId
     * @return AccessTokenEntityInterface
     */
    public function getAccessToken($tokenId);

    public function persistNewAccessToken(AccessTokenEntityInterface $accessTokenEntity);
}
