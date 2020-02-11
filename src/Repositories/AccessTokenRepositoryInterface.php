<?php

namespace Idaas\OpenID\Repositories;

use Idaas\OpenID\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface as LeagueAccessTokenRepositoryInterface;

interface AccessTokenRepositoryInterface extends LeagueAccessTokenRepositoryInterface
{

    /**
     * 
     * @param array $claims []
     */
    public function storeClaims($id, array $claims);

    /**
     * Retrieve an access token.
     *
     * @param string $tokenId
     * @return AccessTokenEntityInterface
     */
    public function getAccessToken($tokenId);

}
