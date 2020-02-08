<?php

namespace Idaas\OpenID\Repositories;

use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface as LeagueAccessTokenRepositoryInterface;

interface AccessTokenRepositoryInterface extends LeagueAccessTokenRepositoryInterface
{
    public function storeClaims($id, array $claims);
}
