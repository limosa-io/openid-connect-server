<?php

namespace Idaas\OpenID\Repositories;

use League\OAuth2\Server\Entities\UserEntityInterface;
use League\OAuth2\Server\Repositories\UserRepositoryInterface as LeagueUserRepositoryInterface;

interface UserRepositoryInterface extends LeagueUserRepositoryInterface
{
    /**
     * Return the claims related to a scope
     */
    public function getClaims($scope);

    /**
     * Returns an associative array with attribute (claim) keys and values
     */
    public function getAttributes(string $userId, $claims, $scopes);
}
