<?php

namespace Idaas\OpenID\Repositories;

use League\OAuth2\Server\Entities\UserEntityInterface;
use League\OAuth2\Server\Repositories\UserRepositoryInterface as LeagueUserRepositoryInterface;

interface UserRepositoryInterface extends LeagueUserRepositoryInterface
{
    /**
     * Return the claims related to a scope
     */
    public function getClaims(ClaimRepositoryInterface $claimRepository, $scope);

    /**
     * Returns an associative array with attribute (claim) keys and values
     */
    public function getAttributes(UserEntityInterface $userEntity, $claims, $scopes);

    /**
     * Return User
     */
    public function getUserByIdentifier($identifier): ?UserEntityInterface;
}
