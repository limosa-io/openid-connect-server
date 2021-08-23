<?php

namespace Idaas\OpenID\Repositories;

use Idaas\OpenID\Entities\ClaimEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Entities\UserEntityInterface;
use League\OAuth2\Server\Repositories\UserRepositoryInterface as LeagueUserRepositoryInterface;

interface UserRepositoryInterface extends LeagueUserRepositoryInterface
{
    /**
     * Return the claims related to a scope
     * @return ClaimEntityInterface[]
     */
    public function getClaims(ClaimRepositoryInterface $claimRepository, ScopeEntityInterface $scope);

    /**
     * Returns an associative array with attribute (claim) keys and values
     */
    public function getAttributes(UserEntityInterface $userEntity, $claims, $scopes);

    /**
     * Returns an associative array with attribute (claim) keys and values. For use by userinfo endpoint
     */
    public function getUserInfoAttributes(UserEntityInterface $userEntity, $claims, $scopes);

    /**
     * Return User
     */
    public function getUserByIdentifier($identifier): ?UserEntityInterface;
}
