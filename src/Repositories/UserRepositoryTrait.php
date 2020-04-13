<?php

namespace Idaas\OpenID\Repositories;

use League\OAuth2\Server\Entities\ScopeEntityInterface;

trait UserRepositoryTrait
{
    public function getClaims(ClaimRepositoryInterface $claimRepository, ScopeEntityInterface $scope)
    {
        return $claimRepository->getClaimsByScope($scope);
    }
}
