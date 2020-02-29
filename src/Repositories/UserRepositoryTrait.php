<?php

namespace Idaas\OpenID\Repositories;

trait UserRepositoryTrait
{
    public function getClaims(ClaimRepositoryInterface $claimRepository, $scope)
    {
        return $claimRepository->getClaimsByScope($scope);
    }
}
