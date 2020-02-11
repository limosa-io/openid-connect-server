<?php

namespace Idaas\OpenID\Repositories;

use Idaas\OpenID\Entities\ClaimEntityInterface;
use League\OAuth2\Server\Repositories\RepositoryInterface;

/**
 * Claim interface.
 */
interface ClaimRepositoryInterface extends RepositoryInterface
{
    /**
     * Return information about a claim.
     *
     * @param string $identifier The claim identifier
     *
     * @return ClaimEntityInterface|null
     */
    public function getClaimEntityByIdentifier($identifier, $type, $essential);

    public function claimsRequestToEntities(string $json = null);
}