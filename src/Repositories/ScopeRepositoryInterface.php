<?php

namespace League\OAuth2\Server\Repositories;

use Idaas\OpenID\Entities\ClaimEntityInterface;

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
}
