<?php

namespace Idaas\OpenID\Entities;

use JsonSerializable;

interface ClaimEntityInterface extends JsonSerializable
{
    /**
     * Get the scope's identifier.
     *
     * @return string
     */
    public function getIdentifier();

    /**
     * Get type of the claim
     *
     * @return string userinfo|id_token
     */
    public function getType();

    /**
     * Whether this is an essential claim
     *
     * @return boolean
     */
    public function getEssential();
}
