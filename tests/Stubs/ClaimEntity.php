<?php

namespace IdaasTests\Stubs;

use Idaas\OpenID\Entities\ClaimEntityInterface;

class ClaimEntity implements ClaimEntityInterface
{

    public const IDENTIFIER = 'id';
    public const ESSENTIAL = 'essential';
    public const TYPE = 'type';

    protected $identifier;

    protected $type;

    protected $essential;

    /**
     * Get the scope's identifier.
     *
     * @return string
     */
    public function getIdentifier()
    {
        return $this->identifier;
    }

    /**
     * Get type of the claim
     *
     * @return string userinfo|id_token
     */
    public function getType()
    {
        return $this->type;
    }

    /**
     * Whether this is an essential claim
     *
     * @return boolean
     */
    public function getEssential()
    {
        return $this->essential;
    }

    public function __construct($identifier, $type = 'userinfo', $essential = false)
    {
        $this->identifier = $identifier;
        $this->type = $type;
        $this->essential = $essential;
    }

    public function jsonSerialize()
    {
        return json_encode([
            self::IDENTIFIER    => $this->getIdentifier(),
            self::ESSENTIAL     => $this->getEssential(),
            self::TYPE          => $this->getType()
        ]);
    }
}
