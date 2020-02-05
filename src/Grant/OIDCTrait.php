<?php

namespace Idaas\OpenID\Grant;

trait OIDCTrait
{
    protected $issuer;

    public function setIssuer($issuer)
    {
        $this->issuer = $issuer;
    }
}
