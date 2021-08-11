<?php

namespace Idaas\OpenID;

use League\OAuth2\Server\CryptKey as BaseCryptKey;

class CryptKey extends BaseCryptKey
{
    public $x509 = null;
    public $kid = null;

    public function getKid()
    {
        return $this->kid;
    }

    public function setX509($x509)
    {
        $this->x509 = $x509;

        return $this;
    }

    public function setKid($kid)
    {
        $this->kid = $kid;

        return $this;
    }
}
