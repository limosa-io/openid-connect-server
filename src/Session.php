<?php

namespace Idaas\OpenID;

class Session implements SessionInterface
{
    public function getAuthTime()
    {
        return new \DateTime();
    }
}
