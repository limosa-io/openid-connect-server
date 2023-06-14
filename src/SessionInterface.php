<?php

namespace Idaas\OpenID;

interface SessionInterface
{
    /**
     * @return \DateTimeInterface
     */
    public function getAuthTime();
}
