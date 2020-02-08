<?php

namespace IdaasTests\Stubs;

use Idaas\OpenID\ResponseTypes\ResponseTypeInterface;
use LeagueTests\Stubs\StubResponseType as LeagueTestsStubResponseType;

class StubResponseType extends LeagueTestsStubResponseType implements ResponseTypeInterface
{

    protected $idToken;

    public function setIdToken($idToken)
    {
        $this->idToken = $idToken;
    }

    public function getIdToken()
    {
        return $this->idToken;
    }
}
