<?php

namespace Idaas\OpenID\ResponseTypes;

use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface as LeagueResponseTypeInterface;

interface ResponseTypeInterface extends LeagueResponseTypeInterface
{
    public function setIdToken($idToken);

    public function getIdToken();
}
