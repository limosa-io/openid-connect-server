<?php

namespace Idaas\OpenID\Repositories;

use Idaas\OpenID\Repositories\ClaimRepositoryInterface;
use Idaas\OpenID\Repositories\UserRepositoryInterface;
use UserRepositoryTrait;

abstract class UserRepositoy implements UserRepositoryInterface
{
    use UserRepositoryTrait;
}
