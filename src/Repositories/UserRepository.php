<?php

namespace Idaas\OpenID\Repositories;

use Idaas\OpenID\Repositories\UserRepositoryInterface;
use Idaas\OpenID\Repositories\UserRepositoryTrait;

abstract class UserRepository implements UserRepositoryInterface
{
    use UserRepositoryTrait;
}
