<?php

namespace IdaasTests;

use DateInterval;
use Idaas\OpenID\Grant\AuthCodeGrant;
use Idaas\OpenID\Repositories\ClaimRepositoryInterface;
use Idaas\OpenID\RequestTypes\AuthenticationRequest;
use Idaas\OpenID\Session;
use LeagueTests\Stubs\AuthCodeEntity;
use LeagueTests\Stubs\ClientEntity;
use LeagueTests\Stubs\UserEntity;
use Nyholm\Psr7\Response;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;

class BasicTest extends TestCase
{
    public function testResponse()
    {
        $clientRepository = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();

        $server = new AuthorizationServer(
            $clientRepository,
            $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock(),
            $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock(),
            'file://' . __DIR__ . '/../vendor/league/oauth2-server/tests/Stubs/private.key',
            'file://' . __DIR__ . '/../vendor/league/oauth2-server/tests/Stubs/public.key'
        );

        $authCodeRepository = $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock();
        $authCodeRepository->method('getNewAuthCode')->willReturn(new AuthCodeEntity());

        $grant = new AuthCodeGrant(
            $authCodeRepository,
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            $this->getMockBuilder(ClaimRepositoryInterface::class)->getMock(),
            new Session,
            new DateInterval('PT10M'),
            new DateInterval('PT10M')
        );

        $server->enableGrantType($grant);

        $authRequest = new AuthenticationRequest();
        $authRequest->setAuthorizationApproved(true);
        $authRequest->setClient(new ClientEntity());
        $authRequest->setGrantTypeId('authorization_code_oidc');
        $authRequest->setUser(new UserEntity());
        $authRequest->setRedirectUri('http://redirect/destination');
        $authRequest->setResponseType('token');

        $this->assertInstanceOf(
            ResponseInterface::class,
            $server->completeAuthorizationRequest($authRequest, new Response)
        );
    }
}
