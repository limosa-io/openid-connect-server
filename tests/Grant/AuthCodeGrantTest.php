<?php

namespace LeagueTests\Grant;

use DateInterval;
use DateTime;
use Idaas\OpenID\Entities\IdToken;
use Idaas\OpenID\Grant\AuthCodeGrant;
use Idaas\OpenID\Repositories\AccessTokenRepositoryInterface;
use Idaas\OpenID\Repositories\ClaimRepositoryInterface;
use Idaas\OpenID\RequestTypes\AuthenticationRequest;
use Idaas\OpenID\Session;
use Idaas\OpenID\SessionInformation;
use IdaasTests\Stubs\ClaimEntity;
use IdaasTests\Stubs\StubResponseType;
use Nyholm\Psr7\ServerRequest;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest;
use League\OAuth2\Server\ResponseTypes\RedirectResponse;
use LeagueTests\Stubs\AccessTokenEntity;
use LeagueTests\Stubs\AuthCodeEntity;
use LeagueTests\Stubs\ClientEntity;
use LeagueTests\Stubs\CryptTraitStub;
use LeagueTests\Stubs\RefreshTokenEntity;
use LeagueTests\Stubs\ScopeEntity;
use LeagueTests\Stubs\UserEntity;
use PHPUnit\Framework\TestCase;

class AuthCodeGrantTest extends TestCase
{
    const DEFAULT_SCOPE = 'basic';

    /**
     * @var CryptTraitStub
     */
    protected $cryptStub;

    const CODE_VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';

    const CODE_CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

    public function setUp(): void
    {
        $this->cryptStub = new CryptTraitStub();
    }

    public function testGetIdentifier()
    {
        $grant = new AuthCodeGrant(
            $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock(),
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            $this->getMockBuilder(ClaimRepositoryInterface::class)->getMock(),
            new Session,
            new DateInterval('PT10M'),
            new DateInterval('PT10M')
        );

        $this->assertEquals('authorization_code_oidc', $grant->getIdentifier());
    }

    public function testCanRespondToAuthorizationRequest()
    {
        $grant = new AuthCodeGrant(
            $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock(),
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            $this->getMockBuilder(ClaimRepositoryInterface::class)->getMock(),
            new Session,
            new DateInterval('PT10M'),
            new DateInterval('PT10M')
        );

        $request = (new ServerRequest(
            'GET',
            'http://example.com?'
        ))->withQueryParams(['response_type' => 'code',
        'client_id'     => 'foo',
        'scope'        => 'openid']);

        $this->assertTrue($grant->canRespondToAuthorizationRequest($request));
    }

    public function testValidateAuthorizationRequest()
    {
        $client = new ClientEntity();
        $client->setRedirectUri('http://foo/bar');
        $client->setConfidential();

        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $claimRepositoryMock = $this->getMockBuilder(ClaimRepositoryInterface::class)->getMock();
        $claimRepositoryMock->method('claimsRequestToEntities')->willReturn([new ClaimEntity('sub')]);

        $scope = new ScopeEntity();
        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scope);

        $grant = new AuthCodeGrant(
            $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock(),
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            $claimRepositoryMock,
            new Session,
            new DateInterval('PT10M'),
            new DateInterval('PT10M')
        );

        $grant->setClientRepository($clientRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setDefaultScope(self::DEFAULT_SCOPE);

        $request = (new ServerRequest('GET', 'http://example.com'))->withQueryParams(
            [
                'response_type' => 'code',
                'client_id'     => 'foo',
                'redirect_uri'  => 'http://foo/bar',
            ]
        );

        $this->assertInstanceOf(AuthorizationRequest::class, $grant->validateAuthorizationRequest($request));
    }

    public function testValidateAuthorizationRequestRedirectUriArray()
    {
        $client = new ClientEntity();
        $client->setRedirectUri(['http://foo/bar']);
        $client->setConfidential();
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $scope = new ScopeEntity();
        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scope);

        $claimRepositoryMock = $this->getMockBuilder(ClaimRepositoryInterface::class)->getMock();
        $claimRepositoryMock->method('claimsRequestToEntities')->willReturn([new ClaimEntity('sub')]);

        $grant = new AuthCodeGrant(
            $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock(),
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            $claimRepositoryMock,
            new Session,
            new DateInterval('PT10M'),
            new DateInterval('PT10M')
        );

        $grant->setClientRepository($clientRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setDefaultScope(self::DEFAULT_SCOPE);

        $request = (new ServerRequest(
            'GET',
            'http://www.example.com'
        ))->withQueryParams(
            [
                'response_type' => 'code',
                'client_id'     => 'foo',
                'redirect_uri'  => 'http://foo/bar',
            ]
        );

        $this->assertInstanceOf(AuthorizationRequest::class, $grant->validateAuthorizationRequest($request));
    }

    public function testValidateAuthorizationRequestCodeChallenge()
    {
        $client = new ClientEntity();
        $client->setRedirectUri('http://foo/bar');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $scope = new ScopeEntity();
        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scope);

        $claimRepositoryMock = $this->getMockBuilder(ClaimRepositoryInterface::class)->getMock();
        $claimRepositoryMock->method('claimsRequestToEntities')->willReturn([new ClaimEntity('sub')]);

        $grant = new AuthCodeGrant(
            $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock(),
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            $claimRepositoryMock,
            new Session,
            new DateInterval('PT10M'),
            new DateInterval('PT10M')
        );

        $grant->setClientRepository($clientRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setDefaultScope(self::DEFAULT_SCOPE);

        $request = (new ServerRequest('GET', '/'))->withQueryParams([
            'response_type'  => 'code',
            'client_id'      => 'foo',
            'redirect_uri'   => 'http://foo/bar',
            'code_challenge' => self::CODE_CHALLENGE,
        ]);

        $this->assertInstanceOf(AuthorizationRequest::class, $grant->validateAuthorizationRequest($request));
    }

    public function testValidateAuthorizationRequestCodeChallengeInvalidLengthTooShort()
    {
        $client = new ClientEntity();
        $client->setRedirectUri('http://foo/bar');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $claimRepositoryMock = $this->getMockBuilder(ClaimRepositoryInterface::class)->getMock();
        $claimRepositoryMock->method('claimsRequestToEntities')->willReturn([new ClaimEntity('sub')]);

        $grant = new AuthCodeGrant(
            $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock(),
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            $claimRepositoryMock,
            new Session,
            new DateInterval('PT10M'),
            new DateInterval('PT10M')
        );

        $grant->setClientRepository($clientRepositoryMock);

        $request = (new ServerRequest('GET', '/'))->withQueryParams([
            'response_type'  => 'code',
            'client_id'      => 'foo',
            'redirect_uri'   => 'http://foo/bar',
            'code_challenge' => \str_repeat('A', 42),
        ]);

        $this->expectException(\League\OAuth2\Server\Exception\OAuthServerException::class);

        $grant->validateAuthorizationRequest($request);
    }

    public function testValidateAuthorizationRequestCodeChallengeInvalidLengthTooLong()
    {
        $client = new ClientEntity();
        $client->setRedirectUri('http://foo/bar');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $claimRepositoryMock = $this->getMockBuilder(ClaimRepositoryInterface::class)->getMock();
        $claimRepositoryMock->method('claimsRequestToEntities')->willReturn([new ClaimEntity('sub')]);

        $grant = new AuthCodeGrant(
            $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock(),
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            $claimRepositoryMock,
            new Session,
            new DateInterval('PT10M'),
            new DateInterval('PT10M')
        );

        $grant->setClientRepository($clientRepositoryMock);

        $request = (new ServerRequest('GET', '/'))->withQueryParams([
            'response_type'  => 'code',
            'client_id'      => 'foo',
            'redirect_uri'   => 'http://foo/bar',
            'code_challenge' => \str_repeat('A', 129),
        ]);

        $this->expectException(\League\OAuth2\Server\Exception\OAuthServerException::class);

        $grant->validateAuthorizationRequest($request);
    }

    public function testValidateAuthorizationRequestCodeChallengeInvalidCharacters()
    {
        $client = new ClientEntity();
        $client->setRedirectUri('http://foo/bar');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $claimRepositoryMock = $this->getMockBuilder(ClaimRepositoryInterface::class)->getMock();
        $claimRepositoryMock->method('claimsRequestToEntities')->willReturn([new ClaimEntity('sub')]);

        $grant = new AuthCodeGrant(
            $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock(),
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            $claimRepositoryMock,
            new Session,
            new DateInterval('PT10M'),
            new DateInterval('PT10M')
        );

        $grant->setClientRepository($clientRepositoryMock);

        $request = (new ServerRequest('GET', '/'))->withQueryParams([
            'response_type' => 'code',
            'client_id' => 'foo',
            'redirect_uri' => 'http://foo/bar',
            'code_challenge' => \str_repeat('A', 42) . '!',
        ]);

        $this->expectException(\League\OAuth2\Server\Exception\OAuthServerException::class);

        $grant->validateAuthorizationRequest($request);
    }

    public function testValidateAuthorizationRequestMissingClientId()
    {
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();

        $claimRepositoryMock = $this->getMockBuilder(ClaimRepositoryInterface::class)->getMock();
        $claimRepositoryMock->method('claimsRequestToEntities')->willReturn([new ClaimEntity('sub')]);

        $grant = new AuthCodeGrant(
            $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock(),
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            $claimRepositoryMock,
            new Session,
            new DateInterval('PT10M'),
            new DateInterval('PT10M')
        );
        $grant->setClientRepository($clientRepositoryMock);

        $request = (new ServerRequest('GET', '/'))->withQueryParams([
            'response_type' => 'code',
        ]);

        $this->expectException(\League\OAuth2\Server\Exception\OAuthServerException::class);
        $this->expectExceptionCode(3);

        $grant->validateAuthorizationRequest($request);
    }

    public function testValidateAuthorizationRequestInvalidClientId()
    {
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn(null);

        $claimRepositoryMock = $this->getMockBuilder(ClaimRepositoryInterface::class)->getMock();
        $claimRepositoryMock->method('claimsRequestToEntities')->willReturn([new ClaimEntity('sub')]);

        $grant = new AuthCodeGrant(
            $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock(),
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            $claimRepositoryMock,
            new Session,
            new DateInterval('PT10M'),
            new DateInterval('PT10M')
        );
        $grant->setClientRepository($clientRepositoryMock);

        $request = (new ServerRequest('GET', '/'))->withQueryParams([
            'response_type' => 'code',
            'client_id'     => 'foo',
        ]);

        $this->expectException(\League\OAuth2\Server\Exception\OAuthServerException::class);
        $this->expectExceptionCode(4);

        $grant->validateAuthorizationRequest($request);
    }

    public function testValidateAuthorizationRequestBadRedirectUriString()
    {
        $client = new ClientEntity();
        $client->setRedirectUri('http://foo/bar');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $claimRepositoryMock = $this->getMockBuilder(ClaimRepositoryInterface::class)->getMock();
        $claimRepositoryMock->method('claimsRequestToEntities')->willReturn([new ClaimEntity('sub')]);

        $grant = new AuthCodeGrant(
            $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock(),
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            $claimRepositoryMock,
            new Session,
            new DateInterval('PT10M'),
            new DateInterval('PT10M')
        );
        $grant->setClientRepository($clientRepositoryMock);

        $request = (new ServerRequest('GET', '/'))->withQueryParams([
            'response_type' => 'code',
            'client_id'     => 'foo',
            'redirect_uri'  => 'http://bar',
        ]);

        $this->expectException(\League\OAuth2\Server\Exception\OAuthServerException::class);
        $this->expectExceptionCode(4);

        $grant->validateAuthorizationRequest($request);
    }

    public function testValidateAuthorizationRequestBadRedirectUriArray()
    {
        $client = new ClientEntity();
        $client->setRedirectUri(['http://foo/bar']);
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $claimRepositoryMock = $this->getMockBuilder(ClaimRepositoryInterface::class)->getMock();
        $claimRepositoryMock->method('claimsRequestToEntities')->willReturn([new ClaimEntity('sub')]);

        $grant = new AuthCodeGrant(
            $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock(),
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            $claimRepositoryMock,
            new Session,
            new DateInterval('PT10M'),
            new DateInterval('PT10M')
        );
        $grant->setClientRepository($clientRepositoryMock);

        $request = (new ServerRequest('GET', '/'))->withQueryParams([
            'response_type' => 'code',
            'client_id'     => 'foo',
            'redirect_uri'  => 'http://bar',
        ]);

        $this->expectException(\League\OAuth2\Server\Exception\OAuthServerException::class);
        $this->expectExceptionCode(4);

        $grant->validateAuthorizationRequest($request);
    }

    public function testValidateAuthorizationRequestInvalidCodeChallengeMethod()
    {
        $client = new ClientEntity();
        $client->setRedirectUri('http://foo/bar');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $scope = new ScopeEntity();
        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scope);

        $claimRepositoryMock = $this->getMockBuilder(ClaimRepositoryInterface::class)->getMock();
        $claimRepositoryMock->method('claimsRequestToEntities')->willReturn([new ClaimEntity('sub')]);

        $grant = new AuthCodeGrant(
            $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock(),
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            $claimRepositoryMock,
            new Session,
            new DateInterval('PT10M'),
            new DateInterval('PT10M')
        );

        $grant->setClientRepository($clientRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setDefaultScope(self::DEFAULT_SCOPE);

        $request = (new ServerRequest('GET', '/'))->withQueryParams([
            'response_type' => 'code',
            'client_id' => 'foo',
            'redirect_uri' => 'http://foo/bar',
            'code_challenge' => 'foobar',
            'code_challenge_method' => 'foo',
        ]);

        $this->expectException(\League\OAuth2\Server\Exception\OAuthServerException::class);
        $this->expectExceptionCode(3);

        $grant->validateAuthorizationRequest($request);
    }

    public function testCompleteAuthorizationRequest()
    {
        $authRequest = new AuthenticationRequest();
        $authRequest->setAuthorizationApproved(true);
        $authRequest->setClient(new ClientEntity());
        $authRequest->setGrantTypeId('authorization_code');
        $authRequest->setUser(new UserEntity());
        $authRequest->setRedirectUri('http://redirect/destination');
        $authRequest->setResponseType('code');

        $authCodeRepository = $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock();
        $authCodeRepository->method('getNewAuthCode')->willReturn(new AuthCodeEntity());

        $claimRepositoryMock = $this->getMockBuilder(ClaimRepositoryInterface::class)->getMock();
        $claimRepositoryMock->method('claimsRequestToEntities')->willReturn([new ClaimEntity('sub')]);

        $grant = new AuthCodeGrant(
            $authCodeRepository,
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            $claimRepositoryMock,
            new Session,
            new DateInterval('PT10M'),
            new DateInterval('PT10M')
        );
        $grant->setEncryptionKey($this->cryptStub->getKey());

        $this->assertInstanceOf(RedirectResponse::class, $grant->completeAuthorizationRequest($authRequest));
    }

    public function testCompleteAuthorizationRequestDenied()
    {
        $authRequest = new AuthenticationRequest();
        $authRequest->setAuthorizationApproved(false);
        $authRequest->setClient(new ClientEntity());
        $authRequest->setGrantTypeId('authorization_code');
        $authRequest->setUser(new UserEntity());
        $authRequest->setRedirectUri('http://redirect/destination');
        $authRequest->setResponseType('code');

        $authCodeRepository = $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock();
        $authCodeRepository->method('getNewAuthCode')->willReturn(new AuthCodeEntity());

        $claimRepositoryMock = $this->getMockBuilder(ClaimRepositoryInterface::class)->getMock();
        $claimRepositoryMock->method('claimsRequestToEntities')->willReturn([new ClaimEntity('sub')]);

        $grant = new AuthCodeGrant(
            $authCodeRepository,
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            $claimRepositoryMock,
            new Session,
            new DateInterval('PT10M'),
            new DateInterval('PT10M')
        );
        $grant->setEncryptionKey($this->cryptStub->getKey());

        $this->expectException(\League\OAuth2\Server\Exception\OAuthServerException::class);
        $this->expectExceptionCode(9);

        $grant->completeAuthorizationRequest($authRequest);
    }

    public function testRespondToAccessTokenRequest()
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setRedirectUri('http://foo/bar');
        $client->setConfidential();
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeEntity = new ScopeEntity();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scopeEntity);
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('getNewToken')->willReturn(new AccessTokenEntity());
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();
        $accessTokenRepositoryMock->method('storeClaims')->willReturnSelf();

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('persistNewRefreshToken')->willReturnSelf();
        $refreshTokenRepositoryMock->method('getNewRefreshToken')->willReturn(new RefreshTokenEntity());

        $grant = new AuthCodeGrant(
            $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock(),
            $refreshTokenRepositoryMock,
            $this->getMockBuilder(ClaimRepositoryInterface::class)->getMock(),
            new Session,
            new DateInterval('PT10M'),
            new DateInterval('PT10M')
        );
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setRefreshTokenRepository($refreshTokenRepositoryMock);
        $grant->setEncryptionKey($this->cryptStub->getKey());
        $grant->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../../vendor/league/oauth2-server/tests/Stubs/private.key'));

        $request = (new ServerRequest('POST', '/'))->withParsedBody(
            [
                'grant_type'   => 'authorization_code',
                'client_id'    => 'foo',
                'redirect_uri' => 'http://foo/bar',
                'scope'        => 'openid',
                'code'         => $this->cryptStub->doEncrypt(
                    \json_encode(
                        [
                            'auth_code_id' => \uniqid(),
                            'expire_time'  => \time() + 3600,
                            'client_id'    => 'foo',
                            'user_id'      => 123,
                            'redirect_uri' => 'http://foo/bar',

                            'scopes'       => ['foo','openid'],
                            'claims'       => ['given_name'],
                            'nonce'        => '12345',
                            'auth_time'       => (new DateTime())->getTimestamp(),
                            'sessionInformation' => (new SessionInformation())->setAcr('acr')->setAmr('amr')->setAzp('azp')->toJSON()
                        ]
                    )
                ),
            ]
        );

        /** @var StubResponseType $response */
        $response = $grant->respondToAccessTokenRequest($request, new StubResponseType(), new DateInterval('PT10M'));

        $this->assertInstanceOf(IdToken::class, $response->getIdToken());
        $this->assertInstanceOf(AccessTokenEntityInterface::class, $response->getAccessToken());
        $this->assertInstanceOf(RefreshTokenEntityInterface::class, $response->getRefreshToken());
    }

    public function testRespondToAccessTokenRequestUsingHttpBasicAuth()
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn(new ScopeEntity());
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('getNewToken')->willReturn(new AccessTokenEntity());

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('getNewRefreshToken')->willReturn(new RefreshTokenEntity());

        $authCodeGrant = new AuthCodeGrant(
            $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock(),
            $refreshTokenRepositoryMock,
            $this->getMockBuilder(ClaimRepositoryInterface::class)->getMock(),
            new Session,
            new DateInterval('PT10M'),
            new DateInterval('PT10M')
        );

        $authCodeGrant->setClientRepository($clientRepositoryMock);
        $authCodeGrant->setScopeRepository($scopeRepositoryMock);
        $authCodeGrant->setAccessTokenRepository($accessTokenRepositoryMock);
        $authCodeGrant->setEncryptionKey($this->cryptStub->getKey());
        $authCodeGrant->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../../vendor/league/oauth2-server/tests/Stubs/private.key'));

        $request = (new ServerRequest('POST', '/'))->withParsedBody(
            [
                'grant_type'   => 'authorization_code',
                'redirect_uri' => 'http://foo/bar',
                'code'         => $this->cryptStub->doEncrypt(
                    \json_encode(
                        [
                            'auth_code_id' => \uniqid(),
                            'client_id' => 'foo',
                            'expire_time'  => \time() + 3600,
                            'user_id'      => 123,
                            'redirect_uri' => 'http://foo/bar',

                            'scopes'       => ['foo','openid'],
                            'claims'       => ['given_name'],
                            'nonce'        => '12345',
                            'auth_time'       => (new DateTime())->getTimestamp(),
                            'sessionInformation' => (new SessionInformation())->setAcr('acr')->setAmr('amr')->setAzp('azp')->toJSON()
                        ]
                    )
                )]
        )->withHeader('Authorization', 'Basic ' . base64_encode('foo:1234'));

        /** @var StubResponseType $response */
        $response = $authCodeGrant->respondToAccessTokenRequest($request, new StubResponseType(), new \DateInterval('PT10M'));

        $this->assertInstanceOf(AccessTokenEntityInterface::class, $response->getAccessToken());
        // TODO: enable the following test
        $this->assertInstanceOf(RefreshTokenEntityInterface::class, $response->getRefreshToken());
    }

    public function testRespondToAccessTokenRequestForPublicClient()
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setRedirectUri('http://foo/bar');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeEntity = new ScopeEntity();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scopeEntity);
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('getNewToken')->willReturn(new AccessTokenEntity());
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('persistNewRefreshToken')->willReturnSelf();
        $refreshTokenRepositoryMock->method('getNewRefreshToken')->willReturn(new RefreshTokenEntity());

        $grant = new AuthCodeGrant(
            $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock(),
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            $this->getMockBuilder(ClaimRepositoryInterface::class)->getMock(),
            new Session,
            new DateInterval('PT10M'),
            new DateInterval('PT10M')
        );
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setRefreshTokenRepository($refreshTokenRepositoryMock);
        $grant->setEncryptionKey($this->cryptStub->getKey());
        $grant->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../../vendor/league/oauth2-server/tests/Stubs/private.key'));

        $request = (new ServerRequest('GET', '/'))->withParsedBody(
            [
                'grant_type'   => 'authorization_code',
                'client_id'    => 'foo',
                'redirect_uri' => 'http://foo/bar',
                'code'         => $this->cryptStub->doEncrypt(
                    \json_encode(
                        [
                            'auth_code_id' => \uniqid(),
                            'expire_time'  => \time() + 3600,
                            'client_id'    => 'foo',
                            'user_id'      => 123,
                            'redirect_uri' => 'http://foo/bar',

                            'scopes'       => ['foo','openid'],
                            'claims'       => ['given_name'],
                            'nonce'        => '12345',
                            'auth_time'       => (new DateTime())->getTimestamp(),
                            'sessionInformation' => (new SessionInformation())->setAcr('acr')->setAmr('amr')->setAzp('azp')->toJSON()
                        ]
                    )
                ),
            ]
        );

        /** @var StubResponseType $response */
        $response = $grant->respondToAccessTokenRequest($request, new StubResponseType(), new DateInterval('PT10M'));

        $this->assertInstanceOf(AccessTokenEntityInterface::class, $response->getAccessToken());
        $this->assertInstanceOf(RefreshTokenEntityInterface::class, $response->getRefreshToken());
    }

    public function testRespondToAccessTokenRequestNullRefreshToken()
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setRedirectUri('http://foo/bar');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeEntity = new ScopeEntity();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scopeEntity);
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('getNewToken')->willReturn(new AccessTokenEntity());
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('persistNewRefreshToken')->willReturnSelf();
        $refreshTokenRepositoryMock->method('getNewRefreshToken')->willReturn(null);

        $claimRepositoryMock = $this->getMockBuilder(ClaimRepositoryInterface::class)->getMock();
        $claimRepositoryMock->method('claimsRequestToEntities')->willReturn([new ClaimEntity('sub')]);

        $grant = new AuthCodeGrant(
            $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock(),
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            $claimRepositoryMock,
            new Session,
            new DateInterval('PT10M'),
            new DateInterval('PT10M')
        );

        $grant->setClientRepository($clientRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setEncryptionKey($this->cryptStub->getKey());
        $grant->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../../vendor/league/oauth2-server/tests/Stubs/private.key'));

        $request = (new ServerRequest('GET', '/'))->withParsedBody(
            [
                'grant_type'   => 'authorization_code',
                'client_id'    => 'foo',
                'redirect_uri' => 'http://foo/bar',
                'code'         => $this->cryptStub->doEncrypt(
                    \json_encode(
                        [
                            'auth_code_id' => \uniqid(),
                            'expire_time'  => \time() + 3600,
                            'client_id'    => 'foo',
                            'user_id'      => 123,
                            'redirect_uri' => 'http://foo/bar',

                            'scopes'       => ['foo','openid'],
                            'claims'       => ['given_name'],
                            'nonce'        => '12345',
                            'auth_time'       => (new DateTime())->getTimestamp(),
                            'sessionInformation' => (new SessionInformation())->setAcr('acr')->setAmr('amr')->setAzp('azp')->toJSON()
                        ]
                    )
                ),
            ]
        );

        /** @var StubResponseType $response */
        $response = $grant->respondToAccessTokenRequest($request, new StubResponseType(), new \DateInterval('PT10M'));

        $this->assertInstanceOf(AccessTokenEntityInterface::class, $response->getAccessToken());
        $this->assertNull($response->getRefreshToken());
    }

    public function testRespondToAccessTokenRequestCodeChallengePlain()
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setRedirectUri('http://foo/bar');
        $client->setConfidential();
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeEntity = new ScopeEntity();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scopeEntity);
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('getNewToken')->willReturn(new AccessTokenEntity());
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('persistNewRefreshToken')->willReturnSelf();
        $refreshTokenRepositoryMock->method('getNewRefreshToken')->willReturn(new RefreshTokenEntity());

        $claimRepositoryMock = $this->getMockBuilder(ClaimRepositoryInterface::class)->getMock();
        $claimRepositoryMock->method('claimsRequestToEntities')->willReturn([new ClaimEntity('sub')]);

        $grant = new AuthCodeGrant(
            $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock(),
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            $claimRepositoryMock,
            new Session,
            new DateInterval('PT10M'),
            new DateInterval('PT10M')
        );

        $grant->setClientRepository($clientRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setRefreshTokenRepository($refreshTokenRepositoryMock);
        $grant->setEncryptionKey($this->cryptStub->getKey());
        $grant->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../../vendor/league/oauth2-server/tests/Stubs/private.key'));

        $request = (new ServerRequest('GET', '/'))->withParsedBody(
            [
                'grant_type'    => 'authorization_code',
                'client_id'     => 'foo',
                'redirect_uri'  => 'http://foo/bar',
                'code_verifier' => self::CODE_VERIFIER,
                'code'          => $this->cryptStub->doEncrypt(
                    \json_encode(
                        [
                            'auth_code_id'          => \uniqid(),
                            'expire_time'           => \time() + 3600,
                            'client_id'             => 'foo',
                            'user_id'               => 123,
                            'redirect_uri'          => 'http://foo/bar',
                            'code_challenge'        => self::CODE_VERIFIER,
                            'code_challenge_method' => 'plain',

                            'scopes'       => ['foo','openid'],
                            'claims'       => ['given_name'],
                            'nonce'        => '12345',
                            'auth_time'       => (new DateTime())->getTimestamp(),
                            'sessionInformation' => (new SessionInformation())->setAcr('acr')->setAmr('amr')->setAzp('azp')->toJSON()
                        ]
                    )
                ),
            ]
        );

        /** @var StubResponseType $response */
        $response = $grant->respondToAccessTokenRequest($request, new StubResponseType(), new DateInterval('PT10M'));

        $this->assertInstanceOf(AccessTokenEntityInterface::class, $response->getAccessToken());
        $this->assertInstanceOf(RefreshTokenEntityInterface::class, $response->getRefreshToken());
    }

    public function testRespondToAccessTokenRequestCodeChallengeS256()
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setRedirectUri('http://foo/bar');
        $client->setConfidential();
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeEntity = new ScopeEntity();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scopeEntity);
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('getNewToken')->willReturn(new AccessTokenEntity());
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('persistNewRefreshToken')->willReturnSelf();
        $refreshTokenRepositoryMock->method('getNewRefreshToken')->willReturn(new RefreshTokenEntity());

        $claimRepositoryMock = $this->getMockBuilder(ClaimRepositoryInterface::class)->getMock();
        $claimRepositoryMock->method('claimsRequestToEntities')->willReturn([new ClaimEntity('sub')]);

        $grant = new AuthCodeGrant(
            $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock(),
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            $claimRepositoryMock,
            new Session,
            new DateInterval('PT10M'),
            new DateInterval('PT10M')
        );

        $grant->setClientRepository($clientRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setRefreshTokenRepository($refreshTokenRepositoryMock);
        $grant->setEncryptionKey($this->cryptStub->getKey());
        $grant->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../../vendor/league/oauth2-server/tests/Stubs/private.key'));

        $request = (new ServerRequest('GET', '/'))->withParsedBody(
            [
                'grant_type'    => 'authorization_code',
                'client_id'     => 'foo',
                'redirect_uri'  => 'http://foo/bar',
                'code_verifier' => self::CODE_VERIFIER,
                'code'          => $this->cryptStub->doEncrypt(
                    \json_encode(
                        [
                            'auth_code_id'          => \uniqid(),
                            'expire_time'           => \time() + 3600,
                            'client_id'             => 'foo',
                            'user_id'               => 123,
                            'redirect_uri'          => 'http://foo/bar',
                            'code_challenge'        => self::CODE_CHALLENGE,
                            'code_challenge_method' => 'S256',

                            'scopes'       => ['foo','openid'],
                            'claims'       => ['given_name'],
                            'nonce'        => '12345',
                            'auth_time'       => (new DateTime())->getTimestamp(),
                            'sessionInformation' => (new SessionInformation())->setAcr('acr')->setAmr('amr')->setAzp('azp')->toJSON()
                        ]
                    )
                ),
            ]
        );

        /** @var StubResponseType $response */
        $response = $grant->respondToAccessTokenRequest($request, new StubResponseType(), new DateInterval('PT10M'));

        $this->assertInstanceOf(AccessTokenEntityInterface::class, $response->getAccessToken());
        $this->assertInstanceOf(RefreshTokenEntityInterface::class, $response->getRefreshToken());
    }

    public function testRespondToAccessTokenRequestMissingRedirectUri()
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setConfidential();
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $claimRepositoryMock = $this->getMockBuilder(ClaimRepositoryInterface::class)->getMock();
        $claimRepositoryMock->method('claimsRequestToEntities')->willReturn([new ClaimEntity('sub')]);

        $grant = new AuthCodeGrant(
            $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock(),
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            $claimRepositoryMock,
            new Session,
            new DateInterval('PT10M'),
            new DateInterval('PT10M')
        );
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setEncryptionKey($this->cryptStub->getKey());

        $request = (new ServerRequest('GET', '/'))->withParsedBody(
            [
                'client_id'  => 'foo',
                'grant_type' => 'authorization_code',
                'code'       => $this->cryptStub->doEncrypt(
                    \json_encode(
                        [
                            'auth_code_id'          => \uniqid(),
                            'expire_time'           => \time() + 3600,
                            'client_id'             => 'foo',
                            'redirect_uri'          => 'http://foo/bar',
                        ]
                    )
                ),
            ]
        );

        $this->expectException(\League\OAuth2\Server\Exception\OAuthServerException::class);
        $this->expectExceptionCode(3);

        $grant->respondToAccessTokenRequest($request, new StubResponseType(), new DateInterval('PT10M'));
    }

    public function testRespondToAccessTokenRequestRedirectUriMismatch()
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setConfidential();
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $claimRepositoryMock = $this->getMockBuilder(ClaimRepositoryInterface::class)->getMock();
        $claimRepositoryMock->method('claimsRequestToEntities')->willReturn([new ClaimEntity('sub')]);

        $grant = new AuthCodeGrant(
            $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock(),
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            $claimRepositoryMock,
            new Session,
            new DateInterval('PT10M'),
            new DateInterval('PT10M')
        );
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setEncryptionKey($this->cryptStub->getKey());

        $request = (new ServerRequest('POST', '/'))->withParsedBody(
            [
                'client_id'  => 'foo',
                'grant_type' => 'authorization_code',
                'redirect_uri' => 'http://bar/foo',
                'code'       => $this->cryptStub->doEncrypt(
                    \json_encode(
                        [
                            'auth_code_id'          => \uniqid(),
                            'expire_time'           => \time() + 3600,
                            'client_id'             => 'foo',
                            'redirect_uri'          => 'http://foo/bar',
                        ]
                    )
                ),
            ]
        );

        $this->expectException(\League\OAuth2\Server\Exception\OAuthServerException::class);
        $this->expectExceptionCode(4);

        $grant->respondToAccessTokenRequest($request, new StubResponseType(), new DateInterval('PT10M'));
    }

    public function testRespondToAccessTokenRequestMissingCode()
    {
        $client = new ClientEntity();
        $client->setRedirectUri('http://foo/bar');
        $client->setConfidential();
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();

        $claimRepositoryMock = $this->getMockBuilder(ClaimRepositoryInterface::class)->getMock();
        $claimRepositoryMock->method('claimsRequestToEntities')->willReturn([new ClaimEntity('sub')]);

        $grant = new AuthCodeGrant(
            $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock(),
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            $claimRepositoryMock,
            new Session,
            new DateInterval('PT10M'),
            new DateInterval('PT10M')
        );
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setRefreshTokenRepository($refreshTokenRepositoryMock);
        $grant->setEncryptionKey($this->cryptStub->getKey());

        $request = (new ServerRequest('POST', '/'))->withParsedBody(
            [
                'grant_type'    => 'authorization_code',
                'client_id'     => 'foo',
                'client_secret' => 'bar',
                'redirect_uri'  => 'http://foo/bar',
            ]
        );

        $this->expectException(\League\OAuth2\Server\Exception\OAuthServerException::class);
        $this->expectExceptionCode(3);

        /* @var StubResponseType $response */
        $grant->respondToAccessTokenRequest($request, new StubResponseType(), new DateInterval('PT10M'));
    }

    public function testRespondToAccessTokenRequestWithRefreshTokenInsteadOfAuthCode()
    {
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn(new ClientEntity());

        $claimRepositoryMock = $this->getMockBuilder(ClaimRepositoryInterface::class)->getMock();
        $claimRepositoryMock->method('claimsRequestToEntities')->willReturn([new ClaimEntity('sub')]);

        $grant = new AuthCodeGrant(
            $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock(),
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            $claimRepositoryMock,
            new Session,
            new DateInterval('PT10M'),
            new DateInterval('PT10M')
        );

        $grant->setClientRepository($clientRepositoryMock);
        $grant->setEncryptionKey($this->cryptStub->getKey());

        $request = (new ServerRequest('GET', '/'))->withParsedBody(
            [
                'grant_type'   => 'authorization_code',
                'client_id'    => 'foo',
                'redirect_uri' => 'http://foo/bar',
                'code'         => $this->cryptStub->doEncrypt(
                    \json_encode(
                        [
                            'client_id'        => 'foo',
                            'refresh_token_id' => 'zyxwvu',
                            'access_token_id'  => 'abcdef',
                            'scopes'           => ['foo'],
                            'user_id'          => 123,
                            'expire_time'      => \time() + 3600,
                        ]
                    )
                ),
            ]
        );

        try {
            /* @var StubResponseType $response */
            $grant->respondToAccessTokenRequest($request, new StubResponseType(), new DateInterval('PT10M'));
        } catch (OAuthServerException $e) {
            $this->assertEquals($e->getHint(), 'Authorization code malformed');
        }
    }

    public function testRespondToAccessTokenRequestExpiredCode()
    {
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn(new ClientEntity());

        $claimRepositoryMock = $this->getMockBuilder(ClaimRepositoryInterface::class)->getMock();
        $claimRepositoryMock->method('claimsRequestToEntities')->willReturn([new ClaimEntity('sub')]);

        $grant = new AuthCodeGrant(
            $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock(),
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            $claimRepositoryMock,
            new Session,
            new DateInterval('PT10M'),
            new DateInterval('PT10M')
        );

        $grant->setClientRepository($clientRepositoryMock);
        $grant->setEncryptionKey($this->cryptStub->getKey());

        $request = (new ServerRequest('GET', '/'))->withParsedBody(
            [
                'grant_type'   => 'authorization_code',
                'client_id'    => 'foo',
                'redirect_uri' => 'http://foo/bar',
                'code'         => $this->cryptStub->doEncrypt(
                    \json_encode(
                        [
                            'auth_code_id' => \uniqid(),
                            'expire_time'  => \time() - 3600,
                            'client_id'    => 'foo',
                            'user_id'      => 123,
                            'scopes'       => ['foo'],
                            'redirect_uri' => 'http://foo/bar',
                        ]
                    )
                ),
            ]
        );

        try {
            /* @var StubResponseType $response */
            $grant->respondToAccessTokenRequest($request, new StubResponseType(), new DateInterval('PT10M'));
        } catch (OAuthServerException $e) {
            $this->assertEquals($e->getHint(), 'Authorization code has expired');
        }
    }

    public function testRespondToAccessTokenRequestRevokedCode()
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setRedirectUri('http://foo/bar');
        $client->setConfidential();
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('persistNewRefreshToken')->willReturnSelf();

        $authCodeRepositoryMock = $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock();
        $authCodeRepositoryMock->method('isAuthCodeRevoked')->willReturn(true);

        $claimRepositoryMock = $this->getMockBuilder(ClaimRepositoryInterface::class)->getMock();
        $claimRepositoryMock->method('claimsRequestToEntities')->willReturn([new ClaimEntity('sub')]);

        $grant = new AuthCodeGrant(
            $authCodeRepositoryMock,
            $refreshTokenRepositoryMock,
            $claimRepositoryMock,
            new Session,
            new DateInterval('PT10M'),
            new DateInterval('PT10M')
        );
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setRefreshTokenRepository($refreshTokenRepositoryMock);
        $grant->setEncryptionKey($this->cryptStub->getKey());

        $request = (new ServerRequest('GET' ,'/'))->withParsedBody(
            [
                'grant_type'   => 'authorization_code',
                'client_id'    => 'foo',
                'redirect_uri' => 'http://foo/bar',
                'code'         => $this->cryptStub->doEncrypt(
                    \json_encode(
                        [
                            'auth_code_id' => \uniqid(),
                            'expire_time'  => \time() + 3600,
                            'client_id'    => 'foo',
                            'user_id'      => 123,
                            'redirect_uri' => 'http://foo/bar',

                            'scopes'       => ['foo','openid'],
                            'claims'       => ['given_name'],
                            'nonce'        => '12345',
                            'auth_time'       => (new DateTime())->getTimestamp(),
                            'sessionInformation' => (new SessionInformation())->setAcr('acr')->setAmr('amr')->setAzp('azp')->toJSON()
                        ]
                    )
                ),
            ]
        );

        try {
            /* @var StubResponseType $response */
            $grant->respondToAccessTokenRequest($request, new StubResponseType(), new DateInterval('PT10M'));
        } catch (OAuthServerException $e) {
            $this->assertEquals($e->getHint(), 'Authorization code has been revoked');
            $this->assertEquals($e->getErrorType(), 'invalid_request');
        }
    }

    public function testRespondToAccessTokenRequestClientMismatch()
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setRedirectUri('http://foo/bar');
        $client->setConfidential();
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('persistNewRefreshToken')->willReturnSelf();

        $claimRepositoryMock = $this->getMockBuilder(ClaimRepositoryInterface::class)->getMock();
        $claimRepositoryMock->method('claimsRequestToEntities')->willReturn([new ClaimEntity('sub')]);

        $grant = new AuthCodeGrant(
            $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock(),
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            $claimRepositoryMock,
            new Session,
            new DateInterval('PT10M'),
            new DateInterval('PT10M')
        );
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setRefreshTokenRepository($refreshTokenRepositoryMock);
        $grant->setEncryptionKey($this->cryptStub->getKey());

        $request = (new ServerRequest('POST', '/'))->withParsedBody(
            [
                'grant_type'   => 'authorization_code',
                'client_id'    => 'foo',
                'redirect_uri' => 'http://foo/bar',
                'code'         => $this->cryptStub->doEncrypt(
                    \json_encode(
                        [
                            'auth_code_id' => \uniqid(),
                            'expire_time'  => \time() + 3600,
                            'client_id'    => 'bar',
                            'user_id'      => 123,
                            'redirect_uri' => 'http://foo/bar',

                            'scopes'       => ['foo','openid'],
                            'claims'       => ['given_name'],
                            'nonce'        => '12345',
                            'auth_time'       => (new DateTime())->getTimestamp(),
                            'sessionInformation' => (new SessionInformation())->setAcr('acr')->setAmr('amr')->setAzp('azp')->toJSON()
                        ]
                    )
                ),
            ]
        );

        try {
            /* @var StubResponseType $response */
            $grant->respondToAccessTokenRequest($request, new StubResponseType(), new DateInterval('PT10M'));
        } catch (OAuthServerException $e) {
            $this->assertEquals($e->getHint(), 'Authorization code was not issued to this client');
        }
    }

    public function testRespondToAccessTokenRequestBadCodeEncryption()
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setRedirectUri('http://foo/bar');
        $client->setConfidential();
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('persistNewRefreshToken')->willReturnSelf();

        $claimRepositoryMock = $this->getMockBuilder(ClaimRepositoryInterface::class)->getMock();
        $claimRepositoryMock->method('claimsRequestToEntities')->willReturn([new ClaimEntity('sub')]);

        $grant = new AuthCodeGrant(
            $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock(),
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            $claimRepositoryMock,
            new Session,
            new DateInterval('PT10M'),
            new DateInterval('PT10M')
        );
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setRefreshTokenRepository($refreshTokenRepositoryMock);
        $grant->setEncryptionKey($this->cryptStub->getKey());

        $request = (new ServerRequest('POST', '/'))->withParsedBody(
            [
                'grant_type'   => 'authorization_code',
                'client_id'    => 'foo',
                'redirect_uri' => 'http://foo/bar',
                'code'         => 'sdfsfsd',
            ]
        );

        try {
            /* @var StubResponseType $response */
            $grant->respondToAccessTokenRequest($request, new StubResponseType(), new DateInterval('PT10M'));
        } catch (OAuthServerException $e) {
            $this->assertEquals($e->getHint(), 'Cannot decrypt the authorization code');
        }
    }

    public function testRespondToAccessTokenRequestBadCodeVerifierPlain()
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setRedirectUri('http://foo/bar');
        $client->setConfidential();
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeEntity = new ScopeEntity();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scopeEntity);
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('getNewToken')->willReturn(new AccessTokenEntity());
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('persistNewRefreshToken')->willReturnSelf();
        $refreshTokenRepositoryMock->method('getNewRefreshToken')->willReturn(new RefreshTokenEntity());

        $claimRepositoryMock = $this->getMockBuilder(ClaimRepositoryInterface::class)->getMock();
        $claimRepositoryMock->method('claimsRequestToEntities')->willReturn([new ClaimEntity('sub')]);

        $grant = new AuthCodeGrant(
            $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock(),
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            $claimRepositoryMock,
            new Session,
            new DateInterval('PT10M'),
            new DateInterval('PT10M')
        );

        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setRefreshTokenRepository($refreshTokenRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setEncryptionKey($this->cryptStub->getKey());

        $request = (new ServerRequest('POST', '/'))->withParsedBody(
            [
                'grant_type'    => 'authorization_code',
                'client_id'     => 'foo',
                'redirect_uri'  => 'http://foo/bar',
                'code_verifier' => self::CODE_VERIFIER,
                'code'          => $this->cryptStub->doEncrypt(
                    \json_encode(
                        [
                            'auth_code_id'          => \uniqid(),
                            'expire_time'           => \time() + 3600,
                            'client_id'             => 'foo',
                            'user_id'               => 123,
                            'scopes'                => ['foo'],
                            'redirect_uri'          => 'http://foo/bar',
                            'code_challenge'        => 'foobar',
                            'code_challenge_method' => 'plain',
                        ]
                    )
                ),
            ]
        );

        try {
            /* @var StubResponseType $response */
            $grant->respondToAccessTokenRequest($request, new StubResponseType(), new DateInterval('PT10M'));
        } catch (OAuthServerException $e) {
            $this->assertEquals($e->getHint(), 'Failed to verify `code_verifier`.');
        }
    }

    public function testRespondToAccessTokenRequestBadCodeVerifierS256()
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setRedirectUri('http://foo/bar');
        $client->setConfidential();
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeEntity = new ScopeEntity();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scopeEntity);
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('getNewToken')->willReturn(new AccessTokenEntity());
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('persistNewRefreshToken')->willReturnSelf();
        $refreshTokenRepositoryMock->method('getNewRefreshToken')->willReturn(new RefreshTokenEntity());

        $claimRepositoryMock = $this->getMockBuilder(ClaimRepositoryInterface::class)->getMock();
        $claimRepositoryMock->method('claimsRequestToEntities')->willReturn([new ClaimEntity('sub')]);

        $grant = new AuthCodeGrant(
            $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock(),
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            $claimRepositoryMock,
            new Session,
            new DateInterval('PT10M'),
            new DateInterval('PT10M')
        );

        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setRefreshTokenRepository($refreshTokenRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setEncryptionKey($this->cryptStub->getKey());

        $request = (new ServerRequest('POST', '/'))->withParsedBody(
            [
                'grant_type'    => 'authorization_code',
                'client_id'     => 'foo',
                'redirect_uri'  => 'http://foo/bar',
                'code_verifier' => 'nope',
                'code'          => $this->cryptStub->doEncrypt(
                    \json_encode(
                        [
                            'auth_code_id'          => \uniqid(),
                            'expire_time'           => \time() + 3600,
                            'client_id'             => 'foo',
                            'user_id'               => 123,
                            'scopes'                => ['foo'],
                            'redirect_uri'          => 'http://foo/bar',
                            'code_challenge'        => 'foobar',
                            'code_challenge_method' => 'S256',
                        ]
                    )
                ),
            ]
        );

        try {
            /* @var StubResponseType $response */
            $grant->respondToAccessTokenRequest($request, new StubResponseType(), new DateInterval('PT10M'));
        } catch (OAuthServerException $e) {
            $this->assertEquals($e->getHint(), 'Code Verifier must follow the specifications of RFC-7636.');
        }
    }

    public function testRespondToAccessTokenRequestMalformedCodeVerifierS256WithInvalidChars()
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setRedirectUri('http://foo/bar');
        $client->setConfidential();
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeEntity = new ScopeEntity();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scopeEntity);
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('getNewToken')->willReturn(new AccessTokenEntity());
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('persistNewRefreshToken')->willReturnSelf();
        $refreshTokenRepositoryMock->method('getNewRefreshToken')->willReturn(new RefreshTokenEntity());

        $claimRepositoryMock = $this->getMockBuilder(ClaimRepositoryInterface::class)->getMock();
        $claimRepositoryMock->method('claimsRequestToEntities')->willReturn([new ClaimEntity('sub')]);

        $grant = new AuthCodeGrant(
            $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock(),
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            $claimRepositoryMock,
            new Session,
            new DateInterval('PT10M'),
            new DateInterval('PT10M')
        );

        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setRefreshTokenRepository($refreshTokenRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setEncryptionKey($this->cryptStub->getKey());

        $request = (new ServerRequest('POST', '/'))->withParsedBody(
            [
                'grant_type'    => 'authorization_code',
                'client_id'     => 'foo',
                'redirect_uri'  => 'http://foo/bar',
                'code_verifier' => 'dqX7C-RbqjHYtytmhGTigKdZCXfxq-+xbsk9_GxUcaE', // Malformed code. Contains `+`.
                'code'          => $this->cryptStub->doEncrypt(
                    \json_encode(
                        [
                            'auth_code_id'          => \uniqid(),
                            'expire_time'           => \time() + 3600,
                            'client_id'             => 'foo',
                            'user_id'               => 123,
                            'scopes'                => ['foo'],
                            'redirect_uri'          => 'http://foo/bar',
                            'code_challenge'        => self::CODE_CHALLENGE,
                            'code_challenge_method' => 'S256',
                        ]
                    )
                ),
            ]
        );

        try {
            /* @var StubResponseType $response */
            $grant->respondToAccessTokenRequest($request, new StubResponseType(), new DateInterval('PT10M'));
        } catch (OAuthServerException $e) {
            $this->assertEquals($e->getHint(), 'Code Verifier must follow the specifications of RFC-7636.');
        }
    }

    public function testRespondToAccessTokenRequestMalformedCodeVerifierS256WithInvalidLength()
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setRedirectUri('http://foo/bar');
        $client->setConfidential();
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeEntity = new ScopeEntity();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scopeEntity);
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('getNewToken')->willReturn(new AccessTokenEntity());
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('persistNewRefreshToken')->willReturnSelf();
        $refreshTokenRepositoryMock->method('getNewRefreshToken')->willReturn(new RefreshTokenEntity());

        $claimRepositoryMock = $this->getMockBuilder(ClaimRepositoryInterface::class)->getMock();
        $claimRepositoryMock->method('claimsRequestToEntities')->willReturn([new ClaimEntity('sub')]);

        $grant = new AuthCodeGrant(
            $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock(),
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            $claimRepositoryMock,
            new Session,
            new DateInterval('PT10M'),
            new DateInterval('PT10M')
        );

        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setRefreshTokenRepository($refreshTokenRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setEncryptionKey($this->cryptStub->getKey());

        $request = (new ServerRequest('POST', '/'))->withParsedBody(
            [
                'grant_type'    => 'authorization_code',
                'client_id'     => 'foo',
                'redirect_uri'  => 'http://foo/bar',
                'code_verifier' => 'dqX7C-RbqjHY', // Malformed code. Invalid length.
                'code'          => $this->cryptStub->doEncrypt(
                    \json_encode(
                        [
                            'auth_code_id'          => \uniqid(),
                            'expire_time'           => \time() + 3600,
                            'client_id'             => 'foo',
                            'user_id'               => 123,
                            'scopes'                => ['foo'],
                            'redirect_uri'          => 'http://foo/bar',
                            'code_challenge'        => 'R7T1y1HPNFvs1WDCrx4lfoBS6KD2c71pr8OHvULjvv8',
                            'code_challenge_method' => 'S256',
                        ]
                    )
                ),
            ]
        );

        try {
            /* @var StubResponseType $response */
            $grant->respondToAccessTokenRequest($request, new StubResponseType(), new DateInterval('PT10M'));
        } catch (OAuthServerException $e) {
            $this->assertEquals($e->getHint(), 'Code Verifier must follow the specifications of RFC-7636.');
        }
    }

    public function testRespondToAccessTokenRequestMissingCodeVerifier()
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setRedirectUri('http://foo/bar');
        $client->setConfidential();
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeEntity = new ScopeEntity();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scopeEntity);
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('getNewToken')->willReturn(new AccessTokenEntity());
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('persistNewRefreshToken')->willReturnSelf();
        $refreshTokenRepositoryMock->method('getNewRefreshToken')->willReturn(new RefreshTokenEntity());

        $claimRepositoryMock = $this->getMockBuilder(ClaimRepositoryInterface::class)->getMock();
        $claimRepositoryMock->method('claimsRequestToEntities')->willReturn([new ClaimEntity('sub')]);

        $grant = new AuthCodeGrant(
            $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock(),
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            $claimRepositoryMock,
            new Session,
            new DateInterval('PT10M'),
            new DateInterval('PT10M')
        );

        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setRefreshTokenRepository($refreshTokenRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setEncryptionKey($this->cryptStub->getKey());

        $request = (new ServerRequest('POST', '/'))->withParsedBody(
            [
                'grant_type'   => 'authorization_code',
                'client_id'    => 'foo',
                'redirect_uri' => 'http://foo/bar',
                'code'         => $this->cryptStub->doEncrypt(
                    \json_encode(
                        [
                            'auth_code_id'          => \uniqid(),
                            'expire_time'           => \time() + 3600,
                            'client_id'             => 'foo',
                            'user_id'               => 123,
                            'scopes'                => ['foo'],
                            'redirect_uri'          => 'http://foo/bar',
                            'code_challenge'        => 'foobar',
                            'code_challenge_method' => 'plain',
                        ]
                    )
                ),
            ]
        );

        try {
            /* @var StubResponseType $response */
            $grant->respondToAccessTokenRequest($request, new StubResponseType(), new DateInterval('PT10M'));
        } catch (OAuthServerException $e) {
            $this->assertEquals($e->getHint(), 'Check the `code_verifier` parameter');
        }
    }

    public function testAuthCodeRepositoryUniqueConstraintCheck()
    {
        $authRequest = new AuthenticationRequest();
        $authRequest->setAuthorizationApproved(true);
        $authRequest->setClient(new ClientEntity());
        $authRequest->setGrantTypeId('authorization_code');
        $authRequest->setUser(new UserEntity());
        $authRequest->setRedirectUri('http://redirect/destination');
        $authRequest->setResponseType('code');

        $authCodeRepository = $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock();
        $authCodeRepository->method('getNewAuthCode')->willReturn(new AuthCodeEntity());

        $authCodeRepository->expects($this->at(0))->method('persistNewAuthCode')->willThrowException(UniqueTokenIdentifierConstraintViolationException::create());
        $authCodeRepository->expects($this->at(1))->method('persistNewAuthCode');

        $claimRepositoryMock = $this->getMockBuilder(ClaimRepositoryInterface::class)->getMock();
        $claimRepositoryMock->method('claimsRequestToEntities')->willReturn([new ClaimEntity('sub')]);

        $grant = new AuthCodeGrant(
            $authCodeRepository,
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            $claimRepositoryMock,
            new Session,
            new DateInterval('PT10M'),
            new DateInterval('PT10M')
        );

        $grant->setEncryptionKey($this->cryptStub->getKey());
        $grant->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../../vendor/league/oauth2-server/tests/Stubs/private.key'));

        $this->assertInstanceOf(RedirectResponse::class, $grant->completeAuthorizationRequest($authRequest));
    }

    public function testAuthCodeRepositoryFailToPersist()
    {
        $authRequest = new AuthenticationRequest();
        $authRequest->setAuthorizationApproved(true);
        $authRequest->setClient(new ClientEntity());
        $authRequest->setGrantTypeId('authorization_code');
        $authRequest->setUser(new UserEntity());
        $authRequest->setRedirectUri('http://redirect/destination');
        $authRequest->setResponseType('code');

        $authCodeRepository = $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock();
        $authCodeRepository->method('getNewAuthCode')->willReturn(new AuthCodeEntity());
        $authCodeRepository->method('persistNewAuthCode')->willThrowException(OAuthServerException::serverError('something bad happened'));

        $claimRepositoryMock = $this->getMockBuilder(ClaimRepositoryInterface::class)->getMock();
        $claimRepositoryMock->method('claimsRequestToEntities')->willReturn([new ClaimEntity('sub')]);

        $grant = new AuthCodeGrant(
            $authCodeRepository,
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            $claimRepositoryMock,
            new Session,
            new DateInterval('PT10M'),
            new DateInterval('PT10M')
        );
        $grant->setEncryptionKey($this->cryptStub->getKey());

        $this->expectException(\League\OAuth2\Server\Exception\OAuthServerException::class);
        $this->expectExceptionCode(7);

        $this->assertInstanceOf(RedirectResponse::class, $grant->completeAuthorizationRequest($authRequest));
    }

    public function testAuthCodeRepositoryFailToPersistUniqueNoInfiniteLoop()
    {
        $authRequest = new AuthenticationRequest();
        $authRequest->setAuthorizationApproved(true);
        $authRequest->setClient(new ClientEntity());
        $authRequest->setGrantTypeId('authorization_code');
        $authRequest->setUser(new UserEntity());
        $authRequest->setRedirectUri('http://redirect/destination');
        $authRequest->setResponseType('code');

        $authCodeRepository = $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock();
        $authCodeRepository->method('getNewAuthCode')->willReturn(new AuthCodeEntity());
        $authCodeRepository->method('persistNewAuthCode')->willThrowException(UniqueTokenIdentifierConstraintViolationException::create());

        $claimRepositoryMock = $this->getMockBuilder(ClaimRepositoryInterface::class)->getMock();
        $claimRepositoryMock->method('claimsRequestToEntities')->willReturn([new ClaimEntity('sub')]);

        $grant = new AuthCodeGrant(
            $authCodeRepository,
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            $claimRepositoryMock,
            new Session,
            new DateInterval('PT10M'),
            new DateInterval('PT10M')
        );

        $this->expectException(\League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException::class);
        $this->expectExceptionCode(100);

        $this->assertInstanceOf(RedirectResponse::class, $grant->completeAuthorizationRequest($authRequest));
    }

    public function testRefreshTokenRepositoryUniqueConstraintCheck()
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setRedirectUri('http://foo/bar');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeEntity = new ScopeEntity();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scopeEntity);
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('getNewToken')->willReturn(new AccessTokenEntity());
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('getNewRefreshToken')->willReturn(new RefreshTokenEntity());
        $refreshTokenRepositoryMock->expects($this->at(0))->method('persistNewRefreshToken')->willThrowException(UniqueTokenIdentifierConstraintViolationException::create());
        $refreshTokenRepositoryMock->expects($this->at(1))->method('persistNewRefreshToken');

        $claimRepositoryMock = $this->getMockBuilder(ClaimRepositoryInterface::class)->getMock();
        $claimRepositoryMock->method('claimsRequestToEntities')->willReturn([new ClaimEntity('sub')]);

        $grant = new AuthCodeGrant(
            $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock(),
            $refreshTokenRepositoryMock,
            $claimRepositoryMock,
            new Session,
            new DateInterval('PT10M'),
            new DateInterval('PT10M')
        );
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setRefreshTokenRepository($refreshTokenRepositoryMock);
        $grant->setEncryptionKey($this->cryptStub->getKey());
        $grant->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../../vendor/league/oauth2-server/tests/Stubs/private.key'));

        $request = (new ServerRequest('POST', '/'))->withParsedBody(
            [
                'grant_type'   => 'authorization_code',
                'client_id'    => 'foo',
                'redirect_uri' => 'http://foo/bar',
                'code'         => $this->cryptStub->doEncrypt(
                    \json_encode(
                        [
                            'auth_code_id' => \uniqid(),
                            'expire_time'  => \time() + 3600,
                            'client_id'    => 'foo',
                            'user_id'      => 123,
                            'redirect_uri' => 'http://foo/bar',

                            'scopes'       => ['foo','openid'],
                            'claims'       => ['given_name'],
                            'nonce'        => '12345',
                            'auth_time'       => (new DateTime())->getTimestamp(),
                            'sessionInformation' => (new SessionInformation())->setAcr('acr')->setAmr('amr')->setAzp('azp')->toJSON()
                        ]
                    )
                ),
            ]
        );

        /** @var StubResponseType $response */
        $response = $grant->respondToAccessTokenRequest($request, new StubResponseType(), new DateInterval('PT10M'));

        $this->assertInstanceOf(AccessTokenEntityInterface::class, $response->getAccessToken());
        $this->assertInstanceOf(RefreshTokenEntityInterface::class, $response->getRefreshToken());
    }

    public function testRefreshTokenRepositoryFailToPersist()
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setRedirectUri('http://foo/bar');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeEntity = new ScopeEntity();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scopeEntity);
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('getNewToken')->willReturn(new AccessTokenEntity());
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('getNewRefreshToken')->willReturn(new RefreshTokenEntity());
        $refreshTokenRepositoryMock->method('persistNewRefreshToken')->willThrowException(OAuthServerException::serverError('something bad happened'));

        $claimRepositoryMock = $this->getMockBuilder(ClaimRepositoryInterface::class)->getMock();
        $claimRepositoryMock->method('claimsRequestToEntities')->willReturn([new ClaimEntity('sub')]);

        $grant = new AuthCodeGrant(
            $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock(),
            $refreshTokenRepositoryMock,
            $claimRepositoryMock,
            new Session,
            new DateInterval('PT10M'),
            new DateInterval('PT10M')
        );
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setRefreshTokenRepository($refreshTokenRepositoryMock);
        $grant->setEncryptionKey($this->cryptStub->getKey());
        $grant->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../../vendor/league/oauth2-server/tests/Stubs/private.key'));

        $request = (new ServerRequest('POST', '/'))->withParsedBody(
            [
                'grant_type'   => 'authorization_code',
                'client_id'    => 'foo',
                'redirect_uri' => 'http://foo/bar',
                'code'         => $this->cryptStub->doEncrypt(
                    \json_encode(
                        [
                            'auth_code_id' => \uniqid(),
                            'expire_time'  => \time() + 3600,
                            'client_id'    => 'foo',
                            'user_id'      => 123,
                            'redirect_uri' => 'http://foo/bar',

                            'scopes'       => ['foo','openid'],
                            'claims'       => ['given_name'],
                            'nonce'        => '12345',
                            'auth_time'       => (new DateTime())->getTimestamp(),
                            'sessionInformation' => (new SessionInformation())->setAcr('acr')->setAmr('amr')->setAzp('azp')->toJSON()
                        ]
                    )
                ),
            ]
        );

        $this->expectException(\League\OAuth2\Server\Exception\OAuthServerException::class);
        $this->expectExceptionCode(7);

        /** @var StubResponseType $response */
        $response = $grant->respondToAccessTokenRequest($request, new StubResponseType(), new DateInterval('PT10M'));

        $this->assertInstanceOf(AccessTokenEntityInterface::class, $response->getAccessToken());
        $this->assertInstanceOf(RefreshTokenEntityInterface::class, $response->getRefreshToken());
    }

    public function testRefreshTokenRepositoryFailToPersistUniqueNoInfiniteLoop()
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setRedirectUri('http://foo/bar');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeEntity = new ScopeEntity();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scopeEntity);
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('getNewToken')->willReturn(new AccessTokenEntity());
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('getNewRefreshToken')->willReturn(new RefreshTokenEntity());
        $refreshTokenRepositoryMock->method('persistNewRefreshToken')->willThrowException(UniqueTokenIdentifierConstraintViolationException::create());

        $claimRepositoryMock = $this->getMockBuilder(ClaimRepositoryInterface::class)->getMock();
        $claimRepositoryMock->method('claimsRequestToEntities')->willReturn([new ClaimEntity('sub')]);

        $grant = new AuthCodeGrant(
            $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock(),
            $refreshTokenRepositoryMock,
            $claimRepositoryMock,
            new Session,
            new DateInterval('PT10M'),
            new DateInterval('PT10M')
        );
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setRefreshTokenRepository($refreshTokenRepositoryMock);
        $grant->setEncryptionKey($this->cryptStub->getKey());
        $grant->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../../vendor/league/oauth2-server/tests/Stubs/private.key'));

        $request = (new ServerRequest('POST', '/'))->withParsedBody(
            [
                'grant_type'   => 'authorization_code',
                'client_id'    => 'foo',
                'redirect_uri' => 'http://foo/bar',
                'code'         => $this->cryptStub->doEncrypt(
                    \json_encode(
                        [
                            'auth_code_id' => \uniqid(),
                            'expire_time'  => \time() + 3600,
                            'client_id'    => 'foo',
                            'user_id'      => 123,
                            'scopes'       => ['foo'],
                            'redirect_uri' => 'http://foo/bar',

                            'scopes'       => ['foo','openid'],
                            'claims'       => ['given_name'],
                            'nonce'        => '12345',
                            'auth_time'       => (new DateTime())->getTimestamp(),
                            'sessionInformation' => (new SessionInformation())->setAcr('acr')->setAmr('amr')->setAzp('azp')->toJSON()
                        ]
                    )
                ),
            ]
        );

        $this->expectException(UniqueTokenIdentifierConstraintViolationException::class);
        $this->expectExceptionCode(100);

        /** @var StubResponseType $response */
        $response = $grant->respondToAccessTokenRequest($request, new StubResponseType(), new DateInterval('PT10M'));

        $this->assertInstanceOf(AccessTokenEntityInterface::class, $response->getAccessToken());
        $this->assertInstanceOf(RefreshTokenEntityInterface::class, $response->getRefreshToken());
    }

    public function testCompleteAuthorizationRequestNoUser()
    {
        $claimRepositoryMock = $this->getMockBuilder(ClaimRepositoryInterface::class)->getMock();
        $claimRepositoryMock->method('claimsRequestToEntities')->willReturn([new ClaimEntity('sub')]);

        $grant = new AuthCodeGrant(
            $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock(),
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            $claimRepositoryMock,
            new Session,
            new DateInterval('PT10M'),
            new DateInterval('PT10M')
        );

        $this->expectException(\LogicException::class);

        $grant->completeAuthorizationRequest(new AuthenticationRequest());
    }

    public function testPublicClientAuthCodeRequestRejectedWhenCodeChallengeRequiredButNotGiven()
    {
        $client = new ClientEntity();
        $client->setRedirectUri('http://foo/bar');

        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $scope = new ScopeEntity();
        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scope);

        $claimRepositoryMock = $this->getMockBuilder(ClaimRepositoryInterface::class)->getMock();
        $claimRepositoryMock->method('claimsRequestToEntities')->willReturn([new ClaimEntity('sub')]);

        $grant = new AuthCodeGrant(
            $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock(),
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            $claimRepositoryMock,
            new Session,
            new DateInterval('PT10M'),
            new DateInterval('PT10M'),
            false
        );

        $grant->setClientRepository($clientRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setDefaultScope(self::DEFAULT_SCOPE);

        $request = (new ServerRequest('GET', '/'))->withQueryParams([
            'response_type' => 'code',
            'client_id'     => 'foo',
            'redirect_uri'  => 'http://foo/bar',
        ]);

        $this->expectException(OAuthServerException::class);
        $this->expectExceptionCode(3);

        $grant->validateAuthorizationRequest($request);
    }
}
