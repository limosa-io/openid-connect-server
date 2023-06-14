<?php

namespace IdaasTests;

use Idaas\OpenID\Entities\IdToken;
use League\OAuth2\Server\CryptKey;
use PHPUnit\Framework\TestCase;

class IDTokenTest extends TestCase
{
    public function testConverToJwt()
    {
        $cryptKey = $this->getMockBuilder(CryptKey::class)->setConstructorArgs([
            __DIR__ . '/../vendor/league/oauth2-server/tests/Stubs/private.key'
        ])->getMock();

        $cryptKey->method('getKeyPath')
            ->willReturn(__DIR__ . '/../vendor/league/oauth2-server/tests/Stubs/private.key');

        $cryptKey->method('getKeyContents')
            ->willReturn(file_get_contents(__DIR__ . '/../vendor/league/oauth2-server/tests/Stubs/private.key'));

        $idToken = new IdToken();
        $idToken->setIssuer('issuer');
        
        $this->assertEquals($idToken->getIssuer(), 'issuer');

        $idToken->setSubject('123');
        $this->assertEquals($idToken->getSubject(), '123');
        $idToken->setAudience('audience');

        $idToken->setExpiration((new \DateTimeImmutable()));
        $idToken->setIat(new \DateTimeImmutable());
        $idToken->setAuthTime(new \DateTime());
        $idToken->setNonce('nonce');
        $idToken->setAmr('amr');
        $idToken->setAcr('acr');
        $idToken->setIdentifier('identifier');

        $token = $idToken->convertToJWT($cryptKey)->toString();

        $this->assertNotNull($token);
        $this->assertIsString($token);

        $parts = explode('.', $token);
        $this->assertEquals(3, count($parts));

        //assert is base64
        $this->assertEquals($parts[1], rtrim(base64_encode(base64_decode($parts[1], true)), '='));

        $decoded = base64_decode($parts[1], true);
        $this->assertJson($decoded);
        $assoc = json_decode($decoded, true);

        $this->assertArrayHasKey('sub', $assoc);
        $this->assertArrayHasKey('iss', $assoc);
        $this->assertArrayHasKey('jti', $assoc);
        $this->assertArrayHasKey('exp', $assoc);
        $this->assertArrayHasKey('iat', $assoc);
        $this->assertArrayHasKey('auth_time', $assoc);
        $this->assertArrayHasKey('nonce', $assoc);
    }
}
