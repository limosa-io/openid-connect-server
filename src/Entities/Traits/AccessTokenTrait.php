<?php

namespace Idaas\OpenID\Entities\Traits;

use Idaas\OpenID\Entities\ClaimEntityInterface;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Entities\Traits\AccessTokenTrait as LeagueAccessTokenTrait;

trait AccessTokenTrait
{
    use LeagueAccessTokenTrait {
        LeagueAccessTokenTrait::convertToJWT as parentConvertToJWT;
    }

    private function convertToJWT(CryptKey $privateKey)
    {
        $config = Configuration::forAsymmetricSigner(
            new Sha256(),
            InMemory::plainText($privateKey->getKeyContents(), $privateKey->getPassPhrase() ?? ''),
            InMemory::plainText('empty', 'empty')
        );

        $builder = $config->builder();

        return $builder
            ->permittedFor($this->getClient()->getIdentifier())
            ->identifiedBy($this->getIdentifier())
            // issuedAt now receives a \DateTimeImmutable object instead of int.
            ->issuedAt(new \DateTimeImmutable())
            // canOnlyBeUsedAfter now receives a \DateTimeImmutable object instead of int.
            ->canOnlyBeUsedAfter(new \DateTimeImmutable())
            // expiresAt now receives a \DateTimeImmutable object instead of int.
            ->expiresAt($this->getExpiryDateTime())
            ->relatedTo((string) $this->getUserIdentifier())
            ->withClaim('scopes', $this->getScopes())
            ->withClaim('claims', $this->getClaims())
            ->getToken($config->signer(), $config->signingKey());
    }

    /**
     * @return ClaimEntityInterface[]
     */
    abstract public function getClaims();
}
