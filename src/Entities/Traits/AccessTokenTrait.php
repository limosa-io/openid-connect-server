<?php

namespace Idaas\OpenID\Entities\Traits;

use Idaas\OpenID\Entities\ClaimEntityInterface;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Signer\Key;
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
        return (new Builder())
            ->permittedFor($this->getClient()->getIdentifier())
            ->identifiedBy($this->getIdentifier())
            ->issuedAt(\time())
            ->canOnlyBeUsedAfter(\time())
            ->expiresAt($this->getExpiryDateTime()->getTimestamp())
            ->relatedTo((string) $this->getUserIdentifier())
            ->withClaim('scopes', $this->getScopes())
            ->withClaim('claims', $this->getClaims())
            ->getToken(new Sha256(), new Key($privateKey->getKeyPath(), $privateKey->getPassPhrase()));
    }

    /**
     * @return ClaimEntityInterface[]
     */
    abstract public function getClaims();
}
