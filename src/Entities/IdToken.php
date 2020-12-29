<?php

namespace Idaas\OpenID\Entities;

use DateTimeImmutable;
use Lcobucci\JWT\Configuration;
use League\OAuth2\Server\CryptKey;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key\LocalFileReference;

class IdToken
{
    protected $issuer;
    protected $subject;
    protected $audience;
    protected $expiration;
    protected $iat; // Time at which the JWT was issued
    protected $authTime;
    protected $nonce;
    protected $acr; // Authentication Context Class Reference
    protected $amr; // Authentication Methods References
    protected $azp; // Authorized party

    protected $extra = [];

    public function __construct()
    {
        $this->iat = new DateTimeImmutable();
        $this->authTime = new DateTimeImmutable();
    }

    public function convertToJWT(CryptKey $privateKey)
    {
        $configuration = Configuration::forAsymmetricSigner(
            // You may use RSA or ECDSA and all their variations (256, 384, and 512)
            new Signer\Rsa\Sha256(),
            LocalFileReference::file($privateKey->getKeyPath()),
            LocalFileReference::file($privateKey->getKeyPath())
            // You may also override the JOSE encoder/decoder if needed by providing extra arguments here
        );

        $token = $configuration->builder()
            ->withHeader('kid', method_exists($privateKey, 'getKid') ? $privateKey->getKid() : null)
            ->issuedBy($this->getIssuer())
            ->identifiedBy($this->getSubject())
            ->permittedFor($this->getAudience())
            ->relatedTo($this->getSubject())
            ->expiresAt(DateTimeImmutable::createFromMutable($this->getExpiration()))
            ->issuedAt($this->getIat())
            ->withClaim('auth_time', $this->getAuthTime()->getTimestamp())
            ->withClaim('nonce', $this->getNonce());

        foreach ($this->extra as $key => $value) {
            $token->withClaim($key, $value);
        }

        return $token->getToken($configuration->signer(), $configuration->signingKey())->toString();
    }


    /**
     * Get the value of subject
     */
    public function getSubject()
    {
        return $this->subject;
    }

    /**
     * Set the value of subject
     *
     * @return  self
     */
    public function setSubject($subject)
    {
        $this->subject = $subject;

        return $this;
    }

    /**
     * Get the value of audience
     */
    public function getAudience()
    {
        return $this->audience;
    }

    /**
     * Set the value of audience
     *
     * @return  self
     */
    public function setAudience($audience)
    {
        $this->audience = $audience;

        return $this;
    }

    /**
     * Get the value of expiration
     */
    public function getExpiration()
    {
        return $this->expiration;
    }

    /**
     * Set the value of expiration
     *
     * @return  self
     */
    public function setExpiration(\DateTime $expiration)
    {
        $this->expiration = $expiration;

        return $this;
    }

    /**
     * Get the value of iat
     */
    public function getIat()
    {
        return $this->iat;
    }

    /**
     * Set the value of iat
     *
     * @return  self
     */
    public function setIat(\DateTimeImmutable $iat)
    {
        $this->iat = $iat;

        return $this;
    }

    /**
     * Get the value of authTime
     */
    public function getAuthTime()
    {
        return $this->authTime;
    }

    /**
     * Set the value of authTime
     *
     * @return  self
     */
    public function setAuthTime(\DateTime $authTime)
    {
        $this->authTime = $authTime;

        return $this;
    }

    /**
     * Get the value of nonce
     */
    public function getNonce()
    {
        return $this->nonce;
    }

    /**
     * Set the value of nonce
     *
     * @return  self
     */
    public function setNonce($nonce)
    {
        $this->nonce = $nonce;

        return $this;
    }

    /**
     * Get the value of acr
     */
    public function getAcr()
    {
        return $this->acr;
    }

    /**
     * Set the value of acr
     *
     * @return  self
     */
    public function setAcr($acr)
    {
        $this->acr = $acr;

        return $this;
    }

    /**
     * Get the value of amr
     */
    public function getAmr()
    {
        return $this->amr;
    }

    /**
     * Set the value of amr
     *
     * @return  self
     */
    public function setAmr($amr)
    {
        $this->amr = $amr;

        return $this;
    }

    /**
     * Get the value of azp
     */
    public function getAzp()
    {
        return $this->azp;
    }

    /**
     * Set the value of azp
     *
     * @return  self
     */
    public function setAzp($azp)
    {
        $this->azp = $azp;

        return $this;
    }

    /**
     * Get the value of issuer
     */
    public function getIssuer()
    {
        return $this->issuer;
    }

    /**
     * Set the value of issuer
     *
     * @return  self
     */
    public function setIssuer($issuer)
    {
        $this->issuer = $issuer;

        return $this;
    }

    public function addExtra($key, $value)
    {
        $this->extra[$key] = $value;
    }
}
