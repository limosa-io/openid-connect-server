<?php

namespace Idaas\OpenID\Entities;

use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use League\OAuth2\Server\CryptKey;

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
        $this->iat = time();
        $this->authTime = time();
    }

    public function convertToJWT(CryptKey $privateKey)
    {

        $token = (new Builder())

            ->setHeader('kid', method_exists($privateKey, 'getKid') ? $privateKey->getKid() : null)
            ->setIssuer($this->getIssuer())
            ->setSubject($this->getSubject())
            ->setAudience($this->getAudience())
            ->setExpiration($this->getExpiration()->getTimestamp())
            ->setIssuedAt($this->getIat()->getTimestamp())
            ->set('auth_time', $this->getAuthTime()->getTimestamp())
            ->set('nonce', $this->getNonce());

        foreach ($this->extra as $key => $value) {
            $token->set($key, $value);
        }

        return $token
            ->sign(new Sha256(), new Key($privateKey->getKeyPath(), $privateKey->getPassPhrase()))
            ->getToken();
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
    public function setIat(\DateTime $iat)
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
