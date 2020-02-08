<?php

namespace Idaas\OpenID;

class SessionInformation
{
    public $acr;
    public $amr;
    public $azp;

    public static function fromJSON($json)
    {
        $json = \json_decode($json);

        $result = new self();

        $result->setAzp($json->azp);
        $result->setAcr($json->acr);
        $result->setAzp($json->azp);

        return $result;
    }

    public function toJSON()
    {
        return json_encode(['acr'=>$this->acr, 'amr'=>$this->amr,'azp'=>$this->azp]);
    }

    public function __toString()
    {
        return $this->toJSON();
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
}
