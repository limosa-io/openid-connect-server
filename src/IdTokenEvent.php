<?php

namespace Idaas\OpenID;

use Idaas\OpenID\Entities\IdToken;
use League\Event\Event;
use League\OAuth2\Server\Grant\GrantTypeInterface;
use Psr\EventDispatcher\StoppableEventInterface;

if (class_exists(Event::class)) {
    class IdTokenEvent extends Event
    {
        use IdTokenEventTrait;

        public const TOKEN_POPULATED = 'id_token.populated';

        public function __construct($name, IdToken $idToken, GrantTypeInterface $grantType)
        {
            parent::__construct($name);
            $this->idToken = $idToken;
            $this->grantType = $grantType;
        }
    }
} else {
    class IdTokenEvent implements StoppableEventInterface
    {
        use IdTokenEventTrait;

        public const TOKEN_POPULATED = 'id_token.populated';

        /**
         * @var string
         */
        private $name;

        /**
         * @var bool
         */
        protected $propagationStopped = false;

        public function __construct($name, IdToken $idToken, GrantTypeInterface $grantType)
        {
            $this->name = $name;
            $this->idToken = $idToken;
            $this->grantType = $grantType;
        }

        /**
         * @return $this
         */
        public function stopPropagation()
        {
            $this->propagationStopped = true;

            return $this;
        }

        public function isPropagationStopped(): bool
        {
            return $this->propagationStopped;
        }

        /**
         * @return string
         */
        public function getName()
        {
            return $this->name;
        }
    }
}
