<?php

namespace Idaas\OpenID\Grant;

use Idaas\OpenID\Entities\IdToken;
use Idaas\OpenID\IdTokenEvent;
use Idaas\OpenID\Repositories\AccessTokenRepositoryInterface;
use Idaas\OpenID\Repositories\ClaimRepositoryInterface;
use Idaas\OpenID\RequestTypes\AuthenticationRequest;
use Idaas\OpenID\ResponseHandler;
use Idaas\OpenID\ResponseTypes\BearerTokenResponse;
use Idaas\OpenID\SessionInterface;
use Idaas\OpenID\SessionInformation;
use League\OAuth2\Server\Entities\UserEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use LogicException;
use Psr\Http\Message\ServerRequestInterface;

class AuthCodeGrant extends \League\OAuth2\Server\Grant\AuthCodeGrant
{
    use OIDCTrait;

    protected $authCodeTTL;

    protected $idTokenTTL;

    protected $session;

    protected $claimRepository;

    /**
     * @var AccessTokenRepositoryInterface
     */
    protected $accessTokenRepository;

    /**
     * @param AuthCodeRepositoryInterface     $authCodeRepository
     * @param RefreshTokenRepositoryInterface $refreshTokenRepository
     * @param \DateInterval                   $authCodeTTL
     */
    public function __construct(
        AuthCodeRepositoryInterface $authCodeRepository,
        RefreshTokenRepositoryInterface $refreshTokenRepository,
        ClaimRepositoryInterface $claimRepository,
        SessionInterface $session,
        \DateInterval $authCodeTTL,
        \DateInterval $idTokenTTL,
        $disableRequireCodeChallengeForPublicClients = true
    ) {
        parent::__construct($authCodeRepository, $refreshTokenRepository, $authCodeTTL);

        $this->claimRepository = $claimRepository;

        $this->authCodeTTL = $authCodeTTL;
        $this->idTokenTTL = $idTokenTTL;
        $this->session = $session;

        if ($disableRequireCodeChallengeForPublicClients) {
            $this->disableRequireCodeChallengeForPublicClients();
        }
    }

    public function getIdentifier()
    {
        return 'authorization_code_oidc';
    }

    /**
     * {@inheritdoc}
     */
    public function canRespondToAuthorizationRequest(ServerRequestInterface $request)
    {
        $result = parent::canRespondToAuthorizationRequest($request);

        $queryParams = $request->getQueryParams();
        $scopes = ($queryParams && isset($queryParams['scope'])) ? $queryParams['scope'] : null;

        $result = $result && ($scopes && in_array('openid', explode(' ', $scopes)));

        return $result;
    }

    public function canRespondToAccessTokenRequest(ServerRequestInterface $request)
    {
        $requestParameters = (array) $request->getParsedBody();

        // Don't try to handle code when it isn't even an authorization_code request
        if (!array_key_exists('grant_type', $requestParameters)
            || $requestParameters['grant_type'] !== 'authorization_code'
        ) {
            return false;
        }

        if (!array_key_exists('code', $requestParameters)) {
            return false;
        }

        try {
            $authCodePayload = json_decode($this->decrypt($requestParameters['code']));
        } catch (LogicException $e) {
            return false;
        }

        return isset($authCodePayload->scopes) && in_array('openid', $authCodePayload->scopes);
    }

    /**
     * {@inheritdoc}
     */
    public function validateAuthorizationRequest(ServerRequestInterface $request)
    {
        $result = parent::validateAuthorizationRequest($request);
        
        $redirectUri = $this->getQueryStringParameter(
            'redirect_uri',
            $request
        );

        //In constract with OAuth 2.0, in OIDC, the redirect_uri parameter is required
        if (is_null($redirectUri)) {
            throw OAuthServerException::invalidRequest('redirect_uri');
        }

        $result = AuthenticationRequest::fromAuthorizationRequest($result);

        $result->setNonce($this->getQueryStringParameter('nonce', $request));

        // When max_age is used, the ID Token returned MUST include an auth_time Claim Value
        $maxAge = $this->getQueryStringParameter('max_age', $request);

        if (!empty($maxAge) && !is_numeric($maxAge)) {
            throw OAuthServerException::invalidRequest('max_age', 'max_age must be numeric');
        }

        $result->setMaxAge($maxAge);

        $result->setPrompt($this->getQueryStringParameter('prompt', $request));
        $result->setResponseMode($this->getQueryStringParameter('response_mode', $request));
        $result->setResponseType($this->getQueryStringParameter('response_type', $request));

        if (!empty($uiLocales = $this->getQueryStringParameter('ui_locales', $request))) {
            $result->setUILocales(explode(' ', $uiLocales));
        }

        $result->setLoginHint($this->getQueryStringParameter('login_hint', $request));

        if (!empty($acrValues = $this->getQueryStringParameter('acr_values', $request))) {
            $result->setAcrValues(explode(' ', $acrValues));
        }

        $claims = $this->getQueryStringParameter('claims', $request);
        $result->setClaims(
            $this->claimRepository->claimsRequestToEntities($claims ? json_decode($claims, true) : null)
        );

        if (!empty($display = $this->getQueryStringParameter('display', $request))) {
            $result->setDisplay($display);
        }

        return $result;
    }

    /**
     * {@inheritdoc}
     */
    public function respondToAccessTokenRequest(
        ServerRequestInterface $request,
        ResponseTypeInterface $responseType,
        \DateInterval $accessTokenTTL
    ) {
        /**
         * @var BearerTokenResponse $result
         */
        $result = parent::respondToAccessTokenRequest($request, $responseType, $accessTokenTTL);

        $encryptedAuthCode = $this->getRequestParameter('code', $request, null);
        $authCodePayload = json_decode($this->decrypt($encryptedAuthCode));

        if ($authCodePayload->claims) {
            $authCodePayload->claims = (array) $authCodePayload->claims;
        }

        $issuedAt = new \DateTimeImmutable();
        $idToken = $this->makeIdTokenInstance();
        $idToken->setIssuer($this->issuer);
        $idToken->setSubject($authCodePayload->user_id);
        $idToken->setAudience($authCodePayload->client_id);
        $idToken->setExpiration($issuedAt->add($this->idTokenTTL));
        $idToken->setIat($issuedAt);
        $idToken->setIdentifier($this->generateUniqueIdentifier());

        $idToken->setAuthTime(new \DateTimeImmutable('@' . $authCodePayload->auth_time));
        $idToken->setNonce($authCodePayload->nonce);

        if ($authCodePayload->claims) {
            $accessToken = $result->getAccessToken();

            $this->accessTokenRepository->storeClaims($accessToken, $authCodePayload->claims);
        }

        // TODO: populate idToken with claims ...
        $idToken = $this->addMoreClaimsToIdToken($idToken);

        /**
         * @var \Idaas\OpenID\SessionInformation
         */
        $sessionInformation = SessionInformation::fromJSON($authCodePayload->sessionInformation);

        $idToken->setAcr($sessionInformation->getAcr());
        $idToken->setAmr($sessionInformation->getAmr());
        $idToken->setAzp($sessionInformation->getAzp());

        $this->getEmitter()->emit(new IdTokenEvent(IdTokenEvent::TOKEN_POPULATED, $idToken, $this));

        $result->setIdToken($idToken);

        return $result;
    }

    protected function addMoreClaimsToIdToken(IdToken $idToken)
    {
        return $idToken;
    }

    /**
     * @return IdToken
     */
    protected function makeIdTokenInstance()
    {
        return new IdToken();
    }

    /**
     * {@inheritdoc}
     */
    public function completeAuthorizationRequest(AuthorizationRequest $authorizationRequest)
    {
        if (!($authorizationRequest instanceof AuthenticationRequest)) {
            throw OAuthServerException::invalidRequest('not possible');
        }

        if ($authorizationRequest->getUser() instanceof UserEntityInterface === false) {
            throw new \LogicException('An instance of UserEntityInterface should be set on the AuthorizationRequest');
        }

        // The user approved the client, redirect them back with an auth code
        if ($authorizationRequest->isAuthorizationApproved() === true) {
            $authCode = $this->issueAuthCode(
                $this->authCodeTTL,
                $authorizationRequest->getClient(),
                $authorizationRequest->getUser()->getIdentifier(),
                $authorizationRequest->getRedirectUri(),
                $authorizationRequest->getScopes()
            );

            $payload = [
                'client_id'             => $authCode->getClient()->getIdentifier(),
                'redirect_uri'          => $authCode->getRedirectUri(),
                'auth_code_id'          => $authCode->getIdentifier(),
                'scopes'                => $authCode->getScopes(),
                'user_id'               => $authCode->getUserIdentifier(),
                'expire_time'           => (new \DateTimeImmutable())->add($this->authCodeTTL)->format('U'),
                'code_challenge'        => $authorizationRequest->getCodeChallenge(),
                'code_challenge_method' => $authorizationRequest->getCodeChallengeMethod(),

                // OIDC specific parameters important for the id_token
                'nonce'                 => $authorizationRequest->getNonce(),
                'max_age'               => $authorizationRequest->getMaxAge(),
                'id_token_hint'         => $authorizationRequest->getIDTokenHint(),
                'claims'                => $authorizationRequest->getClaims(),
                'sessionInformation'    => (string) $authorizationRequest->getSessionInformation(),
                'auth_time'             => $this->session->getAuthTime()->format('U')

            ];

            $code = $this->encrypt(
                json_encode(
                    $payload
                )
            );

            return (new ResponseHandler())->getResponse($authorizationRequest, $code);
        } else {
            // The user denied the client, redirect them back with an error
            throw OAuthServerException::accessDenied(
                'The user denied the request',
                $this->makeRedirectUri(
                    $authorizationRequest->getRedirectUri(),
                    [
                        'state' => $authorizationRequest->getState(),
                    ]
                )
            );
        }
    }
}
