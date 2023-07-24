<?php

namespace Idaas\OpenID\Grant;

use DateTimeImmutable;
use Idaas\OpenID\Entities\IdToken;
use Idaas\OpenID\IdTokenEvent;
use Idaas\OpenID\Repositories\ClaimRepositoryInterface;
use Idaas\OpenID\Repositories\UserRepositoryInterface;
use Idaas\OpenID\RequestTypes\AuthenticationRequest;
use Idaas\OpenID\SessionInterface;
use League\OAuth2\Server\Entities\UserEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest;
use League\OAuth2\Server\ResponseTypes\RedirectResponse;
use Psr\Http\Message\ServerRequestInterface;

class ImplicitGrant extends \League\OAuth2\Server\Grant\ImplicitGrant
{
    use OIDCTrait;

    private $authCodeTTL;
    private $idTokenTTL;
    private $queryDelimiter;

    /**
     * @var UserRepositoryInterface
     */
    protected $userRepository;

    protected $claimRepositoryInterface;

    /**
     * @var SessionInterface
     */
    protected $session;

    /**
     * @param \DateInterval $accessTokenTTL
     * @param string $queryDelimiter
     */
    public function __construct(
        UserRepositoryInterface $userRepository,
        ClaimRepositoryInterface $claimRepositoryInterface,
        SessionInterface $session,
        \DateInterval $accessTokenTTL,
        \DateInterval $idTokenTTL,
        $queryDelimiter = '#'
    ) {
        parent::__construct($accessTokenTTL, $queryDelimiter);

        $this->userRepository = $userRepository;
        $this->claimRepositoryInterface = $claimRepositoryInterface;
        $this->session = $session;

        $this->accessTokenTTL = $accessTokenTTL;
        $this->idTokenTTL = $idTokenTTL;
        $this->queryDelimiter = $queryDelimiter;
    }

    public function getIdentifier()
    {
        return 'implicit_oidc';
    }

    public function canRespondToAuthorizationRequest(ServerRequestInterface $request)
    {
        $result = (isset($request->getQueryParams()['response_type'])
            && ($request->getQueryParams()['response_type'] === 'id_token token' || $request->getQueryParams()['response_type'] === 'id_token' || $request->getQueryParams()['response_type'] === 'token')
            && isset($request->getQueryParams()['client_id']));

        $queryParams = $request->getQueryParams();
        $scopes = ($queryParams && isset($queryParams['scope'])) ? $queryParams['scope'] : null;

        return $result && ($scopes && in_array('openid', explode(' ', $scopes)));
    }

    public function validateAuthorizationRequest(ServerRequestInterface $request)
    {
        $result = parent::validateAuthorizationRequest($request);

        $result = AuthenticationRequest::fromAuthorizationRequest($result);

        $result->setResponseType($this->getQueryStringParameter('response_type', $request));
        $result->setResponseMode($this->getQueryStringParameter('response_mode', $request));

        $nonce = $this->getQueryStringParameter('nonce', $request, '');

        //In OIDC, a nonce is required for the implicit flow
        if (strlen($nonce) == 0) {
            throw OAuthServerException::invalidRequest('nonce');
        }

        $result->setNonce($nonce);

        $redirectUri = $this->getQueryStringParameter(
            'redirect_uri',
            $request
        );

        //In constract with OAuth 2.0, in OIDC, the redirect_uri parameter is required
        if (is_null($redirectUri)) {
            throw OAuthServerException::invalidRequest('redirect_uri');
        }

        // When max_age is used, the ID Token returned MUST include an auth_time Claim Value
        $maxAge = $this->getQueryStringParameter('max_age', $request);

        if (!empty($maxAge) && !is_numeric($maxAge)) {
            throw OAuthServerException::invalidRequest('max_age', 'max_age must be numeric');
        }

        $result->setMaxAge($maxAge);

        $result->setPrompt($this->getQueryStringParameter('prompt', $request));

        if (!empty($uiLocales = $this->getQueryStringParameter('ui_locales', $request))) {
            $result->setUILocales(explode(' ', $uiLocales));
        }

        $result->setLoginHint($this->getQueryStringParameter('login_hint', $request));

        if (!empty($acrValues = $this->getQueryStringParameter('acr_values', $request))) {
            $result->setAcrValues(explode(' ', $acrValues));
        }

        $claims = $this->getQueryStringParameter('claims', $request);
        $result->setClaims(
            $this->claimRepositoryInterface->claimsRequestToEntities($claims ? json_decode($claims, true) : null)
        );

        return $result;
    }

    public function completeAuthorizationRequest(AuthorizationRequest $authorizationRequest)
    {
        if (!($authorizationRequest instanceof AuthenticationRequest)) {
            throw OAuthServerException::invalidRequest('not possible');
        }

        if ($authorizationRequest->getUser() instanceof UserEntityInterface === false) {
            throw new \LogicException('An instance of UserEntityInterface should be set on the AuthorizationRequest');
        }

        $finalRedirectUri = $authorizationRequest->getRedirectUri();

        // The user approved the client, redirect them back with an access token
        if ($authorizationRequest->isAuthorizationApproved() === true) {
            $accessToken = $this->issueAccessToken(
                $this->accessTokenTTL,
                $authorizationRequest->getClient(),
                $authorizationRequest->getUser()->getIdentifier(),
                $authorizationRequest->getScopes()
            );

            $idToken = new IdToken();

            $issuedAt = new \DateTimeImmutable();
            $idToken->setIssuer($this->issuer);
            $idToken->setSubject($authorizationRequest->getUser()->getIdentifier());
            $idToken->setAudience($authorizationRequest->getClient()->getIdentifier());
            $idToken->setExpiration($issuedAt->add($this->idTokenTTL));
            $idToken->setIat($issuedAt);
            $idToken->setAuthTime($this->session->getAuthTime());
            $idToken->setNonce($authorizationRequest->getNonce());
            $idToken->setIdentifier($this->generateUniqueIdentifier());

            $claimsRequested = $authorizationRequest->getClaims();

            // If there is no access token returned, include the supported claims
            if ($authorizationRequest->getResponseType() == 'id_token') {
                $scopes = [];

                foreach ($authorizationRequest->getScopes() as $scope) {
                    $claims = $this->userRepository->getClaims(
                        $this->claimRepositoryInterface,
                        $scope
                    );
                    if (count($claims) > 0) {
                        array_push($claimsRequested, ...$claims);
                        $scopes[] = $scope;
                    }
                }

                $attributes = $this->userRepository->getAttributes(
                    $authorizationRequest->getUser(),
                    $claimsRequested,
                    $scopes
                );

                foreach ($attributes as $key => $value) {
                    $idToken->addExtra($key, $value);
                }
            } else {
                $this->accessTokenRepository->storeClaims($accessToken, $claimsRequested);
            }

            /**
             * @var \Idaas\OpenID\SessionInformation
             */
            $sessionInformation = $authorizationRequest->getSessionInformation();

            $idToken->setAcr($sessionInformation->getAcr());
            $idToken->setAmr($sessionInformation->getAmr());
            $idToken->setAzp($sessionInformation->getAzp());

            $this->getEmitter()->emit(new IdTokenEvent(IdTokenEvent::TOKEN_POPULATED, $idToken, $this));

            $parameters = [];

            //Only add the access token and related parameters if requested
            //TODO: Check if OpenID Connect flow is allowed if only a token is requested.
            if ($authorizationRequest->getResponseType() == 'id_token token' || $authorizationRequest->getResponseType() == 'token') {
                $accessToken->setPrivateKey($this->privateKey);
                $parameters['access_token'] = (string) $accessToken;
                $parameters['token_type'] = 'Bearer';
                $parameters['expires_in'] = $accessToken->getExpiryDateTime()->getTimestamp() - (new \DateTime())->getTimestamp();
            }

            $parameters['state'] = $authorizationRequest->getState();
            $parameters['id_token'] = (string) $idToken->convertToJWT($this->privateKey)->toString();

            $response = new RedirectResponse();
            $response->setRedirectUri(
                $this->makeRedirectUri(
                    $finalRedirectUri,
                    $parameters,
                    $this->queryDelimiter
                )
            );

            return $response;
        }

        // The user denied the client, redirect them back with an error
        throw OAuthServerException::accessDenied(
            'The user denied the request',
            $this->makeRedirectUri(
                $finalRedirectUri,
                [
                    'state' => $authorizationRequest->getState(),
                ]
            )
        );
    }
}
