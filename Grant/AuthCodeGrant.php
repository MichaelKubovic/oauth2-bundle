<?php

declare(strict_types=1);

namespace Trikoder\Bundle\OAuth2Bundle\Grant;

use DateInterval;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\UserEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\AuthCodeGrant as BaseAuthCodeGrant;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest;
use League\OAuth2\Server\ResponseTypes\RedirectResponse;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Psr\Http\Message\ServerRequestInterface;
use Trikoder\Bundle\OAuth2Bundle\League\Repository\AuthCodeRepository;
use Trikoder\Bundle\OAuth2Bundle\OpenIDConnect\IdTokenResponse;

/**
 * @property AuthCodeRepository $authCodeRepository
 */
class AuthCodeGrant extends BaseAuthCodeGrant
{
    private $nonce;

    private $authCodeTTL;

    public function __construct(AuthCodeRepositoryInterface $authCodeRepository, RefreshTokenRepositoryInterface $refreshTokenRepository, DateInterval $authCodeTTL)
    {
        parent::__construct($authCodeRepository, $refreshTokenRepository, $authCodeTTL);
        $this->authCodeTTL = $authCodeTTL;
    }

    public function validateAuthorizationRequest(ServerRequestInterface $request)
    {
        $authorizationRequest = parent::validateAuthorizationRequest($request);
        $authorizationRequest = \Trikoder\Bundle\OAuth2Bundle\OpenIDConnect\AuthorizationRequest::createFromLeagueAuthorizationRequest($authorizationRequest);
        $authorizationRequest->setNonce($this->getQueryStringParameter('nonce', $request, null));

        return $authorizationRequest;
    }

    protected function issueAuthCode(DateInterval $authCodeTTL, ClientEntityInterface $client, $userIdentifier, $redirectUri, array $scopes = [])
    {
        $autCode = parent::issueAuthCode($authCodeTTL, $client, $userIdentifier, $redirectUri, $scopes);

        if (null !== $this->nonce) {
            $this->authCodeRepository->updateWithNonce($autCode, $this->nonce);
        }

        return $autCode;
    }

    public function respondToAccessTokenRequest(ServerRequestInterface $request, ResponseTypeInterface $responseType, DateInterval $accessTokenTTL)
    {
        $response = parent::respondToAccessTokenRequest($request, $responseType, $accessTokenTTL);

        if ($response instanceof IdTokenResponse) {
            $encryptedAuthCode = $this->getRequestParameter('code', $request, null);
            $authCodePayload = json_decode($this->decrypt($encryptedAuthCode));

            $nonce = $this->authCodeRepository->getNonce($authCodePayload->auth_code_id);
            $response->setNonce($nonce);
        }

        return $response;
    }

    public function completeAuthorizationRequest(AuthorizationRequest $authorizationRequest)
    {
        if (false === $authorizationRequest->getUser() instanceof UserEntityInterface) {
            throw new \LogicException('An instance of UserEntityInterface should be set on the AuthorizationRequest');
        }

        $finalRedirectUri = $authorizationRequest->getRedirectUri()
            ?? $this->getClientRedirectUri($authorizationRequest);

        // The user approved the client, redirect them back with an auth code
        if (true === $authorizationRequest->isAuthorizationApproved()) {
            $this->nonce = $authorizationRequest->getNonce();
            $authCode = $this->issueAuthCode(
                $this->authCodeTTL,
                $authorizationRequest->getClient(),
                $authorizationRequest->getUser()->getIdentifier(),
                $authorizationRequest->getRedirectUri(),
                $authorizationRequest->getScopes()
            );

            $payload = [
                'client_id' => $authCode->getClient()->getIdentifier(),
                'redirect_uri' => $authCode->getRedirectUri(),
                'auth_code_id' => $authCode->getIdentifier(),
                'scopes' => $authCode->getScopes(),
                'user_id' => $authCode->getUserIdentifier(),
                'expire_time' => (new \DateTime())->add($this->authCodeTTL)->format('U'),
                'code_challenge' => $authorizationRequest->getCodeChallenge(),
                'code_challenge_method' => $authorizationRequest->getCodeChallengeMethod(),
            ];

            $response = new RedirectResponse();
            $response->setRedirectUri(
                $this->makeRedirectUri(
                    $finalRedirectUri,
                    [
                        'code' => $this->encrypt(
                            json_encode(
                                $payload
                            )
                        ),
                        'state' => $authorizationRequest->getState(),
                    ]
                )
            );

            return $response;
        }

        // The user denied the client, redirect them back with an error
        throw OAuthServerException::accessDenied('The user denied the request', $this->makeRedirectUri($finalRedirectUri, ['state' => $authorizationRequest->getState()]));
    }

    /**
     * Get the client redirect URI if not set in the request.
     *
     * @return string
     */
    private function getClientRedirectUri(AuthorizationRequest $authorizationRequest)
    {
        return \is_array($authorizationRequest->getClient()->getRedirectUri())
            ? $authorizationRequest->getClient()->getRedirectUri()[0]
            : $authorizationRequest->getClient()->getRedirectUri();
    }
}
