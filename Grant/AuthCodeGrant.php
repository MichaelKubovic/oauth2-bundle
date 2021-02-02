<?php

declare(strict_types=1);

namespace Trikoder\Bundle\OAuth2Bundle\Grant;

use DateInterval;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\AuthCodeGrant as BaseAuthCodeGrant;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\RequestEvent;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest;
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
        $nonce = $this->getQueryStringParameter('nonce', $request, null);
        if (!$nonce || $this->authCodeRepository->isNonceUsed($nonce)) {
            $this->getEmitter()->emit(new RequestEvent(RequestEvent::ACCESS_TOKEN_ISSUED, $request));
            throw new OAuthServerException('Nonce is not valid', 40, 'invalid_nonce');
        }
        $authorizationRequest = \Trikoder\Bundle\OAuth2Bundle\OpenIDConnect\AuthorizationRequest::createFromLeagueAuthorizationRequest($authorizationRequest);
        $authorizationRequest->setNonce($nonce);

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
        if ($authorizationRequest->isAuthorizationApproved()) {
            $this->nonce = $authorizationRequest->getNonce();
        }

        return parent::completeAuthorizationRequest($authorizationRequest);
    }
}
