<?php

namespace Trikoder\Bundle\OAuth2Bundle\OpenIDConnect;

use \League\OAuth2\Server\RequestTypes\AuthorizationRequest as BaseAuthorizationRequest;

/**
 * Class AuthorizationRequest
 *
 * @author Tayfun Aydin <tayfun@extendas.com>
 */
class AuthorizationRequest extends BaseAuthorizationRequest
{
    /**
     * The state parameter on the authorization request
     *
     * @var string|null
     */
    protected $nonce;


    public static function createFromLeagueAuthorizationRequest(\League\OAuth2\Server\RequestTypes\AuthorizationRequest $authorization_request)
    {
        $self = new self();
        $self->setState($authorization_request->getState());
        $self->setGrantTypeId($authorization_request->getGrantTypeId());
        $self->setCodeChallengeMethod($authorization_request->getCodeChallengeMethod());
        $self->setCodeChallenge($authorization_request->getCodeChallenge());
        $self->setClient($authorization_request->getClient());
        $self->setRedirectUri($authorization_request->getRedirectUri());
        $self->setScopes($authorization_request->getScopes());

        return $self;
    }

    /**
     * @return string|null
     */
    public function getNonce(): ?string
    {
        return $this->nonce;
    }

    /**
     * @param $nonce
     *
     * @return $this
     */
    public function setNonce($nonce)
    {
        $this->nonce = $nonce;
        return $this;
    }
}
