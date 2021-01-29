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
