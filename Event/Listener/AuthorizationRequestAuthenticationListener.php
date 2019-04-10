<?php

namespace Trikoder\Bundle\OAuth2Bundle\Event\Listener;

use Symfony\Bundle\SecurityBundle\Security\FirewallMap;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Authorization\AuthorizationCheckerInterface;
use Symfony\Component\Security\Http\Util\TargetPathTrait;
use Trikoder\Bundle\OAuth2Bundle\Event\AuthorizationRequestResolveEvent;
use Zend\Diactoros\Response;

/**
 * Class AuthorizationRequestAuthenticationListener
 *
 * Listener that redirects anonymous users to login screen.
 * Enabled automatically with OpenId Connect
 *
 * @package Trikoder\Bundle\OAuth2Bundle\Event\Listener
 */
class AuthorizationRequestAuthenticationListener implements AuthorizationEventListener
{
    use TargetPathTrait;

    /**
     * @var AuthorizationCheckerInterface
     */
    private $authorizationChecker;

    /**
     * @var SessionInterface
     */
    private $session;

    /**
     * @var RequestStack
     */
    private $requestStack;

    /**
     * @var UrlGeneratorInterface
     */
    private $urlGenerator;

    /**
     * @var FirewallMap
     */
    private $firewallMap;

    /**
     * @var string
     */
    private $loginRoute;

    public function __construct(
        AuthorizationCheckerInterface $authorizationChecker,
        SessionInterface $session,
        RequestStack $requestStack,
        UrlGeneratorInterface $urlGenerator,
        FirewallMap $firewallMap,
        string $loginRoute
    ) {
        $this->authorizationChecker = $authorizationChecker;
        $this->session = $session;
        $this->requestStack = $requestStack;
        $this->urlGenerator = $urlGenerator;
        $this->firewallMap = $firewallMap;
        $this->loginRoute = $loginRoute;
    }

    public function onAuthorizationRequest(AuthorizationRequestResolveEvent $event): void
    {
        if (null === $request = $this->requestStack->getMasterRequest()) {
            throw new \RuntimeException('Authentication listener depends on the request context');
        }

        if (!$this->authorizationChecker->isGranted('IS_AUTHENTICATED_REMEMBERED')) {
            $firewallConfig = $this->firewallMap->getFirewallConfig($request);
            $this->saveTargetPath($this->session, $firewallConfig->getProvider(), $request->getUri());

            $loginUrl = $this->urlGenerator->generate($this->loginRoute);
            $event->setResponse(new Response(null, 302, ['Location' => $loginUrl]));
        }
    }
}
