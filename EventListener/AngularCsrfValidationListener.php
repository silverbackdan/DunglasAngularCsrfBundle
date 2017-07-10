<?php

/*
 * (c) Kévin Dunglas <dunglas@gmail.com>
 *
 * This source file is subject to the MIT license that is bundled
 * with this source code in the file LICENSE.
 */

namespace Dunglas\AngularCsrfBundle\EventListener;

use Dunglas\AngularCsrfBundle\Csrf\AngularCsrfTokenManager;
use Dunglas\AngularCsrfBundle\Routing\RouteMatcherInterface;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\HttpKernel\HttpKernelInterface;

/**
 * Checks the validity of the CSRF token sent by AngularJS.
 *
 * @author Kévin Dunglas <dunglas@gmail.com>
 */
class AngularCsrfValidationListener
{
    /**
     * @var AngularCsrfTokenManager
     */
    protected $angularCsrfTokenManager;
    /**
     * @var RouteMatcherInterface
     */
    protected $routeMatcher;
    /**
     * @var array
     */
    protected $routes;
    /**
     * @var string
     */
    protected $headerName;
    /**
     * @var string
     */
    protected $headerEnabled;
    /**
     * @var string
     */
    protected $cookieName;

    /**
     * @param AngularCsrfTokenManager $angularCsrfTokenManager
     * @param RouteMatcherInterface   $routeMatcher
     * @param array                   $routes
     * @param string                  $headerName
     */
    public function __construct(
        AngularCsrfTokenManager $angularCsrfTokenManager,
        RouteMatcherInterface $routeMatcher,
        array $routes,
        $headerName,
        $headerEnabled,
        $cookieName
    ) {
        $this->angularCsrfTokenManager = $angularCsrfTokenManager;
        $this->routeMatcher = $routeMatcher;
        $this->routes = $routes;
        $this->headerName = $headerName;
        $this->headerEnabled = $headerEnabled;
        $this->cookieName = $cookieName;
    }

    /**
     * Handles CSRF token validation.
     *
     * @param GetResponseEvent $event
     *
     * @throws AccessDeniedHttpException
     */
    public function onKernelRequest(GetResponseEvent $event)
    {
        if (
            HttpKernelInterface::MASTER_REQUEST !== $event->getRequestType()
            ||
            !$this->routeMatcher->match($event->getRequest(), $this->routes)
        ) {
            return;
        }

        $request = $event->getRequest();
        $value = $this->headerEnabled ? $request->headers->get($this->headerName) : $request->cookies->get($this->cookieName);
        if (!$value || !$this->angularCsrfTokenManager->isTokenValid($value)) {
            throw new AccessDeniedHttpException('Bad CSRF token.');
        }
    }
}
