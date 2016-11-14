<?php

namespace WechatApp\SessionBundle\EventListener;

use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpKernel\Event\GetResponseForExceptionEvent;
use WechatApp\SessionBundle\Exception\SessionAuthException;

class SessionAuthExceptionListener
{
    public function onKernelException(GetResponseForExceptionEvent $event)
    {
        $exception = $event->getException();

        if ($exception instanceof SessionAuthException) {
            $response = new JsonResponse(['msg' => $exception->getMessage()], $exception->getCode());
            $event->setResponse($response);
        }
    }
}