<?php

namespace WechatApp\SessionBundle\Exception;


class SessionAuthException extends \Exception
{
    public function __construct($reason = '', array $additional = [])
    {
        if (isset($additional['reason'])) {
            unset($additional['reason']);
        }

        $error = array_merge([
            'reason' => $reason
        ], $additional);

        $this->message = json_encode($error);
    }
}