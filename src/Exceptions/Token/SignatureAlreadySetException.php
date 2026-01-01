<?php

/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Scripting/PHPClass.php to edit this template
 */

namespace Phithi92\JsonWebToken\Exceptions\Token;

class SignatureAlreadySetException extends TokenException
{
    public function __construct()
    {
        parent::__construct('SIGNATURE_ALREADY_SET');
    }
}
