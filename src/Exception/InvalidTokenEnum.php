<?php

/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Scripting/PHPClass.php to edit this template
 */

namespace Phithi92\JsonWebToken\Exception;

/**
 * Description of HashErrorEnum
 *
 * @author phillip
 */
enum InvalidTokenEnum: string
{
    //put your code here
    public const SIGNATURE_INVALID = 'HMAC verification for algorithm %s failed. '
            . 'The provided HMAC does not match the expected signature.';
}
