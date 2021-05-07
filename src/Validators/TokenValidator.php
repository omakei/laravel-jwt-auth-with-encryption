<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth\Validators;

use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Support\Facades\Crypt;
use Tymon\JWTAuth\Exceptions\TokenBlacklistedException;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;

class TokenValidator extends Validator
{
    /**
     * Check the structure of the token.
     *
     * @param  string  $value
     *
     * @return string
     */
    public function check($value)
    {
        return $this->validateStructure($value);
    }

    /**
     * @param  string  $token
     *
     * @throws \Tymon\JWTAuth\Exceptions\TokenInvalidException
     *
     * @return string
     */
    protected function validateStructure($token)
    {
        try {
            $decrypted = Crypt::decryptString($token);
        } catch (DecryptException $e) {
            throw new TokenBlacklistedException($e->getMessage());
        }

        $parts = explode('.', $decrypted);

        if (count($parts) !== 3) {
            throw new TokenInvalidException('Wrong number of segments');
        }

        $parts = array_filter(array_map('trim', $parts));

        if (count($parts) !== 3 || implode('.', $parts) !== $decrypted) {
            throw new TokenInvalidException('Malformed token');
        }

        return $token;
    }
}
