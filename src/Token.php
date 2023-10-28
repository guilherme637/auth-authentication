<?php

namespace Auth;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class Token
{
    public static function getJwt(array $assemblerTokenResponse, string $privateKeyPath, string $clientName): string
    {
        $pathKeys = $privateKeyPath . $clientName;
        $privateKey = $pathKeys . AuthEnum::PRIVATE_KEY->value;

        $key = openssl_pkey_get_private(
            file_get_contents($privateKey),
            file_get_contents($pathKeys . AuthEnum::PASSPHRASE->value)
        );

        return JWT::encode($assemblerTokenResponse, $key, AuthEnum::ALG->value);
    }

    public static function decrypt(string $token, string $project): \stdClass
    {
        $publicKey = file_get_contents(AuthEnum::CERTIFICATE->value . AuthEnum::PUBLIC_KEY->value);

        return JWT::decode($token, new Key($publicKey, AuthEnum::ALG->value));
    }
}