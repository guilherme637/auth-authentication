<?php

namespace Auth;

class GenerateKey
{
    private const CONFIG_OPENSSL = [
        "digest_alg" => "sha512",
        "private_key_bits" => 4096,
        "private_key_type" => OPENSSL_KEYTYPE_RSA,
    ];

    private readonly \OpenSSLAsymmetricKey $openssl;

    public function __construct()
    {
        $this->openssl = openssl_pkey_new(self::CONFIG_OPENSSL);
    }

    public function rsa(string $projectName, string $pathCertificate): bool
    {
        $basePath = AuthEnum::CERTIFICATE->value . '/' . $projectName;

        if (!is_dir($basePath)) {
            mkdir($basePath);
        }

        if (file_exists($pathCertificate . AuthEnum::PRIVATE_KEY->value)) {
            return false;
        }

        $privateKey = $pathCertificate . AuthEnum::PRIVATE_KEY->value;
        openssl_pkey_export($this->openssl, $privateKey, $this->getPassphrase($projectName, $pathCertificate));
        $public_key = openssl_pkey_get_details($this->openssl)['key'];

        file_put_contents($basePath . AuthEnum::PUBLIC_KEY->value, $public_key);
//        file_put_contents($pathCertificate . AuthEnum::PRIVATE_KEY->value, $privateKey);

        return true;
    }

    private function getPassphrase(string $projectName, string $pathCertificate): string
    {
        $splitNomeProjeto = str_split($projectName);
        shuffle($splitNomeProjeto);

        $passphrase = hash('ripemd128', implode('', $splitNomeProjeto));

        file_put_contents($pathCertificate . '/passphrase.txt', $passphrase);

        return $passphrase;
    }
}