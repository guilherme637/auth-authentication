<?php

namespace Auth;

enum AuthEnum: string
{
    case CERTIFICATE = '/certificates';
    case PUBLIC_KEY = '/public-key.pem';
    case PRIVATE_KEY = '/private-key.pem';
    case PASSPHRASE = '/passphrase.txt';
    case ALG = 'RS256';
}
