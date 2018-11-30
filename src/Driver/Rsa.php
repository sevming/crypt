<?php

namespace Sevming\Crypt\Driver;

use Sevming\Crypt\Contracts\CryptInterface;
use Sevming\Support\Collection;
use Sevming\Support\Str;

class Rsa implements CryptInterface
{
    /**
     * @var string
     */
    protected $publicKey;

    /**
     * @var string
     */
    protected $privateKey;

    /**
     * The encryption key.
     *
     * @var string
     */
    protected $key;

    /**
     * @var string
     */
    protected $padding = OPENSSL_PKCS1_PADDING;

    /**
     * Bootstrap.
     *
     * @param Collection $config
     */
    public function __construct($config)
    {
        $this->publicKey = $this->getPublicKey($config->get('publicKey'));
        $this->privateKey = $this->getPrivateKey($config->get('privateKey'));
        $this->key = $config->get('key');
    }

    /**
     * Get PublicKey.
     *
     * @param string $publicKey
     *
     * @return string
     */
    protected function getPublicKey($publicKey)
    {
        if (Str::endsWith($publicKey, '.pem')) {
            $publicKey = openssl_pkey_get_public(file_get_contents($publicKey));
        } else {
            $publicKey = "-----BEGIN PUBLIC KEY-----\n" .
                wordwrap($publicKey, 64, "\n", true) .
                "\n-----END PUBLIC KEY-----";
        }

        return $publicKey;
    }

    /**
     * Get PrivateKey.
     *
     * @param string $privateKey
     *
     * @return string
     */
    protected function getPrivateKey($privateKey)
    {
        if (Str::endsWith($privateKey, '.pem')) {
            $privateKey = openssl_pkey_get_private(file_get_contents($privateKey));
        } else {
            $privateKey = "-----BEGIN PRIVATE KEY-----\n" .
                wordwrap($privateKey, 64, "\n", true) .
                "\n-----END PRIVATE KEY-----";
        }

        return $privateKey;
    }

    /**
     * Encrypt the given value.
     *
     * @param string $value
     *
     * @return string|bool
     */
    public function encrypt($value)
    {
        if (openssl_public_encrypt($value, $crypted, $this->publicKey, $this->padding)) {
            return base64_encode($crypted);
        }

        return false;
    }

    /**
     * Decrypt the given value.
     *
     * @param string $crypted
     *
     * @return string|bool
     */
    public function decrypt($crypted)
    {
        $crypted = base64_decode($crypted);
        if (openssl_private_decrypt($crypted, $decrypted, $this->privateKey, $this->padding)) {
            return $decrypted;
        }

        return false;
    }

    /**
     * Generate sign.
     *
     * @param array $params
     *
     * @return string
     */
    public function generateSign($params)
    {
        return $this->getSignContent($params, $this->key);
    }

    /**
     * Verfiy sign.
     *
     * @param array $data
     * @param string|null $sign
     *
     * @return bool
     */
    public function verifySign($data, $sign = null)
    {
        $sign = is_null($sign) ? $data['sign'] : $sign;
        $signContent = $this->getSignContent($data, $this->key);
        if ($sign === $signContent) {
            return true;
        }

        return false;
    }

    /**
     * Generate sign with openssl.
     *
     * @param array $params
     *
     * @return string
     */
    public function generateSignWithOpenssl($params)
    {
        $signContent = $this->getSignContent($params);
        openssl_sign($signContent, $sign, $this->privateKey, OPENSSL_ALGO_SHA256);

        return base64_encode($sign);
    }

    /**
     * Verfiy sign with openssl.
     *
     * @param array $data
     * @param string|null $sign
     *
     * @return bool
     */
    public function verifySignWithOpenssl($data, $sign = null)
    {
        $sign = is_null($sign) ? $data['sign'] : $sign;
        $signContent = $this->getSignContent($data);

        return openssl_verify($signContent, base64_decode($sign), $this->publicKey, OPENSSL_ALGO_SHA256) === 1;
    }

    /**
     * Generate sign content.
     *
     * @param array $data
     * @param string $key
     *
     * @return string
     */
    protected function getSignContent($data, $key = null)
    {
        ksort($data);
        $stringToBeSigned = '';
        foreach ($data as $k => $v) {
            if ($v !== '' && !is_null($v) && $k != 'sign') {
                $stringToBeSigned .= $k . '=' . $v . '&';
            }
        }

        $stringToBeSigned = trim($stringToBeSigned, '&');
        if (!is_null($key)) {
            $stringToBeSigned .= '&key=' . $key;
        }

        return strtoupper(md5($stringToBeSigned));
    }
}