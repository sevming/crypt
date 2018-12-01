<?php

namespace Sevming\Crypt\Driver;

use Sevming\Crypt\Contracts\CryptInterface;
use Sevming\Support\Collection;
use \Exception, \InvalidArgumentException;

/**
 * Aes Modify From Illuminate\Encryption\Encrypter
 */
class Aes implements CryptInterface
{
    /**
     * The encryption key.
     *
     * @var string
     */
    protected $key;

    /**
     * The algorithm used for encryption.
     *
     * @var string
     */
    protected $cipher;

    /**
     * Bootstrap.
     *
     * @param Collection $config
     *
     * @throws InvalidArgumentException|Exception
     */
    public function __construct($config)
    {
        $this->key = $config->get('key');
        $this->cipher = $config->get('cipher', 'AES-128-CBC');

        if (!$this->supported($this->key, $this->cipher)) {
            throw new InvalidArgumentException('The only supported ciphers are AES-128-CBC and AES-256-CBC with the correct key lengths.');
        }
    }

    /**
     * Determine if the given key and cipher combination is valid.
     *
     * @param string $key
     * @param string $cipher
     *
     * @return bool
     */
    public function supported($key, $cipher)
    {
        $length = mb_strlen($key, '8bit');
        return ($cipher === 'AES-128-CBC' && $length === 16) || ($cipher === 'AES-256-CBC' && $length === 32);
    }

    /**
     * Encrypt the given value.
     *
     * @param string $value
     *
     * @return string
     *
     * @throws Exception
     */
    public function encrypt($value)
    {
        $iv = substr($this->key, 0, 16);
        $encryptText = (openssl_encrypt($this->addPkcs7Padding(base64_encode($value)), $this->cipher, $this->key, OPENSSL_RAW_DATA, $iv));

        return bin2hex($encryptText);
    }

    /**
     * Decrypt the given value.
     *
     * @param string $value
     *
     * @return string
     */
    public function decrypt($value)
    {
        $iv = substr($this->key, 0, 16);
        $value = preg_match('/^[0-9a-fA-F]+$/i', $value) ? pack('H*', $value) : false;

        return base64_decode(openssl_decrypt($value, $this->cipher, $this->key, OPENSSL_RAW_DATA, $iv));
    }

    /**
     * 明文加工处理
     *
     * @param string $string
     * @param int $blocksize
     *
     * @return string
     */
    protected function addPkcs7Padding($string, $blocksize = 16)
    {
        $len = strlen($string);
        // 取得补码的长度
        $pad = $blocksize - ($len % $blocksize);
        // 用ASCII码为补码长度的字符,补足最后一段
        $string .= str_repeat(chr($pad), $pad);

        return $string;
    }

    /**
     * Encrypt the given value with mac.
     *
     * @param string $value
     *
     * @return string
     *
     * @throws Exception
     */
    public function encryptWithMac($value)
    {
        $iv = random_bytes(openssl_cipher_iv_length($this->cipher));

        // First we will encrypt the value using OpenSSL. After this is encrypted we
        // will proceed to calculating a MAC for the encrypted value so that this
        // value can be verified later as not having been changed by the users.
        $value = openssl_encrypt($value, $this->cipher, $this->key, 0, $iv);

        // Once we get the encrypted value we'll go ahead and base64_encode the input
        // vector and create the MAC for the encrypted value so we can then verify
        // its authenticity. Then, we'll JSON the data into the "payload" array.
        $mac = $this->hash($iv = base64_encode($iv), $value);

        return base64_encode(json_encode(compact('iv', 'value', 'mac')));
    }

    /**
     * Decrypt the given value with mac.
     *
     * @param string $payload
     *
     * @return string
     *
     * @throws Exception
     */
    public function decryptWithMac($payload)
    {
        $payload = json_decode(base64_decode($payload), true);

        // If the payload is not valid JSON or does not have the proper keys set we will
        // assume it is invalid and bail out of the routine since we will not be able
        // to decrypt the given value. We'll also check the MAC for this encryption.
        if (!$this->validPayload($payload)) {
            throw new Exception('The payload is invalid.');
        }

        if (!$this->validMac($payload)) {
            throw new Exception('The MAC is invalid.');
        }

        $iv = base64_decode($payload['iv']);

        // Here we will decrypt the value. If we are able to successfully decrypt it
        // we will then unserialize it and return it out to the caller. If we are
        // unable to decrypt this value we will throw out an exception message.
        $decrypted = openssl_decrypt($payload['value'], $this->cipher, $this->key, 0, $iv);

        return $decrypted;
    }

    /**
     * Create a MAC for the given value.
     *
     * @param string $iv
     * @param mixed $value
     *
     * @return string
     */
    protected function hash($iv, $value)
    {
        return hash_hmac('sha256', $iv . $value, $this->key);
    }

    /**
     * Verify that the encryption payload is valid.
     *
     * @param mixed $payload
     *
     * @return bool
     */
    protected function validPayload($payload)
    {
        return is_array($payload) && isset($payload['iv'], $payload['value'], $payload['mac']) &&
            strlen(base64_decode($payload['iv'], true)) === openssl_cipher_iv_length($this->cipher);
    }

    /**
     * Determine if the MAC for the given payload is valid.
     *
     * @param array $payload
     *
     * @return bool
     *
     * @throws Exception
     */
    protected function validMac(array $payload)
    {
        $mac = $this->hash($payload['iv'], $payload['value']);
        $bytes = random_bytes(16);

        return hash_equals(
            hash_hmac('sha256', $payload['mac'], $bytes, true),
            hash_hmac('sha256', $mac, $bytes, true)
        );
    }
}