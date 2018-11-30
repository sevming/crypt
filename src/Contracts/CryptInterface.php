<?php

namespace Sevming\Crypt\Contracts;

interface CryptInterface
{
    /**
     * Encrypt the given value.
     *
     * @param string $value
     *
     * @return string
     */
    public function encrypt($value);

    /**
     * Decrypt the given value.
     *
     * @param string $value
     *
     * @return string
     */
    public function decrypt($value);
}