<?php

namespace Sevming\Crypt;

use Sevming\Crypt\Contracts\CryptInterface;
use Sevming\Support\Collection;
use Sevming\Support\Str;
use RuntimeException;
use InvalidArgumentException;

class Crypt
{
    /**
     * @var Collection
     */
    protected $config;

    /**
     * Crypt constructor.
     *
     * @param array $config
     */
    public function __construct(array $config = [])
    {
        $this->config = new Collection($config);
    }

    /**
     * Create a instance.
     *
     * @param $name
     *
     * @return CryptInterface
     *
     * @throws RuntimeException|InvalidArgumentException
     */
    public function create($name)
    {
        $driverNameSpace = __NAMESPACE__ . '\\Driver\\' . Str::studly($name);
        if (class_exists($driverNameSpace)) {
            $driver = new $driverNameSpace($this->config);
            if ($driver instanceof CryptInterface) {
                return $driver;
            }

            throw new RuntimeException("Driver [{$name}] Must Be An Instance Of CryptInterface");
        }

        throw new InvalidArgumentException("Driver [{$name}] Not Exists");
    }

    /**
     * Magic Call Static.
     *
     * @param $name
     * @param $arguments
     *
     * @return CryptInterface
     *
     * @throws RuntimeException|InvalidArgumentException
     */
    public static function __callStatic($name, $arguments)
    {
        $class = new self(...$arguments);
        return $class->create($name);
    }
}