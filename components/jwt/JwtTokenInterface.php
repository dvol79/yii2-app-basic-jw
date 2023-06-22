<?php

namespace app\components\jwt;

/**
 * JwtTokenInterface is the interface that should be implemented by a class providing JWT.
 *
 * @category Authentication
 * @package  app\components\jwt
 * @author   Dmitry Volkov <kidvol2002@gmail.com>
 */
interface JwtTokenInterface
{
    /**
     * Set token for decode
     * @param string $jwtToken 
     * @return bool
     */
    public function setToken(string $jwtToken): bool;

    /**
     * Set payload for encode
     * @param array $payload 
     * @return bool
     */
    public function setPayload(array $payload): bool;

    /**
     * Return jwt token string
     * @return string|null
     */
    public function getToken(): ?string;

    /**
     * Get token header
     * @return array
     */
    public function getHeader(): array;

    /**
     * Get token payload
     * @return array
     */
    public function getPayload(): array;

    /**
     * Get token claim by name
     * @return mixed
     */
    public function getClaim(string $name): mixed;

    /**
     * Is decoded token valid
     * @return bool
     */
    public function isValid(): bool;

    /**
     * Is token sign verifed
     * @return bool
     */
    public function isVerifed(): bool;

    /**
     * Is token expired
     * @return bool
     */
    public function isExpired(): bool;

    /**
     * Return jwt encode success result
     * @return bool
     */
    public function encode(): bool;

    /**
     * Return jwt decode success result
     * @return bool
     */
    public function decode(): bool;
}