<?php

namespace app\components\jwt;

use DateTime;
use Exception;
use DomainException;
use yii\base\BaseObject;

/**
 * JSON Web Token implementation, based on HS256 algorithm
 * 
 * Constructor params:
 * $key (string) - Secret Key. Required!!!
 * 
 * @example
 * ```php
 * echo 'Encode:' . PHP_EOL;
 * $token = new JwtHs256Token('secret-k3y');
 * if ($token->setPayload(['user_id' => 23]) && $token->encode()) {
 *   echo 'Success: ' . $token->getToken();
 * } else {
 *   echo 'Error: ' . json_encode($token->errors);
 * }
 * 
 * echo 'Decode:' . PHP_EOL;
 * $token = new JwtHs256Token('secret-k3y');
 * if ($token->setToken('eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9...') && $token->decode()) {
 *   echo 'Success: ' . $token->getClaim('user_id);
 * } else {
 *   echo 'Error: ' . json_encode($token->errors);
 * }
 * ```
 * 
 * @category Authentication
 * @package app\components\jwt
 * @author Dmitry Volkov <kidvol2002@gmail.com>
 * TODO: refactor json encode-decode methods to component
 */
class JwtHs256Token extends BaseObject implements JwtTokenInterface
{
    /**
     * @var string supported algorithm
     */
    private $alg = 'SHA256';

    /**
     * @var string|null secret key
     */
    private $_key;

    /**
     * @var string|null jwt token
     */
    private $_token;

    /**
     * @var array token parts
     */
    private $_parts = [];

    /**
     * @var array header data
     */
    private $_header = [];

    /**
     * @var array payload data
     */
    private $_payload = [];

    /**
     * @var bool is valid flag
     */
    private $_isValid = false;

    /**
     * @var bool is verifed flag
     */
    private $_isVerifed = false;

    /**
     * @var bool
     */
    private $_isExpired = false;
    

    /**
     * @var array errors
     */
    private $_errors = [];


    /**
     * {@inheritdoc}
     */
    public function __construct(string $key, $config = [])
    {
        $this->setKey($key);

        parent::__construct($config);
    }

    /**
     * {@inheritdoc}
     */
    public function setToken(string $jwtToken): bool
    {
        $token = trim($jwtToken);
        if (!$token) {
            $this->addError('Empty token string!');
            return false;
        }

        $parts = explode('.', $jwtToken);
        if (count($parts) != 3) {
            $this->addError('Wrong number of jwt segments');
            return false;
        }

        $this->_parts = $parts;
        $this->_token = $token;

        return true;
    }

    /**
     * {@inheritdoc}
     */
    public function setPayload(array $payload): bool
    {
        if (!count($payload)) {
            return false;
        }
        $this->_payload = $payload;

        return true;
    }

    /**
     * {@inheritdoc}
     */
    public function encode(): bool
    {
        if (!count($this->_payload)) {
            $this->addError('Empty Payload data!');
            return false;
        }

        $this->setDefaultHeader();
        $segments = [];
        $segments[] = $this->urlsafeB64Encode((string) $this->jsonEncode($this->_header));
        $segments[] = $this->urlsafeB64Encode((string) $this->jsonEncode($this->_payload));
        $signing_input = implode('.', $segments);

        $signature = $this->sign($signing_input, $this->_key);
        $segments[] = $this->urlsafeB64Encode($signature);

        $this->_isValid = true;
        $this->_token = implode('.', $segments);
        return true;
    }

    /**
     * {@inheritdoc}
     */
    public function decode(): bool
    {
        if (!$this->_token || (count($this->_parts) != 3)) {
            return false;
        }

        list($headb64, $bodyb64, $cryptob64) = $this->_parts;

        $isHeaderSet = $this->setHeaderFromB64($headb64);
        $isPayloadSet = $this->setPayloadFromB64($bodyb64);
        $isSignVerified = $this->verifySignatureFromB64($cryptob64, "$headb64.$bodyb64");

        $this->_isVerifed = $isSignVerified;
        $this->_isValid = $isHeaderSet && $isPayloadSet && $isSignVerified;

        return $this->_isValid;
    }

    /**
     * {@inheritdoc}
     */
    public function getToken(): ?string
    {
        return $this->_token;
    }

    /**
     * {@inheritdoc}
     */
    public function getHeader(): array
    {
        return $this->_header;
    }

    /**
     * {@inheritdoc}
     */
    public function getPayload(): array
    {
        return $this->_payload;
    }

    /**
     * {@inheritdoc}
     */
    public function getClaim(string $name): mixed
    {
        return $this->_payload[$name] ?? null;
    }

    /**
     * {@inheritdoc}
     */
    public function isValid(): bool
    {
        return $this->_isValid;
    }

    /**
     * {@inheritdoc}
     */
    public function isVerifed(): bool
    {
        return $this->_isVerifed;
    }

    /**
     * {@inheritdoc}
     */
    public function isExpired(): bool
    {
        return $this->_isExpired;
    }

    /**
     * Return errors
     *
     * @return array
     */
    public function getErrors(): array
    {
        return $this->_errors;
    }

    /**
     * Add error
     *
     * @param string $error
     * @param string $setFlag = valid|expired|verifed
     * @return void
     */
    private function addError(string $error): void
    {
        array_push($this->_errors, $error);
    }

    /**
     * Set Secret Key
     * 
     * @param mixed $key 
     * @return bool
     * @throws Exception 
     */
    private function setKey($key): bool
    {
        $key = trim($key);
        if (!$key) {
            throw new Exception('Emtpy Secret Key!');
        }
        if (mb_strlen($key) < 6) {
            throw new Exception('Secret key length must be at least 6 characters!');
        }

        $this->_key = $key;
        return true;
    }

    /**
     * Set header for encode
     * 
     * @param array $data 
     * @return void 
     */
    private function setDefaultHeader(): void
    {
        $this->_header = ['typ' => 'JWT', 'alg' => $this->alg];
    }

    /**
     * Set header for decode
     * 
     * @param string $headb64 
     * @return bool 
     */
    private function setHeaderFromB64(string $headb64): bool
    {
        $header = $this->jsonDecode($this->urlsafeB64Decode($headb64));
        $alg = $header['alg'] ?? null;

        if (!count($header)) {
            $this->addError('Invalid header encoding');
            return false;
        }
        $this->_header = $header;

        if (!$alg) {
            $this->addError('Empty header algorithm');
            return false;
        }
        if ($alg != $this->alg) {
            $this->addError('Header algorithm not supported');
            return false;
        }
        
        return true;
    }

    /**
     * Set payload for decode
     * 
     * @param string $bodyb64 
     * @return bool 
     */
    private function setPayloadFromB64(string $bodyb64): bool
    {
        $payload = $this->jsonDecode($this->urlsafeB64Decode($bodyb64));

        if (!count($payload)) {
            $this->addError('Invalid claims encoding');
            return false;
        }

        $this->_payload = $payload;
        $timestamp = time();

        // Check if this token has expired.
        $exp = $payload['exp'] ?? null;
        if ($exp && ($timestamp) >= $exp) {
            $this->addError('Expired token');
            $this->_isExpired = true;
            return false;
        }

        // Check the nbf if it is defined. This is the time that the
        // token can actually be used. If it's not yet that time, abort.
        $nbf = $payload['nbf'] ?? null;
        if ($nbf && $nbf > ($timestamp)) {
            $this->addError('Cannot handle token prior to ' . date(DateTime::ATOM, $nbf));
            return false;
        }

        // Check that this token has been created before 'now'. This prevents
        // using tokens that have been created for later use (and haven't correctly used the nbf claim).
        $iat = $payload['iat'] ?? null;
        if ($iat && $iat > ($timestamp)) {
            $this->addError('Cannot handle token prior to ' . date(DateTime::ATOM, $iat));
            return false;
        }

        return true;
    }

    /**
     * Signature verification
     * 
     * @param string $cryptob64 
     * @param string $msg 
     * @return bool 
     * @throws DomainException 
     */
    private function verifySignatureFromB64(string $cryptob64, string $msg): bool
    {
        $sig = $this->urlsafeB64Decode($cryptob64);

        if (!$this->verify($msg, $sig, $this->_key)) {
            $this->addError('Signature verification failed');
            return false;
        }

        return true;
    }

    /**
     * Sign a string with a given key and algorithm.
     *
     * @param string $msg  The message to sign
     * @param string $key  The secret key.
     * @return string An encrypted message
     */
    private function sign(string $msg, string $key): string 
    {
        return hash_hmac($this->alg, $msg, $key, true);
    }

    /**
     * Verify a signature with the message, key and method.
     *
     * @param string $msg   The original message (header and body)
     * @param string $sign  The original signature
     * @param string $key   A string sekret key
     * @return bool
     */
    private function verify(string $msg, string $sign, string $key): bool 
    {
        $hash = hash_hmac($this->alg, $msg, $key, true);
        return $this->constantTimeEquals($hash, $sign);
    }

    /**
     * Decode a JSON string into a PHP array.
     *
     * @param string $input JSON string
     * @return array
     */
    private function jsonDecode(string $input): array
    {
        $obj = json_decode($input, false, 512, JSON_BIGINT_AS_STRING);

        if ($errno = json_last_error()) {
            $this->handleJsonError($errno);
        } elseif ($obj === null && $input !== 'null') {
            $this->addError('Null result with non-null input');
        }
        return (array) $obj;
    }

    /**
     * Encode a PHP array into a JSON string.
     *
     * @param array<mixed> $input A PHP array
     * @return string JSON representation of the PHP array
     * @throws DomainException Provided object could not be encoded to valid JSON
     */
    private function jsonEncode(array $input): string
    {
        if (PHP_VERSION_ID >= 50400) {
            $json = json_encode($input, \JSON_UNESCAPED_SLASHES);
        } else {
            // PHP 5.3 only
            $json = json_encode($input);
        }
        if ($errno = json_last_error()) {
            $this->handleJsonError($errno);
        } elseif ($json === 'null' && $input !== null) {
            throw new DomainException('Null result with non-null input');
        }
        if ($json === false) {
            throw new DomainException('Provided object could not be encoded to valid JSON');
        }
        return $json;
    }

    /**
     * Decode a string with URL-safe Base64.
     *
     * @param string $input A Base64 encoded string
     * @return string A decoded string
     */
    private function urlsafeB64Decode(string $input): string
    {
        $remainder = strlen($input) % 4;
        if ($remainder) {
            $padlen = 4 - $remainder;
            $input .= str_repeat('=', $padlen);
        }
        return base64_decode(strtr($input, '-_', '+/'));
    }

    /**
     * Encode a string with URL-safe Base64.
     *
     * @param string $input The string you want encoded
     * @return string The base64 encode of what you passed in
     */
    private function urlsafeB64Encode(string $input): string
    {
        return str_replace('=', '', strtr(base64_encode($input), '+/', '-_'));
    }

    /**
     * Compare strings
     * 
     * @param string $left  The string of known length to compare against
     * @param string $right The user-supplied string
     * @return bool
     */
    private function constantTimeEquals(string $left, string $right): bool
    {
        if (function_exists('hash_equals')) {
            return hash_equals($left, $right);
        }
        $len = min($this->safeStrlen($left), $this->safeStrlen($right));

        $status = 0;
        for ($i = 0; $i < $len; $i++) {
            $status |= (ord($left[$i]) ^ ord($right[$i]));
        }
        $status |= ($this->safeStrlen($left) ^ $this->safeStrlen($right));

        return ($status === 0);
    }

    /**
     * Helper method to create a JSON error.
     *
     * @param int $errno An error number from json_last_error()
     * @return void
     */
    private function handleJsonError(int $errno): void
    {
        $messages = [
            JSON_ERROR_DEPTH => 'Maximum stack depth exceeded',
            JSON_ERROR_STATE_MISMATCH => 'Invalid or malformed JSON',
            JSON_ERROR_CTRL_CHAR => 'Unexpected control character found',
            JSON_ERROR_SYNTAX => 'Syntax error, malformed JSON',
            JSON_ERROR_UTF8 => 'Malformed UTF-8 characters'
        ];

        $this->addError(
            isset($messages[$errno])
            ? $messages[$errno]
            : 'Unknown JSON error: ' . $errno
        );
    }

    /**
     * Get the number of bytes in cryptographic strings.
     *
     * @param string $str
     * @return int
     */
    private function safeStrlen(string $str): int
    {
        if (function_exists('mb_strlen')) {
            return mb_strlen($str, '8bit');
        }
        return strlen($str);
    }
}