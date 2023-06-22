<?php

namespace app\components\jwt;

use yii\web\UnauthorizedHttpException;
use yii\web\ServerErrorHttpException;
use yii\web\Cookie;
use yii\base\BaseObject;
use yii\base\InvalidConfigException;
use app\components\jwt\models\UserRefreshToken;
use DomainException;
use Exception;
use Yii;


/**
 * Class JwtService
 * 
 * Add component in web.php:
 * ```php
 * 'jwt' => [
 *    'class' => 'app\components\jwt\JwtService',
 *    'tokenClass' => 'app\components\jwt\tokens\JwtHs256Token',
 *    'secretKey' => 'Som5-Se6RE1_K4y',
 *    'issuer' => 'you-domain-name',
 *    'audience' => ['you-domain-name', 'other-domain-name],
 * ]
 * ```
 * 
 * Create tokens example:
 * ```
 * $jwt = Yii::$app->jwt;
 * $user = Yii::$app->user;
 * $refreshToken = $jwt->generateRefreshToken($user->id);
 * $accessToken = $jwt->createJwt(['user_token' => $user->auth_key,]);
 * ```
 * 
 * Validate and get payload from JWT example:
 * ```
 * $jwt = Yii::$app->jwt;
 * $token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJTSEEyNTYifQ.eyJ...';
 * $isValid = $jwt->validateJwt($token);    // true or false
 * $payload = $jwt->getJwtPayload($token);  // ['user_token' => 'Yt34K8...',]
 * ```
 * 
 * @category Authentication
 * @package  app\components\jwt
 * @author   Dmitry Volkov <kidvol2002@gmail.com>
 */
class JwtService extends BaseObject
{
    /**
     * @var JwtTokenInterface token
     */
    private JwtTokenInterface $token;

    /**
     * @var string
     */
    public $tokenClass;

    /**
     * @var string
     */
    public $secretKey;

    /**
     * @var string
     */
    public $issuer;

    /**
     * Set false, to disable
     *
     * @var string|array|null
     */
    public $audience;

    /**
     * Access token lifetime
     * Default: 10 minutes
     *
     * @var int in sec
     */
    public $expiration = 60 * 10;

    /**
     * Refresh token lifetime
     * Default: 90 day
     *
     * @var int
     */
    public $expirationRefresh = 60 * 60 * 24 * 90;

    /**
     * {@inheritdoc}
     */
    public function init(): void
    {
        parent::init();

        $this->token = Yii::createObject($this->tokenClass, [$this->getSecretKey()]);
    }

    /**
     * Create JWT token
     * 
     * @param  array $params 
     * @return string|null
     * @throws DomainException 
     */
    public function createJwt(array $params, $checkUser = true): ?string
    {
        if ($issuer = $this->getIssuer()) {
            $params['iss'] = $issuer;
        }

        if ($audience = $this->getAudience()) {
            $params['aud'] = $audience;
        }

        $time = time();
        $params['iat'] = $time;
        $params['nbf'] = $time;
        $params['exp'] = $this->getExpiration($time);

        if ($checkUser && !isset($params['user_token'])) {
            throw new DomainException('There no user_token in params!');
        }

        $token = $this->token;
        if ($token->setPayload($params) && $token->encode()) {
            return $token->getToken();
        }

        return null;
    }

    /**
     * Return is the token verified flag
     *
     * @param string $jwtToken
     * @return bool
     */
    public function validateJwt(string $jwtToken): bool
    {
        $token = $this->getDecodedJwt($jwtToken);

        return $token ? $token->isValid() : false;
    }

    /**
     * Return JWT Payload
     * 
     * @param string $jwtToken 
     * @return array
     */
    public function getJwtPayload(string $jwtToken): array
    {
        $jwtToken = $this->getDecodedJwt($jwtToken);
    
        return ($jwtToken && $jwtToken->isValid()) ? $jwtToken->getPayload() : [];
    }

    /**
     * Return JWT user_id 
     * 
     * @param string $jwtToken 
     * @return int|null
     */
    public function getJwtUserId(string $jwtToken): ?int
    {
        $jwtToken = $this->getDecodedJwt($jwtToken);
    
        return ($jwtToken && $jwtToken->isValid()) ? $jwtToken->getClaim('user_id') : null;
    }

    /**
     * Return JWT user_token 
     * 
     * @param string $jwtToken 
     * @return string|null
     */
    public function getJwtUserAuthKey(string $jwtToken): ?string
    {
        $jwtToken = $this->getDecodedJwt($jwtToken);
    
        return ($jwtToken && $jwtToken->isValid()) ? $jwtToken->getClaim('user_token') : null;
    }

    /**
     * Get all User refresh tokens (sessions)
     * 
     * @param int $userId 
     * @return array 
     * @throws InvalidConfigException 
     */
    public function getAllUserSessions(int $userId): array
    {
        return UserRefreshToken::findAll(['user_id' => $userId]);
    }

    /**
     * Create new Refresh Token
     * 
     * @param  int  $userId
     * @param  bool $setCookie set refresh token by cookie
     * @return UserRefreshToken
     * @throws UnauthorizedHttpException
     */
    public function generateRefreshToken(int $userId, $setCookie = false): UserRefreshToken
    {
        $userRefreshToken = UserRefreshToken::addTokenByUser($userId, $this->expirationRefresh);

		if (!$userRefreshToken) {
            throw new ServerErrorHttpException('Failed to create refresh token.', 500);
        }

		// Send the refresh-token to the user in a HttpOnly cookie
        if ($setCookie) {
            Yii::$app->response->cookies->add(new Cookie([
                'name' => 'refresh-token',
                'value' => $userRefreshToken->refresh_token,
                'httpOnly' => true,
                'sameSite' => 'none',
                // 'path' => '/auth/refresh-token',
                // 'secure' => true,  // Uncomment on PROD
            ]));
        }

		return $userRefreshToken;
    }

    /**
     * Delete Current Refresh Token
     * 
     * @param  string|null $refreshToken
     * @return bool
     * @throws ServerErrorHttpException
     */
    public function deleteCurrentRefreshToken($refreshToken = null): bool
    {
        $userRefreshToken = $refreshToken 
            ? UserRefreshToken::getToken($refreshToken)
            : $this->getRefreshToken();

        if (!$userRefreshToken) {
            throw new ServerErrorHttpException('Not found current refresh token.');
        }

        if (!$userRefreshToken->delete()) {
            throw new ServerErrorHttpException('Failed to delete the refresh token.');
        }

        return true;
    }

    /**
     * Delete all User Refresh Tokens
     * 
     * @param  int $userId
     * @return bool
     * @throws NotSupportedException
     */
    public function deleteAllUserTokens($userId)
    {
        $res = UserRefreshToken::deleteAll(['user_id' => $userId]);

        return boolval($res);
    }

    /**
     * Renew Access Token
     * 
     * @param  string|null $refreshToken
     * @return string generated new access token
     * @throws UnauthorizedHttpException
     */
    public function renewJwtTokens($refreshToken = null): string
    {
        $userRefreshToken = $refreshToken 
            ? UserRefreshToken::getToken($refreshToken)
            : $this->getRefreshToken();

        if (!$userRefreshToken) {
            throw new UnauthorizedHttpException('No refresh token found.');
        }

        $user = $userRefreshToken->user;
        if (!$user) {
            $userRefreshToken->delete();
            throw new UnauthorizedHttpException('The user is inactive.');
        }

        $token = $this->createJwt(['user_token' => $user->auth_key]);
        if (!$token) {
            throw new ServerErrorHttpException('Access Token create Error.');
        }

        return $token;
    }

    /**
     * Get expiration
     *
     * @param  int $time
     * @return int
     */
    private function getExpiration(int $time): int
    {
        $expiration = $this->expiration ?? 60 * 5;
        return $time + $expiration;
    }

    /**
     * Get secret key
     *
     * @return string|null
     */
    private function getSecretKey(): ?string
    {
        return $this->getConfigValue($this->secretKey);
    }

    /**
     * Get issuer
     *
     * @return string|null
     */
    private function getIssuer(): ?string
    {
        return $this->getConfigValue($this->issuer);
    }

    /**
     * Get audience
     *
     * @return array|string|bool
     */
    private function getAudience()
    {
        $audience = $this->audience ?? $this->getIssuer();

        if (is_array($audience)) {
            $audience = array_map(function ($value) {
                return $this->getConfigValue($value);
            }, $audience);
        }

        return $audience;
    }

    /**
     * Parse value and return itself or real value from `Yii::$app->params`
     *
     * @param string $value
     * @return mixed
     */
    private function getConfigValue($value)
    {
        $inParams = explode('yii-params.', $value);

        if (!empty($inParams[1])) {
            return Yii::$app->params[$inParams[1]] ?? $value;
        }

        return $value;
    }

    /**
     * Decode jwt string to Token object
     *
     * @param string $jwtToken
     * @return JwtTokenInterface|null
     */
    private function getDecodedJwt(string $jwtToken): ?JwtTokenInterface
    {
        try {
            $token = $this->token;
            $token->setToken($jwtToken);
            $token->decode();

            return $token;
        } catch (Exception $e) {
            Yii::error("Decode token $jwtToken error: {$e->getMessage()}");

            return null;
        }
    }

    /**
     * Get Refresh Token from Cookies
     * 
     * @param bool $actual - time valid
     * @return UserRefreshToken|null 
     */
    private function getRefreshToken($actual = true)
    {
        $refreshToken = Yii::$app->request->cookies->getValue('refresh-token', null);
        
        return $refreshToken 
            ? UserRefreshToken::getToken($refreshToken, $actual) 
            : null;
    }
}