<?php

namespace app\components\jwt;

use yii\db\Exception;
use yii\di\Instance;
use yii\web\Request;
use yii\web\Response;
use app\components\jwt\JwtService;
use yii\filters\auth\HttpBearerAuth;
use yii\web\UnauthorizedHttpException;
use yii\base\InvalidConfigException;

/**
 * Class JwtBearerAuth - JWT Authentication
 * 
 * JwtBearerAuth can be used by attaching as a behavior to a controller:
 * 
 * ```php
 * public function behaviors()
 * {
 *     $behaviors = parent::behaviors();
 * 
 *     $behaviors['authenticator'] = [
 *         'class' => \app\components\jwt\JwtBearerAuth::class,
 *         'except' => ['login', 'register', 'refresh-token', 'options'] // it's doesn't run in login action
 *     ];
 * 
 *     return $behaviors;
 * }
 * ```
 * 
 * @category Authentication
 * @package  app\components\jwt
 * @author   Dmitry Volkov <kidvol2002@gmail.com>
 * 
 * @link https://github.com/kakadu-dev/yii2-jwt-auth
 */
class JwtBearerAuth extends HttpBearerAuth
{
    /**
     * @var JwtService|null token component instance or null
     */
    public $jwtService;

    /**
     * @var string jwt component name
     */
    public $jwtComponentName = 'jwt';

    /**
     * @inheritdoc
     * @throws InvalidConfigException
     */
    public function init(): void
    {
        parent::init();

        $this->jwtService = Instance::ensure($this->jwtComponentName, JwtService::class);
    }

    /**
     * @inheritdoc
     * @throws Exception
     */
    public function authenticate($user, $request, $response)
    {
        $authHeader = $this->getAuthHeader($request);

        if ($authHeader !== null) {
            // $token = $this->jwtService->getJwtUserId($authHeader);
            $token = $this->jwtService->getJwtUserAuthKey($authHeader);

            if (!$token) {
                $this->failure($response);
                return null;
            }

            $identity = $user->loginByAccessToken($token, get_class($this));
            if ($identity === null) {
                $this->failure($response);
            }

            return $identity;
        }

        return null;
    }

    /**
     * Get header
     *
     * @param Request $request
     * @return null|string
     */
    protected function getAuthHeader($request): ?string
    {
        $authHeader = $request->headers->get($this->header);

        if ($authHeader !== null && preg_match($this->pattern, $authHeader, $matches)) {
            $authHeader = $matches[1];
        } else {
            $authHeader = null;
        }

        return $authHeader;
    }

    /**
     * Failure jwt
     *
     * @param Response $response
     * @throws UnauthorizedHttpException
     */
    protected function failure($response): void
    {
        $this->challenge($response);
        $this->handleFailure($response);
    }
}