<?php

namespace app\controllers;

use Yii;
use yii\filters\Cors;
use yii\web\Controller;
use yii\web\Response;
use app\models\LoginForm;
use app\models\ContactForm;
use app\components\jwt\JwtBearerAuth;
use yii\web\UnauthorizedHttpException;

class SiteController extends Controller
{
    /**
     * {@inheritdoc}
     */
    public function behaviors()
    {
        $behaviors = parent::behaviors();

        $behaviors['authenticator'] = [
            'class'  => JwtBearerAuth::class,
            'except' => [
                'options',
                'login',
                'logout',
                'refresh-token'
            ],
        ];

        $behaviors['cors'] = [
            'class' => Cors::class
        ];

        return $behaviors;
    }

    /**
     * {@inheritdoc}
     */
    public function actions()
    {
        return [
            'error' => [
                'class' => 'yii\web\ErrorAction',
            ],
            'captcha' => [
                'class' => 'yii\captcha\CaptchaAction',
                'fixedVerifyCode' => YII_ENV_TEST ? 'testme' : null,
            ],
        ];
    }

    /**
     * Displays homepage.
     *
     * @return string
     */
    public function actionIndex()
    {
        return $this->render('index');
    }

    /**
     * Login action.
     *
     * @return Response|string
     */
    public function actionLogin()
    {
        if (!Yii::$app->user->isGuest) {
            return $this->goHome();
        }

        $model = new LoginForm();
        if ($model->load(Yii::$app->request->post()) && $model->login() && $user = $model->getUser()) {
            /** @var \app\components\jwt\JwtService $jwt */
            $jwt = Yii::$app->jwt;
            $refreshToken = $jwt->generateRefreshToken($user->id);
            $accessToken = $jwt->createJwt(['user_token' => $user->auth_key]);
            // send $refreshToken and $accessToken to front

            return $this->goBack();
        }

        $model->password = '';
        return $this->render('login', [
            'model' => $model,
        ]);
    }

    /**
     * Logout action.
     *
     * @return Response
     */
    public function actionLogout()
    {
        /** @var \app\components\jwt\JwtService $jwt */
        $jwt = Yii::$app->jwt;

        /** @var \yii\web\Request $request */
        $request = Yii::$app->request;

        /** @var string|null $authHeader */
        $authHeader = $request->headers->get('authorization');

        /** @var string|null $refreshToken */
        $refreshToken = $request->post('refreshToken');

        if ($authHeader && $refreshToken && $jwt->deleteCurrentRefreshToken($refreshToken)) {
            Yii::$app->user->logout();
        }
        
        return $this->goHome();
    }

    /**
     * Displays contact page.
     *
     * @return Response|string
     */
    public function actionContact()
    {
        $model = new ContactForm();
        if ($model->load(Yii::$app->request->post()) && $model->contact(Yii::$app->params['adminEmail'])) {
            Yii::$app->session->setFlash('contactFormSubmitted');

            return $this->refresh();
        }
        return $this->render('contact', [
            'model' => $model,
        ]);
    }

    /**
     * Displays about page.
     *
     * @return string
     */
    public function actionAbout()
    {
        return $this->render('about');
    }

    /**
     * Autologin, if access token expired and refresh token not expired.
     *
     * @return string
     * @throws UnauthorizedHttpException
     * @throws ServerErrorHttpException
     * @link https://www.yiiframework.com/wiki/2568/jwt-authentication-tutorial
     */
    public function actionRefreshToken(): string
    {
        /** @var \app\components\jwt\JwtService */
        $jwt = Yii::$app->jwt;
        $token = null;

        if ($refreshToken = Yii::$app->request->post('refreshToken')) {
            $token = $jwt->renewJwtTokens($refreshToken);
        }

        if ($token === null) {
            throw new UnauthorizedHttpException('Wrong request method.');
        }
        
        return $token; 
    }
}
