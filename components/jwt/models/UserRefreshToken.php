<?php

namespace app\components\jwt\models;

use Yii;
use yii\db\ActiveRecord;
use app\models\User;
use yii\behaviors\TimestampBehavior;

/**
 * This is the model class for table "{{%user_refresh_token}}".
 * 
 * Each token is stored separately for the device and the user's IP address.
 *
 * @property integer $id
 * @property integer $user_id
 * @property string  $refresh_token
 * @property integer $expired_at
 * @property integer $created_at
 * @property integer $updated_at
 * 
 * @property User  $user
 */
class UserRefreshToken extends ActiveRecord
{
    /**
     * @inheritdoc
     */
    public static function tableName()
    {
        return '{{%user_refresh_token}}';
    }

    /**
     * {@inheritdoc}
     */
    public function rules()
    {
        return [
            /* Required */
            [['user_id', 'refresh_token'], 'required'],

            /* user_id */
            [
                ['user_id'], 'exist', 'skipOnError' => true, 
                'targetClass' => User::class, 'targetAttribute' => ['user_id' => 'id']
            ],

            /* Safe */
            [['expired_at'], 'safe'],

            /* String */
            [['refresh_token'], 'string', 'max' => 512],
            [['refresh_token'], 'unique'],
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function attributeLabels()
    {
        return [
            'id' => 'ID',
            'user_id' => 'User ID',
            'refresh_token' => 'Refresh Token',
            'expired_at' => 'Expired at',
            'created_at' => 'Login at',
            'updated_at' => 'Updated at',
        ];
    }

    /**
     * @inheritdoc
     */
    public function behaviors()
    {
        return [
            TimestampBehavior::class,
        ];
    }

    /**
     * Get query for [[User]].
     *
     * @return \yii\db\ActiveQuery
     */
    public function getUser(): ?\yii\db\ActiveQuery
    {
        return $this->hasOne(User::class, ['id' => 'user_id']);
    }

    /**
     * Add new refresh_token or use exists
     * 
     * @param int $userId
     * @param int $expire
     * @return static|null
     */
    public static function addTokenByUser(int $userId, int $expire): ?static
    {
        $token = self::getTokenByUser($userId);

        if (!$token) {
            $token = new self();
            $token->user_id = $userId;
        }
        $token->generateToken((time() + $expire));
        $token->save();
        $token->refresh();

        return $token;
    }

    /**
     * Get by userId
     * 
     * @param int $userId
     * @return static|null
     */
    public static function getTokenByUser(int $userId): ?static
    {
        return static::find()
            ->where(['user_id' => $userId])
            ->andWhere(['>', 'expired_at', time()])
            ->one();
    }

    /**
     * Get by refresh_token
     * 
     * @param  string $token
     * @param  bool   $actual - get actual token
     * @return static|null
     */
    public static function getToken(string $token, $actual = true): ?static
    {
        $req = static::find()->where(['refresh_token' => $token]);
        if ($actual) {
            $req->andWhere(['>', 'expired_at', time()]);
        }
        return $req->one();
    }

    /**
     * Get All User refresh tokens
     * 
     * @param int  $userId
     * @return array[static|null]
     */
    public static function getAllTokensByUser(int $userId): array
    {
        return static::find()->where(['user_id' => $userId])->all();
    }

    /**
     * Get user refresh token
     * 
     * @return array
     */
    public function getRefreshToken(): array
    {
        return [
            'refresh_token' => $this->token,
            'expired' => date('Y-m-d H:i:s', $this->expired_at),
        ];
    }

    /**
     * Generates refresh token by expire
     *
     * @param int $expire
     * @return void
     */
    public function generateToken(int $expire): void
    {
        $this->expired_at = $expire;
        $this->refresh_token = \Yii::$app->security->generateRandomString(128);
    }
}
