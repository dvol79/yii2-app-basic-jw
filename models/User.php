<?php

namespace app\models;

use Yii;
use yii\behaviors\TimestampBehavior;
use yii\db\ActiveRecord;
use yii\helpers\ArrayHelper;
use yii\web\IdentityInterface;

/**
 * This is the model class for table "{{%user}}".
 *
 * @property int $id
 * @property string $username
 * @property string $auth_key
 * @property string $email_confirm_token
 * @property string $password_hash
 * @property string $password_reset_token
 * @property string $email
 * @property int $status
 * @property int $created_at
 * @property int $updated_at
 */
class User extends ActiveRecord implements IdentityInterface
{
    const STATUS_BLOCKED = 0;
    const STATUS_ACTIVE = 1;
    const STATUS_WAIT = 2;

    /**
     * @inheritdoc
     */
    public static function tableName()
    {
        return '{{%user}}';
    }

    /**
     * @inheritdoc
     */
    public function rules()
    {
        return [
            ['username', 'required'],
            ['username', 'match', 'pattern' => '#^[\w_-]+$#i'],
            ['username', 'unique', 'targetClass' => self::class],
            ['username', 'string', 'min' => 2, 'max' => 255],

            ['email', 'required'],
            ['email', 'email'],
            ['email', 'unique', 'targetClass' => self::class],
            ['email', 'string', 'max' => 255],

            ['status', 'integer'],
            ['status', 'default', 'value' => self::STATUS_ACTIVE],
            ['status', 'in', 'range' => array_keys(self::getStatusesArray())],
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function attributeLabels()
    {
        return [
            'id' => 'ID',
            'username' => 'User Name',
            'email' => 'Email',
            'status' => 'Status',
            'created_at' => 'Created at',
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
     * Return status name
     * 
     * @return string
     */
    public function getStatusName(): string
    {
        return ArrayHelper::getValue(
            self::getStatusesArray(),
            $this->status,
            'undefined'
        );
    }

    /**
     * Return array status name
     * 
     * @return array
     */
    public static function getStatusesArray(): array
    {
        return [
            self::STATUS_BLOCKED => 'blocked',
            self::STATUS_ACTIVE => 'active',
            self::STATUS_WAIT => 'wait',
        ];
    }

    /**
     * {@inheritdoc}
     */
    public static function findIdentity($id): ?IdentityInterface
    {
        return static::findOne(['id' => $id, 'status' => self::STATUS_ACTIVE]);
    }

    /**
     * @inheritdoc
     */
    public static function findIdentityByAccessToken($token, $type = null): ?IdentityInterface
    {
        return static::findOne([
            'auth_key' => $token,
            'status'   => self::STATUS_ACTIVE
        ]);
    }

    /**
     * Finds user by username
     *
     * @param  string $username
     */
    public static function findByUsername(string $username): ?IdentityInterface
    {
        return static::findOne(['username' => $username,]);
    }

    /**
     * Finds user by email
     *
     * @param string $email
     */
    public static function findByEmail(string $email): ?IdentityInterface
    {
        return static::findOne(['email' => $email,]);
    }

    /**
     * Find user by emailConfirmToken
     * 
     * @param  string $emailConfirmToken
     * @return static|null
     */
    public static function findByEmailConfirmToken($emailConfirmToken): ?IdentityInterface
    {
        return static::findOne([
            'email_confirm_token' => $emailConfirmToken, 
            'status' => self::STATUS_WAIT
        ]);
    }

    /**
     * Finds user by password reset token
     *
     * @param string $token  password reset token
     * @param string $authKey User auth_key
     */
    public static function findByPasswordResetToken(string $token, string $authKey): ?IdentityInterface
    {
        if (!static::isPasswordResetTokenValid($token)) {
            return null;
        }
        return static::findOne([
            'auth_key' => $authKey, 
            'password_reset_token' => $token, 
            'status' => self::STATUS_ACTIVE
        ]);
    }

    /**
     * Finds out if password reset token is valid
     *
     * @param string $token password reset token
     */
    public static function isPasswordResetTokenValid(string $token): bool
    {
        if (empty($token)) {
            return false;
        }

        $timestamp = (int) substr($token, strrpos($token, '_') + 1);
        $expire = Yii::$app->params['user.passwordResetTokenExpire'];
        return $timestamp + $expire >= time();
    }

    /**
     * Generates new password reset token
     */
    public function generatePasswordResetToken(): void
    {
        $this->password_reset_token = Yii::$app->security->generateRandomString(10) . '_' . time();
    }

    /**
     * Removes password reset token
     */
    public function removePasswordResetToken(): void
    {
        $this->password_reset_token = null;
    }

    /**
     * Removes email confirmation token
     */
    public function removeEmailConfirmToken(): void
    {
        $this->email_confirm_token = null;
    }

    /**
     * Generates password hash from password and sets it to the model
     *
     * @param string $password
     */
    public function setPassword($password): void
    {
        $this->password_hash = Yii::$app->security->generatePasswordHash($password);
    }

    /**
     * Validates password
     *
     * @param  string $password password to validate
     * @return bool   if password provided is valid for current user
     */
    public function validatePassword($password): bool
    {
        return Yii::$app->security->validatePassword($password, $this->password_hash);
    }

    /**
     * {@inheritdoc}
     */
    public function getId(): int
    {
        return $this->id;
    }

    /**
     * {@inheritdoc}
     */
    public function getAuthKey(): string
    {
        return $this->auth_key;
    }

    /**
     * {@inheritdoc}
     */
    public function validateAuthKey($authKey): bool
    {
        return $this->auth_key === $authKey;
    }

    /**
     * @inheritdoc
     */
    public function beforeSave($insert)
    {
        if (parent::beforeSave($insert)) {
            if ($insert) {
                $this->generateAuthKey();
            }
            return true;
        }
        return false;
    }
}
