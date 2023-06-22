<?php

use yii\db\Migration;

/**
 * Handles the creation of table `{{%user}}`.
 */
class m230622_091854_create_user_table extends Migration
{
    const TABLE_NAME = '{{%user}}';

    /**
     * {@inheritdoc}
     */
    public function safeUp()
    {
        $tableOptions = null;
        if ($this->db->driverName === 'mysql') {
            $tableOptions = 'CHARACTER SET utf8 COLLATE utf8_general_ci ENGINE=InnoDB';
        }

        $this->createTable(self::TABLE_NAME, [
            'id' => $this->primaryKey(),
            'username' => $this->string()->notNull(),
            'auth_key' => $this->string(32),
            'email_confirm_token' => $this->string(),
            'password_hash' => $this->string()->notNull(),
            'password_reset_token' => $this->string(),
            'email' => $this->string()->notNull(),
            'status' => $this->smallInteger()->notNull()->defaultValue(0),
            'created_at' => $this->integer()->notNull(),
            'updated_at' => $this->integer()->notNull(),
        ], $tableOptions);

        $this->createIndex('idx-user-username', self::TABLE_NAME, 'username', true);
        $this->createIndex('idx-user-email', self::TABLE_NAME, 'email', true);

        /* Create admin user */
        $password = '!qaZse$32i';
        $this->insert(self::TABLE_NAME, [
            'username' => 'admin',
            'email' => Yii::$app->params['adminEmail'] ?? 'admin@mail.ru',
            'auth_key' => Yii::$app->security->generateRandomString(),
            'password_hash' => Yii::$app->security->generatePasswordHash($password),
            'status' => 1,
            'created_at' => time(),
            'updated_at' => time(),
        ]);
    }

    /**
     * {@inheritdoc}
     */
    public function safeDown()
    {
        $this->dropIndex('idx-user-username', self::TABLE_NAME);
        $this->dropIndex('idx-user-email', self::TABLE_NAME);

        $this->dropTable(self::TABLE_NAME);
    }
}
