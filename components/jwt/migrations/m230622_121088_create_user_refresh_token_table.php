<?php

use yii\db\Migration;

/**
 * Handles the creation of table `{{%user_refresh_token}}`.
 */
class m230622_121088_create_user_refresh_token_table extends Migration
{
    const TABLE_NAME = '{{%user_refresh_token}}';

    /**
     * {@inheritdoc}
     */
    public function up()
    {
        $tableOptions = null;
        if ($this->db->driverName === 'mysql') {
            $tableOptions = 'CHARACTER SET utf8 COLLATE utf8_general_ci ENGINE=InnoDB';
        }

        $this->createTable(self::TABLE_NAME, [
            'id' => $this->primaryKey(),
            'user_id' => $this->integer()->notNull(),
            'refresh_token' => $this->string()->notNull(),
            'expired_at' => $this->integer()->notNull(),
            'created_at' => $this->integer()->notNull(),
            'updated_at' => $this->integer()->notNull(),
        ], $tableOptions);

        $this->createIndex("idx-user_refresh_token-user_id", self::TABLE_NAME, 'user_id');
        $this->createIndex('idx-user_refresh_token-refresh_token', self::TABLE_NAME, 'refresh_token', true);
        $this->addForeignKey('fk-user_refresh_token-user_id', self::TABLE_NAME, 'user_id', '{{%user}}', 'id', 'CASCADE', 'RESTRICT');
    }

    /**
     * {@inheritdoc}
     */
    public function down()
    {
        $this->dropForeignKey('fk-user_refresh_token-user_id', self::TABLE_NAME);

        $this->dropIndex('idx-user_refresh_token-user_id', self::TABLE_NAME);
        $this->dropIndex('idx-user_refresh_token-refresh_token', self::TABLE_NAME);

        $this->dropTable(self::TABLE_NAME);
    }
}
