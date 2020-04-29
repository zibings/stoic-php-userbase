<?php

	namespace Stoic\User;

	use Stoic\Log\Logger;
	use Stoic\Pdo\BaseDbModel;
	use Stoic\Pdo\BaseDbTypes;

	/**
	 * Represents a general purpose token for an individual user within the system.
	 *
	 * @package Stoic\User
	 * @version 1.0.0
	 */
	class Token extends BaseDbModel {
		/**
		 * Date and time the token was created.
		 *
		 * @var \DateTimeInterface
		 */
		public $created;
		/**
		 * Short 'purpose' code to provide context for this token.
		 *
		 * @var string
		 */
		public $purpose;
		/**
		 * Unique token string value.
		 *
		 * @var string
		 */
		public $token;
		/**
		 * Identifier of user who belongs to this token.
		 *
		 * @var integer
		 */
		public $userId;


		public static function fromToken(int $userId, string $token, \PDO $db, Logger $log = null) : Token {
			return new Token($db, $log);
		}


		protected function __canCreate() {
			return true;
		}

		protected function __canDelete() {
			return true;
		}

		protected function __canRead() {
			return true;
		}

		protected function __canUpdate() {
			return true;
		}

		protected function __initialize() : void {
			$this->setTableName('UserToken');
			$this->setColumn('created', 'Created', BaseDbTypes::DATETIME, false, true, false);
			$this->setColumn('purpose', 'Purpose', BaseDbTypes::STRING, false, true, false);
			$this->setColumn('token', 'Token', BaseDbTypes::STRING, false, true, false);
			$this->setColumn('userId', 'UserID', BaseDbTypes::INTEGER, false, true, false);

			$this->purpose = 'N/A';
			$this->userId = 0;

			return;
		}
	}
