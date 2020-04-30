<?php

	namespace Stoic\User;

	use Stoic\Log\Logger;
	use Stoic\Pdo\BaseDbQueryTypes;
	use Stoic\Pdo\BaseDbTypes;
	use Stoic\Pdo\StoicDbModel;

	/**
	 * Represents a general purpose token for an individual user within the system.
	 *
	 * @package Stoic\User
	 * @version 1.0.0
	 */
	class Token extends StoicDbModel {
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
			$ret = new Token($db, $log);

			$ret->tryPdoExcept(function () use ($db, $log, $token, $userId, &$ret) {
				$stmt = $ret->db->prepare($ret->generateClassQuery(BaseDbQueryTypes::SELECT, false) . " WHERE `Token` = :token AND `UserID` = :userId");
				$stmt->bindValue(':token', $token, \PDO::PARAM_STR);
				$stmt->bindValue(':userId', $userId, \PDO::PARAM_INT);
				$stmt->execute();

				if ($stmt->rowCount() > 0) {
					$ret = Token::fromArray($stmt->fetch(\PDO::FETCH_ASSOC), $db, $log);
				}
			}, "Failed to check for user token by token");

			return new Token($db, $log);
		}


		protected function __canCreate() {
			if ($this->userId < 1 || empty($this->token) || empty($this->purpose)) {
				return false;
			}

			return true;
		}

		protected function __canDelete() {
			if ($this->userId < 1 || empty($this->token)) {
				return false;
			}

			return true;
		}

		protected function __canRead() {
			if ($this->userId < 1 || empty($this->token)) {
				return false;
			}

			return true;
		}

		protected function __canUpdate() {
			return false;
		}

		protected function __setupModel() : void {
			$this->setTableName('UserToken');
			$this->setColumn('created', 'Created', BaseDbTypes::DATETIME, false, true, false);
			$this->setColumn('purpose', 'Purpose', BaseDbTypes::STRING, false, true, false);
			$this->setColumn('token', 'Token', BaseDbTypes::STRING, true, true, false);
			$this->setColumn('userId', 'UserID', BaseDbTypes::INTEGER, true, true, false);

			$this->purpose = 'N/A';
			$this->userId = 0;

			return;
		}
	}
