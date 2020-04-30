<?php

	namespace Stoic\User;

	use Stoic\Log\Logger;
	use Stoic\Pdo\BaseDbQueryTypes;
	use Stoic\Pdo\BaseDbTypes;
	use Stoic\Pdo\StoicDbModel;

	/**
	 * Represents a single user session for authentication purposes.
	 *
	 * @package Stoic\User
	 * @version 1.0.0
	 */
	class Session extends StoicDbModel {
		/**
		 * Network address associated with this session.
		 *
		 * @var string
		 */
		public $address;
		/**
		 * Date and time the session was created.
		 *
		 * @var null|\DateTimeInterface
		 */
		public $created;
		/**
		 * Network hostname associated with this session.
		 *
		 * @var string
		 */
		public $hostname;
		/**
		 * Unique identifier for this session.
		 *
		 * @var integer
		 */
		public $id;
		/**
		 * Token value associated with this session.
		 *
		 * @var string
		 */
		public $token;
		/**
		 * Identifier for user who belongs to this session.
		 *
		 * @var integer
		 */
		public $userId;


		public static function fromId(int $id, \PDO $db, Logger $log = null) : Session {
			$ret = new Session($db, $log);
			$ret->id = $id;

			if ($ret->read()->isBad()) {
				$ret->id = 0;
			}

			return $ret;
		}

		public static function fromToken(int $userId, string $token, \PDO $db, Logger $log = null) : Session {
			if ($userId < 1 || empty($token)) {
				throw new \InvalidArgumentException("Invalid token or user identifier value");
			}

			$ret = new Session($db, $log);

			$ret->tryPdoExcept(function () use ($userId, $token, &$ret) {
				$stmt = $ret->db->prepare($ret->generateClassQuery(BaseDbQueryTypes::SELECT, false) . " WHERE `Token` = :token AND `UserID` = :userId");
				$stmt->bindValue(':token', $token, \PDO::PARAM_STR);
				$stmt->bindValue(':userId', $userId, \PDO::PARAM_INT);
				$stmt->execute();

				if ($stmt->rowCount() > 0) {
					$ret = Session::fromArray($stmt->fetch(\PDO::FETCH_ASSOC), $ret->db, $ret->log);
				}
			}, "Failed to search for user session with token '{$token}'");

			return $ret;
		}

		/**
		 * Returns a (usually) unique	GUID in the typical 8-4-4-4-12 character format.
		 *
		 * @param boolean $withBrackets Whether or not to surround the GUID with curly brackets ({})
		 * @return string
		 */
		public static function generateGuid(bool $withBrackets = true) : string {
			$ret = '';

			// @codeCoverageIgnoreStart
			if (function_exists('com_create_guid')) {
				$ret = com_create_guid();
			} else {
				mt_srand((double)microtime()*10000);//optional for php 4.2.0 and up.
				$charid = strtoupper(md5(uniqid(rand(), true)));
				$hyphen = chr(45);// "-"
				$ret = (chr(123)
					.substr($charid, 0, 8).$hyphen
					.substr($charid, 8, 4).$hyphen
					.substr($charid,12, 4).$hyphen
					.substr($charid,16, 4).$hyphen
					.substr($charid,20,12)
					.chr(125));
			}
			// @codeCoverageIgnoreEnd

			if ($withBrackets) {
				return $ret;
			}

			return trim($ret, '{}');
		}


		protected function __canCreate() {
			if ($this->userId < 1 || $this->id > 0 || empty($this->token)) {
				return false;
			}

			$this->created = new \DateTimeImmutable('now', new \DateTimeZone('UTC'));

			return true;
		}

		protected function __canDelete() {
			if ($this->id < 1) {
				return false;
			}

			return true;
		}

		protected function __canRead() {
			if ($this->id < 1) {
				return false;
			}

			return true;
		}

		protected function __canUpdate() {
			return false;
		}

		protected function __setupModel() : void {
			$this->setTableName('UserSession');
			$this->setColumn('address', 'Address', BaseDbTypes::STRING, false, true, false);
			$this->setColumn('created', 'Created', BaseDbTypes::DATETIME, false, true, false);
			$this->setColumn('hostname', 'Hostname', BaseDbTypes::STRING, false, true, false);
			$this->setColumn('id', 'ID', BaseDbTypes::INTEGER, true, false, false, false, true);
			$this->setColumn('token', 'Token', BaseDbTypes::STRING, false, true, false);
			$this->setColumn('userId', 'UserID', BaseDbTypes::INTEGER, false, true, false);

			$this->id = 0;
			$this->userId = 0;

			return;
		}
	}
