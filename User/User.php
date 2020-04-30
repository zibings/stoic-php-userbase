<?php

	namespace Stoic\User;

	use Stoic\Log\Logger;
	use Stoic\Pdo\BaseDbQueryTypes;
	use Stoic\Pdo\BaseDbTypes;
	use Stoic\Pdo\StoicDbModel;
	use Stoic\Utilities\ReturnHelper;

	/**
	 * Represents a user within the system.
	 *
	 * @version 1.0.0
	 */
	class User extends StoicDbModel {
		/**
		 * User's email address.
		 *
		 * @var string
		 */
		public $email;
		/**
		 * Whether or not the user has confirmed their email address is real.
		 *
		 * @var boolean
		 */
		public $emailConfirmed;
		/**
		 * Date and time the user's account was created.
		 *
		 * @var \DateTimeInterface
		 */
		public $dateJoined;
		/**
		 * Unique identifier for user.
		 *
		 * @var integer
		 */
		public $id;
		/**
		 * Date and time the user last logged into the site.
		 *
		 * @var null|\DateTimeInterface
		 */
		public $lastLogin;
		/**
		 * Display name for user.
		 *
		 * @var string
		 */
		public $name;


		/**
		 * Static method to instantiate a user from the given email address.
		 *
		 * @param string $email Email address to use when looking for user.
		 * @param \PDO $db PDO instance for use by object.
		 * @param Logger $log Logger instance for use by object, defaults to new instance.
		 * @return User
		 */
		public static function fromEmail(string $email, \PDO $db, Logger $log = null) : User {
			$ret = new User($db, $log);

			if (!static::validEmail($email)) {
				$ret->log->error("Error retrieving user: invalid email address");

				return $ret;
			}

			$ret->tryPdoExcept(function () use ($email, &$ret) {
				$stmt = $ret->db->prepare($ret->generateClassQuery(BaseDbQueryTypes::SELECT, false) . " WHERE `Email` = :email");
				$stmt->bindValue(':email', $email, \PDO::PARAM_STR);
				$stmt->execute();

				if ($stmt->rowCount() > 0) {
					$ret = User::fromArray($stmt->fetch(\PDO::FETCH_ASSOC), $ret->db, $ret->log);
				}
			}, "Error retrieving user");

			return $ret;
		}

		/**
		 * Static method to retrieve a user by their unique identifier.
		 *
		 * @param integer $id Integer value to attempt using as User identifier.
		 * @param \PDO $db PDO instance for use by object.
		 * @param Logger $log Logger instance for use by object, defaults to new instance.
		 * @return User
		 */
		public static function fromId(int $id, \PDO $db, Logger $log = null) : User {
			$ret = new User($db, $log);
			$ret->id = intval($id);

			if ($ret->read()->isBad()) {
				$ret->id = 0;
			}

			return $ret;
		}

		/**
		 * Static method to determine if a provided string is a valid email address.
		 *
		 * @param string $string String to validate as an email address.
		 * @return boolean
		 */
		public static function validEmail(string $string) : bool {
			return filter_var($string, FILTER_VALIDATE_EMAIL) !== false;
		}

		/**
		 * Static method to determine if a provided string is a valid username.
		 *
		 * @param string $string String to validate as a username.
		 * @return boolean
		 */
		public static function validName(string $string) : bool {
			if (empty($string)) {
				return false;
			}

			return true;
		}


		/**
		 * Determines if the system should attempt to create a new User in the database.
		 *
		 * @return ReturnHelper
		 */
		protected function __canCreate() {
			$ret = new ReturnHelper();
			$ret->makeBad();

			if ($this->id > 0 || !static::validName($this->name) || !static::validEmail($this->email)) {
				$ret->addMessage("Cannot create a User with invalid name, email, or id fields");

				return $ret;
			}

			$this->tryPdoExcept(function () use (&$ret) {
				$stmt = $this->db->prepare("SELECT COUNT(*) FROM {$this->prepColumn('User')} WHERE {$this->prepColumn('Email')} = :email");
				$stmt->bindValue(':email', $this->email, \PDO::PARAM_STR);
				$stmt->execute();

				if ($stmt->fetch()['COUNT(*)'] > 0) {
					$ret->addMessage("Found duplicate User by email, unable to create (Email: {$this->email})");

					return;
				}

				$this->dateJoined = new \DateTimeImmutable('now', new \DateTimeZone('UTC'));

				$ret->makeGood();
			}, "Failed to check for User duplicates during creation");

			return $ret;
		}

		/**
		 * Determines if the system should attempt to delete a User from the database.
		 *
		 * @return boolean
		 */
		protected function __canDelete() {
			if ($this->id < 1) {
				return false;
			}

			return true;
		}

		/**
		 * Determines if the system should attempt to read a User from the database.
		 *
		 * @return boolean
		 */
		protected function __canRead() {
			if ($this->id < 1) {
				return false;
			}

			return true;
		}

		/**
		 * Determines if the system should attempt to update a User in the database.
		 *
		 * @return ReturnHelper
		 */
		protected function __canUpdate() {
			$ret = new ReturnHelper();
			$ret->makeBad();

			if ($this->id < 1 || !static::validName($this->name) || !static::validEmail($this->email)) {
				$ret->addMessage("Invalid data for User update (check ID, Name, and Email for valid values.");

				return $ret;
			}

			$this->tryPdoExcept(function () use (&$ret) {
				$stmt = $this->db->prepare("SELECT COUNT(*) FROM `User` WHERE `Email` = :email AND `ID` <> :id");
				$stmt->bindValue(':email', $this->email, \PDO::PARAM_STR);
				$stmt->bindValue(':id', $this->id, \PDO::PARAM_INT);
				$stmt->execute();

				if ($stmt->fetch()['COUNT(*)'] > 0) {
					$ret->addMessage("Found duplicate User by email, unable to update (Email: {$this->email})");

					return;
				}

				$ret->makeGood();
			}, "Failed to check for User duplicates during update");

			return $ret;
		}

		/**
		 * Initializes a new User object after its constructor has been called.
		 *
		 * @return void
		 */
		protected function __setupModel() : void {
			$this->setTableName('User');
			$this->setColumn('email', 'Email', BaseDbTypes::STRING, false, true, true);
			$this->setColumn('emailConfirmed', 'EmailConfirmed', BaseDbTypes::BOOLEAN, false, true, true);
			$this->setColumn('dateJoined', 'DateJoined', BaseDbTypes::DATETIME, false, true, false);
			$this->setColumn('id', 'ID', BaseDbTypes::INTEGER, true, false, false, false, true);
			$this->setColumn('lastLogin', 'LastLogin', BaseDbTypes::DATETIME, false, true, true, true);
			$this->setColumn('name', 'Name', BaseDbTypes::STRING, false, true, true);

			$this->id = 0;
			$this->lastLogin = null;
			$this->emailConfirmed = false;

			return;
		}
	}
