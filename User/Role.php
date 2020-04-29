<?php

	namespace Stoic\User;

	use Stoic\Log\Logger;
	use Stoic\Pdo\BaseDbModel;
	use Stoic\Pdo\BaseDbTypes;
	use Stoic\Utilities\ReturnHelper;

	/**
	 * Represents a role available in the system.
	 *
	 * @version 1.0
	 */
	class Role extends BaseDbModel {
		/**
		 * Unique identifier for role.
		 *
		 * @var integer
		 */
		public $id;
		/**
		 * Unique name for role.
		 *
		 * @var string
		 */
		public $name;


		/**
		 * Static method to instantiate a Role object with
		 * a specific identifier.
		 *
		 * @param integer $id Integer value to attempt using as Role identifier.
		 * @param \PDO $db PDO instance for use by object.
		 * @param Logger $log Logger instance for use by object, defaults to new instance.
		 * @return Role
		 */
		public static function fromId($id, \PDO $db, Logger $log = null) {
			$ret = new Role($db, $log);
			$ret->id = intval($id);
			
			if ($ret->read()->isBad()) {
				$ret->id = 0;
			}

			return $ret;
		}


		/**
		 * Determines if the system should attempt to create
		 * a new Role in the database.
		 *
		 * @return boolean
		 */
		protected function __canCreate() {
			if ($this->id > 0 || empty($this->name) || $this->name === null) {
				return false;
			}

			try {
				$stmt = $this->db->prepare("SELECT COUNT(*) FROM `Role` WHERE `Name` = :name");
				$stmt->bindValue(':name', $this->name, \PDO::PARAM_STR);
				$stmt->execute();

				if ($stmt->fetch()['COUNT(*)'] > 0) {
					return false;
				}
			// @codeCoverageIgnoreStart
			} catch (\PDOException $ex) {
				$this->log->error("Error checking for duplicates on creation: {ERROR}", array('ERROR' => $ex->getMessage()));

				return false;
			}
			// @codeCoverageIgnoreEnd

			return true;
		}

		/**
		 * Determines if the system should attempt to delete
		 * a Role from the database.
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
		 * Determines if the system should attempt to read
		 * a Role from the database.
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
		 * Determines if the system should attempt to update
		 * a Role in the database.
		 *
		 * @return ReturnHelper
		 */
		protected function __canUpdate() {
			$ret = new ReturnHelper();
			$ret->makeBad();

			if ($this->id < 1 || empty($this->name) || $this->name === null) {
				$ret->addMessage("Invalid name or identifier for update");

				return $ret;
			}

			try {
				$stmt = $this->db->prepare("SELECT COUNT(*) FROM `Role` WHERE `Name` = :name AND `ID` <> :id");
				$stmt->bindValue(':name', $this->name, \PDO::PARAM_STR);
				$stmt->bindValue(':id', $this->id, \PDO::PARAM_INT);
				$stmt->execute();

				if ($stmt->fetch()['COUNT(*)'] > 0) {
					$ret->addMessage("Found duplicate role with name {$this->name} in database");

					return $ret;
				}
			// @codeCoverageIgnoreStart
			} catch (\PDOException $ex) {
				$this->log->error("Error checking for duplicates on creation: {ERROR}", array('ERROR' => $ex->getMessage()));

				return $ret;
			}
			// @codeCoverageIgnoreEnd

			$ret->makeGood();

			return $ret;
		}

		/**
		 * Initializes a new Role object after its constructor
		 * has been called.
		 *
		 * @return void
		 */
		protected function __initialize() {
			$this->setTableName('Role');
			$this->setColumn('id', 'ID', BaseDbTypes::INTEGER, true, false, false, false, true);
			$this->setColumn('name', 'Name', BaseDbTypes::STRING, false, true, true);

			$this->id = 0;
			$this->name = null;

			return;
		}
	}
