<?php

	namespace Stoic\User;

	use Stoic\Log\Logger;
	use Stoic\Pdo\BaseDbClass;

	/**
	 * Repository class for common actions with
	 * Users.
	 *
	 * @version 1.0.0
	 */
	class Users extends BaseDbClass {
		/**
		 * Retrieves the name for the given user.
		 *
		 * @param integer $userId Identifier of the user.
		 * @return string
		 */
		public function getUserName(int $userId) {
			$user = User::fromId($userId, $this->db, $this->log);

			return $user->name;
		}

		/**
		 * Retrieves a set of users from the database.
		 *
		 * @param null|integer $limit Optional limit for returned set.
		 * @param null|integer $offset Optional offset for returned set.
		 * @return User[]
		 */
		public function getUsers($limit = null, $offset = null) {
			$ret = array();
			$sql = "SELECT `Email`, `EmailConfirmed`, `DateJoined`, `ID`, `LastLogin`, `Name`, `Theme` FROM `User`";

			if ($limit !== null) {
				$sql .= " LIMIT ";

				if ($offset !== null) {
					$sql .= "{$offset},{$limit}";
				} else {
					$sql .= $limit;
				}
			}

			try {
				$stmt = $this->db->prepare($sql);
				$stmt->execute();

				if ($stmt->rowCount() > 0) {
					while ($row = $stmt->fetch(\PDO::FETCH_ASSOC)) {
						$ret[] = User::fromArray($row, $this->db, $this->log);
					}
				}
			} catch (\PDOException $ex) {
				$this->log->error("Error retrieving all users: {ERROR}", array('ERROR' => $ex));
			}

			return $ret;
		}

		/**
		 * Retrieves the number of users in the database.
		 *
		 * @return integer
		 */
		public function getUsersCount() {
			$ret = 0;

			try {
				$stmt = $this->db->prepare("SELECT COUNT(*) FROM `User`");
				$stmt->execute();

				if ($stmt->rowCount() > 0) {
					$ret = $stmt->fetch()['COUNT(*)'];
				}
			} catch (\PDOException $ex) {
				$this->log->error("Error retrieving user count: {ERROR}", array('ERROR' => $ex));
			}

			return $ret;
		}

		/**
		 * Retrieves all users in the database and returns them as a
		 * list of strings with the user's name and email address.
		 *
		 * @return string[]
		 */
		public function getUsersForTypeahead() {
			$ret = [];
			$this->tryPdoExcept(function (\PDO $db, Logger $log) use (&$ret) {
				$stmt = $this->db->prepare("SELECT `Email`, `Name` FROM `User`");
				$stmt->execute();

				if ($stmt->rowCount() > 0) {
					while ($row = $stmt->fetch(\PDO::FETCH_ASSOC)) {
						$ret[] = "{$row['Name']} ({$row['Email']})";
					}
				}
			}, "Failed to retrieve list of users for typeahead control");

			return $ret;
		}
	}
