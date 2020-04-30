<?php

	namespace Stoic\User;

	use Stoic\Pdo\BaseDbClass;

	/**
	 * Repository class for common actions with LoginKeys.
	 *
	 * @version 1.0.0
	 */
	class LoginKeys extends BaseDbClass {
		/**
		 * Retrieves all keys for the given user.
		 *
		 * @param integer $userId Value of user identifier.
		 * @return LoginKey[]
		 */
		public function getAllForUser(int $userId) {
			if ($userId < 1) {
				$this->log->error("Error retrieving login keys for user, called with invalid user identifier");

				return array();
			}

			$ret = array();

			try {
				$stmt = $this->db->prepare("SELECT `UserID`, `Provider`, `Key` FROM `LoginKey` WHERE `UserID` = :id");
				$stmt->bindValue(':id', intval($userId), \PDO::PARAM_INT);
				$stmt->execute();

				if ($stmt->rowCount() > 0) {
					while ($row = $stmt->fetch(\PDO::FETCH_ASSOC)) {
						$ret[] = LoginKey::fromArray($row, $this->db, $this->log);
					}
				}
			} catch (\PDOException $ex) {
				$this->log->error("Error retrieving login keys for user: {ERROR}", array('ERROR' => $ex));
			}

			return $ret;
		}

		/**
		 * Removes all keys for the given user.
		 *
		 * @param integer $userId Value of user identifier.
		 * @return boolean
		 */
		public function deleteAllForUser(int $userId) : bool {
			if ($userId < 1) {
				$this->log->error("Error deleting user login keys, called with invalid user identifier");

				return false;
			}

			try {
				$stmt = $this->db->prepare("DELETE FROM `LoginKey` WHERE `UserID` = :id");
				$stmt->bindValue(':id', intval($userId), \PDO::PARAM_INT);
				$stmt->execute();

				return true;
			} catch (\PDOException $ex) {
				$this->log->error("Error deleting user login keys: {ERROR}", array('ERROR' => $ex));
			}

			return false;
		}
	}
