<?php

	namespace Stoic\User;

	use Stoic\Pdo\BaseDbClass;

	/**
	 * Repository class for common actions with
	 * Roles.
	 *
	 * @version 1.0
	 */
	class Roles extends BaseDbClass {
		/**
		 * Retrieves a role by name.
		 *
		 * TODO: This should probably be a static instantiation
		 * method on the G3\Classes\Role class.  - Andrew (11/01/2018)
		 *
		 * @param string $name Name of role to retrieve.
		 * @return null|Role
		 */
		public function getByName($name) {
			if (empty($name)) {
				$this->log->error("Error retrieving role with invalid name");

				return null;
			}

			$ret = null;

			try {
				$stmt = $this->db->prepare("SELECT `ID`, `Name` FROM `Role` WHERE `Name` = :name");
				$stmt->bindValue(':name', $name, \PDO::PARAM_STR);
				$stmt->execute();

				if ($stmt->rowCount() > 0) {
					$ret = Role::fromArray($stmt->fetch(\PDO::FETCH_ASSOC), $this->db, $this->log);
				}
			} catch (\PDOException $ex) {
				$this->log->error("Error retrieving role: {ERROR}", array('ERROR' => $ex));
			}

			return $ret;
		}

		/**
		 * Retrieves all roles.
		 *
		 * @return Role[]
		 */
		public function getAll() {
			$ret = array();

			try {
				$stmt = $this->db->prepare("SELECT `ID`, `Name` FROM `Role`");
				$stmt->execute();

				if ($stmt->rowCount() > 0) {
					while ($row = $stmt->fetch(\PDO::FETCH_ASSOC)) {
						$ret[] = Role::fromArray($row, $this->db, $this->log);
					}
				}
			} catch (\PDOException $ex) {
				$this->log->error("Error retrieving roles: {ERROR}", array('ERROR' => $ex));
			}

			return $ret;
		}

		/**
		 * Creates a new role if it is missing from
		 * the database.
		 *
		 * Returns created (or existing) role when complete,
		 * or null when there is an error.
		 *
		 * @param string $name Name of role to create/return.
		 * @return null|Role
		 */
		public function createIfMissing($name) {
			$ret = null;

			try {
				$stmt = $this->db->prepare("SELECT `ID`, `Name` FROM `Role` WHERE `Name` = :name");
				$stmt->bindParam(':name', $name, \PDO::PARAM_STR);
				$stmt->execute();
				if ($stmt->rowCount() > 0) {
					$ret = Role::fromArray($stmt->fetch(\PDO::FETCH_ASSOC), $this->db, $this->log);
				} else {
					$tmp = new Role($this->db, $this->log);
					$tmp->name = $name;
					$tmp->create();

					if ($tmp->id > 0) {
						$ret = $tmp;
					}
				}
			} catch (\PDOException $ex) {
				$this->log->error("Error finding/creating role '{NAME}': {MESSAGE}", array('NAME' => $name, 'MESSAGE' => $ex->getMessage()));
			}

			return $ret;
		}
	}
