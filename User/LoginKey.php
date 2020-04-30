<?php

	namespace Stoic\User;

	use Stoic\Log\Logger;
	use Stoic\Pdo\BaseDbModel;
	use Stoic\Pdo\BaseDbTypes;
	use Stoic\Utilities\EnumBase;
	use Stoic\Utilities\ReturnHelper;

	/**
	 * Represents a login key that is used to authenticate
	 * a user within the system.
	 *
	 * @version 1.0.0
	 */
	class LoginKey extends BaseDbModel {
		/**
		 * The string value of the login key.
		 *
		 * @var string
		 */
		public $key;
		/**
		 * Which type of provider this key represents.
		 *
		 * @var LoginKeyProviders
		 */
		public $provider;
		/**
		 * User identifier tied to this login key.
		 *
		 * @var integer
		 */
		public $userId;


		/**
		 * Static method to retrieve a login key for the given user and provider type.
		 *
		 * @param integer $userId Integer value to use as the user identifier.
		 * @param integer|LoginKeyProviders $provider Integer value to use as the provider type.
		 * @param \PDO $db PDO instance for use by object.
		 * @param Logger $log Logger instance for use by object, defaults to new instance.
		 * @throws \InvalidArgumentException
		 * @return LoginKey
		 */
		public static function fromUserAndProvider(int $userId, $provider, \PDO $db, Logger $log = null) : LoginKey {
			$lkProvider = EnumBase::tryGetEnum($provider, LoginKeyProviders::class);

			if ($lkProvider->getValue() === null) {
				throw new \InvalidArgumentException("Invalid provider value ({$provider})");
			}

			$ret = new LoginKey($db, $log);
			$ret->userId = intval($userId);
			$ret->provider = $lkProvider;

			if ($ret->read()->isBad()) {
				$ret->userId = 0;
				$ret->provider = new LoginKeyProviders(LoginKeyProviders::ERROR);
			}

			return $ret;
		}


		/**
		 * Determines if the system should attempt to create a new LoginKey in the database.
		 *
		 * @return ReturnHelper
		 */
		protected function __canCreate() {
			$ret = new ReturnHelper();
			$ret->makeBad();

			if ($this->userId < 1 || !LoginKeyProviders::validValue($this->provider->getValue()) || empty($this->key)) {
				$ret->addMessage("Invalid login key values for userId, provider, and/or key");

				return $ret;
			}

			try {
				$stmt = $this->db->prepare("SELECT COUNT(*) FROM `{$this->dbTable}` WHERE `UserID` = :userId AND `Provider` = :provider");
				$stmt->bindValue(':userId', $this->userId, \PDO::PARAM_INT);
				$stmt->bindValue(':provider', $this->provider->value(), \PDO::PARAM_INT);
				$stmt->execute();

				if ($stmt->fetch()['COUNT(*)'] > 0) {
					$ret->addMessage("Found duplicate login key for userId {$this->userId} and provider {$this->provider}");

					return $ret;
				}
			// @codeCoverageIgnoreStart
			} catch (\PDOException $ex) {
				$this->log->error("Failed to check for duplicate login key with error: {ERROR}", array('ERROR' => $ex));
				$ret->addMessage("Failed to check for duplicate login key with error: {$ex->getMessage()}");

				return $ret;
			}
			// @codeCoverageIgnoreEnd

			$ret->makeGood();

			return $ret;
		}

		/**
		 * Determines if the system should attempt to delete a LoginKey from the database.
		 *
		 * @return boolean
		 */
		protected function __canDelete() {
			if ($this->userId < 1 || !LoginKeyProviders::validValue($this->provider->getValue())) {
				return false;
			}

			return true;
		}

		/**
		 * Determines if the system should attempt to read a LoginKey from the database.
		 *
		 * @return boolean
		 */
		protected function __canRead() {
			if ($this->userId < 1 || !LoginKeyProviders::validValue($this->provider->getValue())) {
				return false;
			}

			return true;
		}

		/**
		 * Determines if the system should attempt to update a LoginKey in the database.
		 *
		 * @return boolean
		 */
		protected function __canUpdate() {
			if ($this->userId < 1 || !LoginKeyProviders::validValue($this->provider->getValue()) || empty($this->key)) {
				return false;
			}

			return true;
		}

		/**
		 * Initializes a new LoginKey object after its constructor has been called.
		 *
		 * @return void
		 */
		protected function __setupModel() {
			$this->setTableName('LoginKey');
			$this->setColumn('key', 'Key', BaseDbTypes::STRING, false, true, true);
			$this->setColumn('provider', 'Provider', BaseDbTypes::INTEGER, true, true, false);
			$this->setColumn('userId', 'UserID', BaseDbTypes::INTEGER, true, true, false);

			$this->userId = 0;
			$this->provider = new LoginKeyProviders(LoginKeyProviders::ERROR);

			return;
		}
	}
