<?php

	namespace Stoic\User;

	use AndyM84\Config\ConfigContainer;
	use Stoic\Log\Logger;
	use Stoic\Utilities\ParameterHelper;
	use Stoic\Utilities\ReturnHelper;
	use Stoic\Web\Resources\HttpStatusCodes;

	/**
	 * Class that provides several common operations
	 * for users within the system, as well as ways
	 * to be notified when the operations complete.
	 *
	 * @version 1.0.0
	 */
	class UserEvents {
		const EVT_AUTH = 'auth';
		const EVT_CREATE = 'create';
		const EVT_DELETE = 'delete';
		const EVT_LOGIN = 'login';
		const EVT_LOGOUT = 'logout';
		const EVT_RESETPASSWORD = 'resetPassword';
		const EVT_UPDATE = 'update';
		const STR_DATA = 'data';
		const STR_HTTP_CODE = 'http_code';


		/**
		 * Internal \PDO instance.
		 *
		 * @var \PDO
		 */
		protected $db = null;
		/**
		 * Internal \Stoic\Log\Logger instance.
		 *
		 * @var \Stoic\Log\Logger
		 */
		protected $log = null;
		/**
		 * Static collection of operation events.
		 *
		 * @var array
		 */
		protected static $events = [
			self::EVT_AUTH => [],
			self::EVT_CREATE => [],
			self::EVT_DELETE => [],
			self::EVT_LOGIN => [],
			self::EVT_LOGOUT => [],
			self::EVT_RESETPASSWORD => [],
			self::EVT_UPDATE => []
		];


		/**
		 * Static method to assign a subscriber callback to an event.
		 *
		 * @param string $event Key value of event.
		 * @param callable $subscriber Callable subscriber to add.
		 * @return void
		 */
		protected static function assignSubscriber($event, callable $subscriber) {
			self::$events[$event][] = $subscriber;

			return;
		}

		/**
		 * Static method to subscribe to the AUTH user operation
		 * event.
		 *
		 * @param callable $subscriber Callable subscriber to add.
		 * @return void
		 */
		public static function subscribeToAuth(callable $subscriber) {
			static::assignSubscriber(self::EVT_AUTH, $subscriber);

			return;
		}

		/**
		 * Static method to subscriber to the CREATE user operation
		 * event.
		 *
		 * @param callable $subscriber Callable subscriber to add.
		 * @return void
		 */
		public static function subscribeToCreate(callable $subscriber) {
			static::assignSubscriber(self::EVT_CREATE, $subscriber);

			return;
		}

		/**
		 * Static method to subscribe to the DELETE user operation
		 * event.
		 *
		 * @param callable $subscriber Callable subscriber to add.
		 * @return void
		 */
		public static function subscribeToDelete(callable $subscriber) {
			static::assignSubscriber(self::EVT_DELETE, $subscriber);

			return;
		}

		/**
		 * Static method to subscribe to the LOGIN user operation
		 * event.
		 *
		 * @param callable $subscriber Callable subscriber to add.
		 * @return void
		 */
		public static function subscribeToLogin(callable $subscriber) {
			static::assignSubscriber(self::EVT_LOGIN, $subscriber);

			return;
		}

		/**
		 * Static method to subscribe to the LOGOUT user operation
		 * event.
		 *
		 * @param callable $subscriber Callable subscriber to add.
		 * @return void
		 */
		public static function subscribeToLogout(callable $subscriber) {
			static::assignSubscriber(self::EVT_LOGOUT, $subscriber);

			return;
		}

		/**
		 * Static method to subscribe to the RESETPASSWORD user
		 * operation event.
		 *
		 * @param callable $subscriber Callable subscriber to add.
		 * @return void
		 */
		public static function subscribeToResetPassword(callable $subscriber) {
			static::assignSubscriber(self::EVT_RESETPASSWORD, $subscriber);

			return;
		}

		/**
		 * Static method to subscribe to the UPDATE user operation
		 * event.
		 *
		 * @param callable $subscriber Callable subscriber to add.
		 * @return void
		 */
		public static function subscribeToUpdate(callable $subscriber) {
			static::assignSubscriber(self::EVT_UPDATE, $subscriber);

			return;
		}

		/**
		 * Static method to notify all subscribers to an event.
		 *
		 * @param string $event Key value of event.
		 * @param array $args Arguments to pass along to subscriber callables.
		 * @return void
		 */
		protected static function touchEvent($event, ...$args) {
			foreach (array_values(static::$events[$event]) as $callable) {
				call_user_func_array($callable, $args);
			}

			return;
		}


		/**
		 * Instantiates a new UserEvents object.
		 *
		 * @param \PDO $db PDO instance for use by object.
		 * @param Logger $log Logger instance for use by object, defaults to new instance.
		 */
		public function __construct(\PDO $db, Logger $log = null) {
			$this->db = $db;
			$this->log = $log ?? new Logger();

			return;
		}

		/**
		 * Performs the AUTH event and notifies subscribers
		 * if successful.
		 *
		 * @param ParameterHelper $params Parameters for performing operation.
		 * @return ReturnHelper
		 */
		public function auth(ParameterHelper $params) {
			$ret = new ReturnHelper();

			if (!$params->hasValue('email') || !$params->hasValue('password')) {
				$ret->addMessage("Missing parameters for authorization");
				$ret->addResult([self::STR_HTTP_CODE => HttpStatusCodes::INTERNAL_SERVER_ERROR]);

				return $ret;
			}

			$email = $params->getString('email');
			$password = $params->getString('password');
			$user = User::fromEmail($email, $this->db, $this->log);

			if ($user->id < 1) {
				$ret->addMessage("Invalid credentials supplied");
				$ret->addResult([self::STR_HTTP_CODE => HttpStatusCodes::INTERNAL_SERVER_ERROR]);

				return $ret;
			}

			$key = LoginKey::fromUserAndProvider($user->id, LoginKeyProviders::BASIC, $this->db, $this->log);

			if ($key->userId < 1) {
				$ret->addMessage("No login available for user");
				$ret->addResult([self::STR_HTTP_CODE => HttpStatusCodes::INTERNAL_SERVER_ERROR]);

				return $ret;
			}

			if (!password_verify($password, $key->key)) {
				$ret->addMessage("Invalid credentials provided");
				$ret->addResult([self::STR_HTTP_CODE => HttpStatusCodes::INTERNAL_SERVER_ERROR]);
				$this->log->error("Failed login because of password mismatch: '{$email}'");

				return $ret;
			}

			if (password_needs_rehash($key->key, PASSWORD_DEFAULT)) {
				$key->key = password_hash($password, PASSWORD_DEFAULT);

				try {
					$key->update();
				} catch (\Exception $ex) {
					$this->log->warning("Failed to rehash password for user '{$email}' with error: {ERROR}", ['ERROR' => $ex]);
				}
			}

			$user->lastLogin = new \DateTimeImmutable('now', new \DateTimeZone('UTC'));
			
			if ($user->update()->isBad()) {
				$this->log->warning("Failed to update last login time for user '{$email}'");
			}

			$ret->makeGood();
			$ret->addResult([
				self::STR_HTTP_CODE => HttpStatusCodes::OK,
				self::STR_DATA => ['userId' => $user->id]
			]);

			static::touchEvent(self::EVT_AUTH, $user->id, $this->db, $this->log);

			return $ret;
		}

		/**
		 * Performs the CREATE event and notifies subscribers
		 * if successful.
		 *
		 * @param ParameterHelper $params Parameters for performing operation.
		 * @param ConfigContainer $settings System settings to use while performing operation.
		 * @param null|string $siteRoot Optional site root to override for PageHelper instances.
		 * @return ReturnHelper
		 */
		public function create(ParameterHelper $params, ConfigContainer $settings, $siteRoot = null) {
			$ret = new ReturnHelper();

			if (!$params->hasValue('email') || !$params->hasValue('new_password') || !$params->hasValue('confirm_password') || !$params->hasValue('name')) {
				$ret->addMessage("Failed to create account, please contact an administrator");
				$this->log->error("Failed to create account, invalid parameter set");

				return $ret;
			}

			$email = $params->getString('email');
			$name = $params->getString('name');
			$new1 = $params->getString('new_password');
			$new2 = $params->getString('confirm_password');
			$preConfirm = $params->getBool('email_confirmed', false);
            $userRole = $params->getString('role');

			if ($new1 !== $new2 || empty($new1)) {
				$ret->addMessage("Failed to create account, please contact an administrator");
				$this->log->error("Failed to create account, password mismatch for '{$email}'");

				return $ret;
			}

			$user = new User($this->db, $this->log);

			try {
				$user->email = $email;
				$user->emailConfirmed = $preConfirm;
				$user->name = $name;
				$create = $user->create();

				if ($create->isBad()) {
					$ret->addMessage("Failed to create account, please contact an administrator");
					$this->log->error("Failed to create account, issue with user account creation");

					return $ret;
				}

				$key = new LoginKey($this->db, $this->log);

				$key->userId = $user->id;
				$key->provider = new LoginKeyProviders(LoginKeyProviders::BASIC);
				$key->key = password_hash($new1, PASSWORD_DEFAULT);
				$create = $key->create();

				if ($create->isBad()) {
					$user->delete();
					$ret->addMessage("Failed to create account, please contact an administrator");
					$this->log->error("Failed to create login key for user '{$email}'");

					return $ret;
				}

				$ret->makeGood();
				static::touchEvent(self::EVT_CREATE, $user, $this->db, $this->log);
			} catch (\Exception $ex) {
				$ret->addMessage("Failed to create account, please contact an administrator");
				$this->log->error("Failed to create account for user '{$email}': {ERROR}", ['ERROR' => $ex]);
			}

			return $ret;
		}

		/**
		 * Performs the DELETE event and notifies subscribers
		 * if successful.
		 *
		 * @param ParameterHelper $params Parameters for performing operation.
		 * @return ReturnHelper
		 */
		public function delete(ParameterHelper $params) {
			$ret = new ReturnHelper();

			if (!$params->hasValue('id') || !$params->hasValue('uid') || !$params->hasValue('token')) {
				$ret->addMessage("Failed to delete user, incomplete parameters");

				return $ret;
			}

			$id = $params->getInt('id');
			$executorId = $params->getInt('uid');

			if ($executorId == $id) {
				$ret->addMessage("Failed to delete user, you shouldn't delete yourself");

				return $ret;
			}

			$roleRepo = new UserRoles($this->db, $this->log);
			$executorIsAdmin = $roleRepo->userInRoleByRoleName($executorId, RoleStrings::ADMINISTRATOR, 0);

			if (!$executorIsAdmin) {
				$ret->addMessage("Failed to delete user, admin role mismatch");
				$this->log->error("Failed to delete user #{$id} because executor (user #{$executorId}) was not a site admin");

				return $ret;
			}

			try {
				$user = User::fromId($id, $this->db, $this->log);
				
				if ($user->delete()->isGood()) {
					$ret->makeGood();

					$roleRepo->removeAllUserOrganizationRoles($id, 0);
					(new LoginKeys($this->db, $this->log))->deleteAllForUser($id);

					static::touchEvent(self::EVT_DELETE, $user, $this->db, $this->log);
				}
			} catch (\Exception $ex) {
				$ret->addMessage("Failed to delete user, an exception occurred");
				$this->log->error("Failed to delete user #{$id} by user #{$executorId} with error: {ERROR}", ['ERROR' => $ex]);
			}

			return $ret;
		}

		/**
		 * Performs the LOGIN event and notifies subscribers
		 * if successful.
		 *
		 * @param ParameterHelper $params Parameters for performing operation.
		 * @param mixed $requiredRole Optional role or array of roles to further secure login.
		 * @return ReturnHelper
		 */
		public function login(ParameterHelper $params, $requiredRole = null) {
			$ret = new ReturnHelper();

			// TODO: Call AUTH and then do extra work

			if (!$params->hasValue('email') || !$params->hasValue('password')) {
				$ret->addMessage("Invalid parameter set provided, please try again");

				return $ret;
			}

			$email = $params->getString('email');
			$password = $params->getString('password');
			$user = User::fromEmail($email, $this->db, $this->log);

			if ($user->id < 1) {
				$ret->addMessage("Invalid account provided");

				return $ret;
			}

			if (!$user->emailConfirmed) {
				$ret->addMessage("Unverified account provided");

				return $ret;
			}

			$key = LoginKey::fromUserAndProvider($user->id, LoginKeyProviders::BASIC, $this->db, $this->log);

			if ($key->userId < 1) {
				$ret->addMessage("Invalid account provided");

				return $ret;
			}

			if (!password_verify($password, $key->key)) {
				$ret->addMessage("Invalid credentials provided");

				return $ret;
			}

			$roleRepo = new UserRoles($this->db, $this->log);

			// TODO: Someday we'll need to likely make this more granular for organization-specific logins.  - Andrew, 10/22/2018
			if ($requiredRole !== null && !$roleRepo->userInRoleByRoleName($user->id, $requiredRole, 0)) {
				$ret->addMessage("Invalid credentials provided");

				return $ret;
			}

			if ($requiredRole === null && count($roleRepo->getAllUserRoles($user->id)) < 1) {
				$ret->addMessage("Invalid account permissions");

				return $ret;
			}

			if (password_needs_rehash($key->key, PASSWORD_DEFAULT)) {
				$key->key = password_hash($password, PASSWORD_DEFAULT);

				try {
					$key->update();
				} catch (\Exception $ex) {
					$this->log->warning("Failed to rehash password for user '{$user->email}': {ERROR}", ['ERROR' => $ex]);
				}
			}

			try {
				$user->lastLogin = new \DateTimeImmutable('now', new \DateTimeZone('UTC'));
				$user->update();
			} catch (\Exception $ex) {
				$this->log->warning("Failed to update last login time to user '{$user->email}': {ERROR}", ['ERROR' => $ex]);
			}

			// TODO: Create 'SessionToken' model/repo

			$sess = new ApiSession($this->db, $this->log);
			$sess->userId = $user->id;
			$sess->token = \G3\Utilities\getGuid(false);
			$sess->hostname = gethostbyaddr($_SERVER[PhpStrings::Server_Remote_Addr]);
			$sess->address = $_SERVER[PhpStrings::Server_Remote_Addr];

			try {
				$event = $sess->create();

				if ($event->isGood()) {
					$_SESSION[SessionStrings::Key_ApiToken] = $sess->token;
					$_SESSION[SessionStrings::Key_UserId] = $user->id;

					$ret->makeGood();
					$ret->addResult(['user' => $user, 'session' => $sess]);
					$this->aLog->logActivity(Activities::LOGIN, $user->id);
					static::touchEvent(self::EVT_LOGIN, $user, $sess, $this->db, $this->log);

					return $ret;
				}

				if ($event->hasMessages()) {
					$ret->addMessage($event->getMessages()[0]);
				} else {
					$ret->addMessage("Issue creating API session");
				}
			} catch (\Exception $ex) {
				$ret->addMessage("Failed to create API session");
				$this->log->error("Failed to create API session for user '{$user->email}': {ERROR}", ['ERROR' => $ex]);
			}

			return $ret;
		}

		/**
		 * Performs the LOGOUT event and notifies subscribers
		 * if successful.
		 *
		 * @return ReturnHelper
		 */
		public function logout() {
			$ret = new ReturnHelper();
			$session = new ParameterHelper($_SESSION);
			$userId = $session->getInt(SessionStrings::Key_UserId);
			$token = $session->getString(SessionStrings::Key_ApiToken);

			if ($session->hasValue(SessionStrings::Key_UserId)) {
				unset($_SESSION[SessionStrings::Key_UserId]);
			}

			if ($session->hasValue(SessionStrings::Key_ApiToken)) {
				unset($_SESSION[SessionStrings::Key_ApiToken]);
			}

			if ($userId !== null && $token !== null) {
				$sess = ApiSession::fromToken($userId, $token, $this->db, $this->log);

				try {
					$sess->delete();

					$ret->makeGood();
					$this->aLog->logActivity(Activities::LOGOUT, $userId);
					static::touchEvent(self::EVT_LOGOUT, $sess, $this->db, $this->log);
				} catch (\Exception $ex) {
					$this->log->error("Failed to delete session for token '{$token}': {ERROR}", ['ERROR' => $ex]);
				}
			}

			return $ret;
		}

		/**
		 * Performs the RESETPASSWORD event and notifies subscribers
		 * if successful.
		 *
		 * @param ParameterHelper $params Parameters for performing operation.
		 * @return ReturnHelper
		 */
		public function resetPassword(ParameterHelper $params) {
			$ret = new ReturnHelper();

			if (!$params->hasValue('id') || !$params->hasValue('new_password') || !$params->hasValue('confirm_password')) {
				$ret->addMessage("Failed password reset, invalid parameters provided");

				return $ret;
			}

			$new1 = $params->getString('new_password');
			$new2 = $params->getString('confirm_password');

			if ($new1 !== $new2) {
				$ret->addMessage("Failed password reset, invalid passwords provided");

				return $ret;
			}

			$user = User::fromId($params->getInt('id'), $this->db, $this->log);

			if ($user->id < 1) {
				$ret->addMessage("Failed password reset, invalid account information");

				return $ret;
			}

			$key = LoginKey::fromUserAndProvider($user->id, LoginKeyProviders::BASIC, $this->db, $this->log);

			try {
				$event = new ReturnHelper();

				if ($key->userId < 1) {
					$key = new LoginKey($this->db, $this->log);
					$key->userId = $user->id;
					$key->provider = new LoginKeyProviders(LoginKeyProviders::BASIC);
					$key->key = password_hash($new1, PASSWORD_DEFAULT);
					$event = $key->create();
				} else {
					$key->key = password_hash($new1, PASSWORD_DEFAULT);
					$event = $key->update();
				}

				if ($event->isBad()) {
					if ($event->hasMessages()) {
						$ret->addMessage($event->getMessages()[0]);
					}

					return $ret;
				}

				$ret->makeGood();
				$ret->addResult(['user' => $user]);
				static::touchEvent(self::EVT_RESETPASSWORD, $user, $this->db, $this->log);
			} catch (\Exception $ex) {
				$ret->addMessage("Failed password reset, an exception occurred");
			}

			return $ret;
		}

		/**
		 * Performs the UPDATE event and notifies subscribers
		 * if successful.
		 *
		 * @param ParameterHelper $params Parameters for performing operation.
		 * @return ReturnHelper
		 */
		public function update(ParameterHelper $params) {
			$ret = new ReturnHelper();

			if (!$params->hasValue('id') || !$params->hasValue('token')) {
				$ret->addMessage("Failed user update, invalid account information");

				return $ret;
			}

			$user = User::fromId($params->getInt('id'), $this->db, $this->log);
			$user->email = $params->getString('email', $user->email);
			$user->name = $params->getString('name', $user->name);

			if ($user->id < 1) {
				$ret->addMessage("Failed user update, invalid account information");

				return $ret;
			}

			$executorIsAdmin = false;
			$session = new ParameterHelper($_SESSION);

			if ($session->getInt(SessionStrings::Key_UserId) != $user->id) {
				$executor = User::fromId($session->getInt(SessionStrings::Key_UserId), $this->db, $this->log);

				if ($executor->id < 1) {
					$ret->addMessage("Failed user update, invalid executor information");

					return $ret;
				}

				$sess = ApiSession::fromToken($executor->id, $session->getString(SessionStrings::Key_ApiToken), $this->db, $this->log);

				if ($sess->userId < 1) {
					$ret->addMessage("Failed user update, invalid executor information");

					return $ret;
				}

				$roleRepo = new UserRoles($this->db, $this->log);

				if (!$roleRepo->userInRoleByRoleName($sess->userId, RoleStrings::ADMINISTRATOR, 0)) {
					$ret->addMessage("Failed user update, invalid executor");

					return $ret;
				}

				$executorIsAdmin = true;
			}

			$account = User::fromId($params->getInt('id'), $this->db, $this->log);

			try {
				if (!$params->hasValue('email') || !User::validEmail($params->getString('email'))) {
					$user->email = $account->email;
					$user->emailConfirmed = $account->emailConfirmed;
				}

				if ($user->email !== $account->email) {
					$user->emailConfirmed = false;
				}

				if ($params->hasValue('email_confirmed', true)) {
					$user->emailConfirmed = $params->getBool('email_confirmed');
				}

				if ($params->hasValue('current_password') && $params->hasValue('new_password') && $params->hasValue('confirm_password')) {
					$curr = $params->getString('current_password');
					$new1 = $params->getString('new_password');
					$new2 = $params->getString('confirm_password');

					if ($new1 !== $new2) {
						$ret->addMessage("Failed user update, invalid password information supplied");

						return $ret;
					}

					$key = LoginKey::fromUserAndProvider($user->id, LoginKeyProviders::BASIC, $this->db, $this->log);

					if ($key->userId < 1) {
						$ret->addMessage("Failed user update, invalid password information");

						return $ret;
					}

					if (!password_verify($curr, $key->key)) {
						$ret->addMessage("Failed user update, invalid password information supplied");

						return $ret;
					}

					$key->key = password_hash($new1, PASSWORD_DEFAULT);
					$key->update();
				} else if ($params->hasValue('new_password') && $params->hasValue('confirm_password') && $executorIsAdmin) {
					$new1 = $params->getString('new_password');
					$new2 = $params->getString('confirm_password');

					if ($new1 !== $new2) {
						$ret->addMessage("Failed user update, invalid password information supplied");

						return $ret;
					}

					$key = LoginKey::fromUserAndProvider($user->id, LoginKeyProviders::BASIC, $this->db, $this->log);

					if ($key->userId < 1) {
						$ret->addMessage("Failed user update, invalid password information");

						return $ret;
					}

					$key->key = password_hash($new1, PASSWORD_DEFAULT);
					$key->update();
				}

				$user->update();

				$ret->makeGood();
				$ret->addResult(['user' => $user]);
				static::touchEvent(self::EVT_UPDATE, $user, $this->db, $this->log);
			} catch (\Exception $ex) {
				$ret->addMessage("Failed user update, exception occurred");
				$this->log->error("Failed user update for user #{$user->id}, exception occurred: {ERROR}", ['ERROR' => $ex]);
			}

			return $ret;
		}
	}

