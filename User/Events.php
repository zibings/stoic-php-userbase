<?php

	namespace Stoic\User;

	use AndyM84\Config\ConfigContainer;
	use Stoic\Log\Logger;
	use Stoic\Pdo\PdoHelper;
	use Stoic\Utilities\ParameterHelper;
	use Stoic\Utilities\ReturnHelper;
	use Stoic\Web\Resources\HttpStatusCodes;

	/**
	 * Class that provides several common operations for users within the system, as well as ways
	 * to be notified when the operations complete.
	 *
	 * @version 1.0.0
	 */
	class UserEvents {
		const EVT_AUTH = 'auth';
		const EVT_CREATE = 'create';
		const EVT_DELETE = 'delete';
		const EVT_LOGOUT = 'logout';
		const EVT_RESETPASSWORD = 'resetPassword';
		const EVT_UPDATE = 'update';
		const STR_DATA = 'data';
		const STR_HTTP_CODE = 'http_code';


		/**
		 * Internal PdoHelper instance.
		 *
		 * @var PdoHelper
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
		protected static function assignSubscriber(string $event, callable $subscriber) : void {
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
		public static function subscribeToAuth(callable $subscriber) : void {
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
		public static function subscribeToCreate(callable $subscriber) : void {
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
		public static function subscribeToDelete(callable $subscriber) : void {
			static::assignSubscriber(self::EVT_DELETE, $subscriber);

			return;
		}

		/**
		 * Static method to subscribe to the LOGOUT user operation
		 * event.
		 *
		 * @param callable $subscriber Callable subscriber to add.
		 * @return void
		 */
		public static function subscribeToLogout(callable $subscriber) : void {
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
		public static function subscribeToResetPassword(callable $subscriber) : void {
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
		public static function subscribeToUpdate(callable $subscriber) : void {
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
		protected static function touchEvent(string $event, ...$args) : void {
			foreach (array_values(static::$events[$event]) as $callable) {
				call_user_func_array($callable, $args);
			}

			return;
		}


		/**
		 * Instantiates a new UserEvents object.
		 *
		 * @param PdoHelper $db PDO instance for use by object.
		 * @param Logger $log Logger instance for use by object, defaults to new instance.
		 */
		public function __construct(PdoHelper $db, Logger $log = null) {
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
		public function auth(ParameterHelper $params) : ReturnHelper {
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

			$session = new Session($this->db, $this->log);
			$session->address = $_SERVER['REMOTE_ADDR'];
			$session->hostname = gethostbyaddr($session->address);
			$session->token = Session::generateGuid(false);
			$session->userId = $user->id;
			$sCreate = $session->create();

			if ($sCreate->isBad()) {
				if ($sCreate->hasMessages()) {
					foreach (array_values($sCreate->getMessages()) as $msg) {
						$this->log->error($msg);
					}
				} else {
					$this->log->error("Failed to create user session for auth");
				}

				return $ret;
			}

			if (!defined('STOIC_DISABLE_SESSION')) {
				$_SESSION[Strings::SESSION_USRID] = $user->id;
				$_SESSION[Strings::SESSION_TOKEN] = $session->token;
			}

			$ret->makeGood();
			$ret->addResult([
				self::STR_HTTP_CODE => HttpStatusCodes::OK,
				self::STR_DATA => [
					'userId' => $user->id,
					'token' => $session->token
				]
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
		 * @return ReturnHelper
		 */
		public function create(ParameterHelper $params, ConfigContainer $settings) : ReturnHelper {
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

				static::touchEvent(self::EVT_CREATE, $user, $this->db, $this->log);

				$ret->makeGood();
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
		public function delete(ParameterHelper $params) : ReturnHelper {
			$ret = new ReturnHelper();

			if (!$params->hasValue('id') || !$params->hasValue('executor') || !$params->hasValue('token')) {
				$ret->addMessage("Failed to delete user, incomplete parameters");

				return $ret;
			}

			$id = $params->getInt('id');
			$executorId = $params->getInt('executor');

			if ($executorId == $id) {
				$ret->addMessage("Failed to delete user, you shouldn't delete yourself");

				return $ret;
			}

			try {
				$user = User::fromId($id, $this->db, $this->log);

				if ($user->id < 1) {
					throw new \Exception("Couldn't find user with that identifier");
				}

				static::touchEvent(self::EVT_DELETE, $user, $this->db, $this->log);
				(new LoginKeys($this->db, $this->log))->deleteAllForUser($id);
				
				if ($user->delete()->isGood()) {
					$ret->makeGood();
				}
			} catch (\Exception $ex) {
				$ret->addMessage("Failed to delete user, an exception occurred");
				$this->log->error("Failed to delete user #{$id} by user #{$executorId} with error: {ERROR}", ['ERROR' => $ex]);
			}

			return $ret;
		}

		/**
		 * Performs the LOGOUT event and notifies subscribers
		 * if successful.
		 *
		 * @return ReturnHelper
		 */
		public function logout() : ReturnHelper {
			$ret = new ReturnHelper();

			if (!defined('STOIC_DISABLE_SESSION')) {
				$session = new ParameterHelper($_SESSION);
				$userId = $session->getInt(Strings::SESSION_USRID);
				$token = $session->getString(Strings::SESSION_TOKEN);

				if ($session->hasValue(Strings::SESSION_USRID)) {
					unset($_SESSION[Strings::SESSION_USRID]);
				}

				if ($session->hasValue(Strings::SESSION_TOKEN)) {
					unset($_SESSION[Strings::SESSION_TOKEN]);
				}
			}

			if ($userId !== null && $token !== null) {
				$sess = Session::fromToken($userId, $token, $this->db, $this->log);

				try {
					$sess->delete();

					static::touchEvent(self::EVT_LOGOUT, $sess, $this->db, $this->log);

					$ret->makeGood();
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
		public function resetPassword(ParameterHelper $params) : ReturnHelper {
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

				$ret->addResult(['user' => $user]);

				static::touchEvent(self::EVT_RESETPASSWORD, $user, $this->db, $this->log);

				$ret->makeGood();
			} catch (\Exception $ex) {
				$ret->addMessage("Failed password reset, an exception occurred");
			}

			return $ret;
		}

		/**
		 * Performs the UPDATE event and notifies subscribers if successful.
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

			$account = User::fromId($user->id, $this->db, $this->log);

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
				}

				$user->update();
				$ret->addResult(['user' => $user]);

				static::touchEvent(self::EVT_UPDATE, $user, $this->db, $this->log);

				$ret->makeGood();
			} catch (\Exception $ex) {
				$ret->addMessage("Failed user update, exception occurred");
				$this->log->error("Failed user update for user #{$user->id}, exception occurred: {ERROR}", ['ERROR' => $ex]);
			}

			return $ret;
		}
	}
