<?php

	namespace Stoic\User;

	/**
	 * The role strings available in the
	 * system.
	 *
	 * @version 1.0
	 */
	class RoleStrings {
		const ADMINISTRATOR = 'Administrator';
		const AUTHOR = 'Author';
		const CONTRIBUTOR = 'Reviewer';
		const VIEWER = 'Viewer';
		const EDITOR = 'Editor';
		const NONE = 'None';


		/**
		 * Internal static cache of constants.
		 *
		 * @var array
		 */
		protected static $constCache = null;


		/**
		 * Retrieves the internal cache of constants.
		 *
		 * @return array
		 */
		public static function getConstList() {
			if (static::$constCache === null) {
				$ref = new \ReflectionClass(get_called_class());
				static::$constCache = $ref->getConstants();
			}

			return static::$constCache;
		}
	}
