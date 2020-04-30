<?php

	namespace Stoic\User;

	use Stoic\Utilities\EnumBase;

	/**
	 * Set of providers available to use as login keys.
	 *
	 * @version 1.0.0
	 */
	class LoginKeyProviders extends EnumBase {
		const ERROR = 0;
		const BASIC = 1;
	}
