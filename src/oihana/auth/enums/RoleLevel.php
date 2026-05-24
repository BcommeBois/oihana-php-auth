<?php

namespace oihana\auth\enums;

use oihana\reflect\traits\ConstantsTrait;

/**
 * Hard limits applied to the `level` field of every role on POST and PATCH.
 *
 * These values are the **default fallback** used when the configuration file
 * does not provide a `[auth.roles]` section. Once injected through the DI
 * container, the runtime values may override these defaults, but they must
 * remain compatible with the levels of the seeded `guest` and `superadmin`
 * roles (i.e. `MIN_DEFAULT <= guest.level` and `MAX_DEFAULT >= superadmin.level`).
 *
 * The top value is reserved: only a user whose own maxLevel equals it can
 * create or assign a role at this level. This guarantees the `superadmin`
 * tier remains a singleton tier reserved by bootstrap.
 *
 * @package oihana\auth\enums
 * @author  Marc Alcaraz
 */
class RoleLevel
{
    use ConstantsTrait ;

    /**
     * Default lower bound. Aligned with the seeded `guest` role.
     */
    public const int MIN_DEFAULT = 1 ;

    /**
     * Default upper bound. Aligned with the seeded `superadmin` role.
     */
    public const int MAX_DEFAULT = 1000 ;
}
