<?php

namespace oihana\auth\exceptions ;

use RuntimeException ;

/**
 * Thrown by IdTokenValidator when the id_token fails any validation
 * step (signature, expiration, issuer mismatch, sub mismatch, …).
 *
 * The middleware catches this exception and maps it to a 401
 * response with the appropriate `reason` code.
 *
 * @package oihana\auth\exceptions
 * @author  Marc Alcaraz
 */
class IdTokenValidationException extends RuntimeException
{
}
