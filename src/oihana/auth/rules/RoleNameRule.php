<?php

namespace oihana\auth\rules;

use Somnambulist\Components\Validation\Rule;

/**
 * Validates a role `name`: 2-70 ASCII characters in
 * `[a-z0-9 _-]`, lowercase enforced.
 *
 * Accents and Latin extended characters are deliberately excluded for
 * the first iteration — internal role names like `manager-com` or
 * `content_editor` are common, free-form display labels go in the
 * `description` i18n field instead.
 *
 * @package oihana\auth\rules
 * @author  Marc Alcaraz
 */
class RoleNameRule extends Rule
{
    /**
     * The rule name.
     */
    public const string NAME = 'role_name' ;

    /**
     * Default error message.
     */
    protected string $message = ':attribute must be 2-70 lowercase ASCII characters (letters, digits, spaces, hyphens, underscores)' ;

    /**
     * Regex applied to the canonical (already trimmed + lowercased) name.
     *
     * `\A` / `\z` (instead of `^` / `$`) anchor on the absolute string
     * boundaries — `$` would tolerate a trailing newline (`"editor\n"`),
     * which would slip through validation even though the canonical step
     * already trimmed. Defence in depth: never trust the upstream trim.
     */
    private const string PATTERN = '/\A[a-z0-9 _-]{2,70}\z/' ;

    /**
     * Validates whether the given value matches the canonical role-name shape.
     *
     * @param mixed $value The (already trimmed + lowercased) name to validate.
     *
     * @return bool True if the value is a string matching the pattern.
     */
    public function check( mixed $value ): bool
    {
        if( !is_string( $value ) )
        {
            return false ;
        }

        return (bool) preg_match( self::PATTERN , $value ) ;
    }
}
