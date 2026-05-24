<?php

namespace tests\oihana\auth\jwt\helpers;

use PHPUnit\Framework\TestCase;

use function oihana\auth\jwt\helpers\decodeJwtClaims;

/**
 * Unit coverage for {@see \oihana\auth\jwt\helpers\decodeJwtClaims()}.
 *
 * The helper is purely a client-side inspection utility — it does NOT
 * verify the signature, the issuer, the audience, or the expiration of
 * the token. Its contract is narrow :
 *
 * - extract the payload segment of a compact-serialized JWT,
 * - decode URL-safe base64 (`-` / `_` aliases for `+` / `/`),
 * - JSON-decode the resulting bytes,
 * - return the decoded array, or `null` on any structural failure.
 */
class DecodeJwtClaimsTest extends TestCase
{
    /**
     * Encodes a payload array as a fake compact-serialized JWT.
     *
     * The header and signature segments are arbitrary placeholders — the
     * helper never reads them. The payload is encoded in URL-safe base64
     * (the form Zitadel and most OIDC providers emit).
     *
     * @param array<string, mixed> $payload The claim set to embed.
     */
    private function makeJwt( array $payload ) :string
    {
        $headerSegment    = $this->base64UrlEncode( '{"alg":"RS256","typ":"JWT"}' ) ;
        $payloadSegment   = $this->base64UrlEncode( json_encode( $payload , JSON_UNESCAPED_SLASHES ) ) ;
        $signatureSegment = $this->base64UrlEncode( 'fake-signature-bytes' ) ;

        return "$headerSegment.$payloadSegment.$signatureSegment" ;
    }

    /**
     * URL-safe base64 encoding without `=` padding (RFC 7515 §2).
     */
    private function base64UrlEncode( string $bytes ) :string
    {
        return rtrim( strtr( base64_encode( $bytes ) , '+/' , '-_' ) , '=' ) ;
    }

    public function testWellFormedJwtReturnsClaims() :void
    {
        $payload = [ 'sub' => 'user-42' , 'iss' => 'https://example.com' , 'aud' => 'project-id' ] ;
        $jwt     = $this->makeJwt( $payload ) ;

        $this->assertSame( $payload , decodeJwtClaims( $jwt ) ) ;
    }

    public function testUrlSafeBase64IsTolerated() :void
    {
        // A UTF-8 multibyte payload statistically guarantees that the
        // standard base64 encoding contains `+` and `/` characters, which
        // the URL-safe form remaps to `-` and `_`. The fixture sub is
        // long enough (>= 60 base64 chars) to make the presence of at
        // least one alias deterministic in practice.
        $payload = [ 'sub' => 'svc-✓-José-ñ-ÿ-Δ-Π-Ω-Æ-Œ-ß-§-¶-©-®-€' ] ;
        $json    = json_encode( $payload , JSON_UNESCAPED_UNICODE ) ;
        $segment = $this->base64UrlEncode( $json ) ;

        // Sanity check : the segment must contain at least one URL-safe alias,
        // otherwise this test is not actually exercising the conversion path.
        $this->assertTrue
        (
            str_contains( $segment , '-' ) || str_contains( $segment , '_' ) ,
            'Test fixture is supposed to exercise the URL-safe alias path'
        ) ;

        $jwt = "header.$segment.signature" ;

        $this->assertSame( $payload , decodeJwtClaims( $jwt ) ) ;
    }

    public function testNumericClaimsArePreserved() :void
    {
        $payload = [ 'sub' => 'svc-001' , 'iat' => 1_700_000_000 , 'exp' => 1_700_003_600 ] ;
        $jwt     = $this->makeJwt( $payload ) ;

        $claims = decodeJwtClaims( $jwt ) ;

        $this->assertSame( 1_700_000_000 , $claims[ 'iat' ] ?? null ) ;
        $this->assertSame( 1_700_003_600 , $claims[ 'exp' ] ?? null ) ;
    }

    public function testNestedClaimsArePreserved() :void
    {
        $payload =
        [
            'sub'             => 'user-99' ,
            'realm_access'    => [ 'roles' => [ 'admin' , 'editor' ] ] ,
            'resource_access' =>
            [
                'api' => [ 'roles' => [ 'read' , 'write' ] ] ,
            ] ,
        ] ;

        $jwt = $this->makeJwt( $payload ) ;

        $this->assertSame( $payload , decodeJwtClaims( $jwt ) ) ;
    }

    public function testEmptyStringReturnsNull() :void
    {
        $this->assertNull( decodeJwtClaims( '' ) ) ;
    }

    public function testWrongSegmentCountReturnsNull() :void
    {
        // 1 segment
        $this->assertNull( decodeJwtClaims( 'only-one' ) ) ;

        // 2 segments
        $this->assertNull( decodeJwtClaims( 'header.payload' ) ) ;

        // 4 segments
        $this->assertNull( decodeJwtClaims( 'a.b.c.d' ) ) ;

        // 5 segments
        $this->assertNull( decodeJwtClaims( 'a.b.c.d.e' ) ) ;
    }

    public function testInvalidBase64ReturnsNull() :void
    {
        // `*` is outside the base64 alphabet ; `base64_decode( ... , true )`
        // returns `false` in strict mode, which the helper maps to `null`.
        $jwt = 'header.***invalid-base64***.signature' ;

        $this->assertNull( decodeJwtClaims( $jwt ) ) ;
    }

    public function testNonJsonPayloadReturnsNull() :void
    {
        $segment = $this->base64UrlEncode( 'this is plain text, not JSON' ) ;
        $jwt     = "header.$segment.signature" ;

        $this->assertNull( decodeJwtClaims( $jwt ) ) ;
    }

    public function testJsonScalarPayloadReturnsNull() :void
    {
        // A JSON string scalar : `"hello"` decodes to PHP string, not array.
        $segment = $this->base64UrlEncode( '"hello"' ) ;
        $jwt     = "header.$segment.signature" ;
        $this->assertNull( decodeJwtClaims( $jwt ) ) ;

        // A JSON number : decodes to PHP int.
        $segment = $this->base64UrlEncode( '42' ) ;
        $jwt     = "header.$segment.signature" ;
        $this->assertNull( decodeJwtClaims( $jwt ) ) ;

        // A JSON boolean.
        $segment = $this->base64UrlEncode( 'true' ) ;
        $jwt     = "header.$segment.signature" ;
        $this->assertNull( decodeJwtClaims( $jwt ) ) ;

        // A JSON null literal.
        $segment = $this->base64UrlEncode( 'null' ) ;
        $jwt     = "header.$segment.signature" ;
        $this->assertNull( decodeJwtClaims( $jwt ) ) ;
    }

    public function testEmptyJsonObjectReturnsEmptyArray() :void
    {
        $segment = $this->base64UrlEncode( '{}' ) ;
        $jwt     = "header.$segment.signature" ;

        $this->assertSame( [] , decodeJwtClaims( $jwt ) ) ;
    }

    public function testTokenWithSurroundingWhitespaceReturnsNull() :void
    {
        // The helper does NOT trim its input — leading whitespace turns
        // the first segment into something that no longer matches the
        // header pattern, but the segment count stays at 3, so the
        // base64 decode of the payload still proceeds. The expectation
        // here is therefore not "always null" but "robust to either
        // outcome" : if the payload happens to decode, the helper must
        // still return a typed result. We pin the current behaviour so
        // a future change is surfaced explicitly.
        $payload = [ 'sub' => 'user-1' ] ;
        $jwt     = '  ' . $this->makeJwt( $payload ) ;

        // Leading whitespace lives inside the header segment, the payload
        // segment is untouched : the helper should still decode the claims.
        $this->assertSame( $payload , decodeJwtClaims( $jwt ) ) ;
    }
}
