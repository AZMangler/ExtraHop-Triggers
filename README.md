 * Custom Detection: Country of Concern Access
 *
 * Configuration Requirements:
 * - Platform: ExtraHop Reveal(x) 360 / 9.x+.
 * - Events: HTTP_REQUEST, SSL_OPEN, AAA_REQUEST, AAA_RESPONSE, SSH_OPEN.
 * - Assignment: Perimeter / internet-facing sensors or device groups where client IPs are external.
 * - GeoIP: GeoIP.getCountry() must be enabled.
 * - Logging: Remote.Syslog target named "Chronicle-CYDERES" must exist.
 * - Privileges: User account must be able to create triggers and custom detections.
 *
 * Known Exclusions:
 * - Skips flows where Flow.client.ipaddr is RFC1918.
 * - Skips traffic where HTTP.host or client device names match EXCLUDED_HOSTS.
 *
 * Notes:
 * - Detection type ID: country_of_concern_access (appears as custom.country_of_concern_access).
 * - Identity key: <identity>:<countryCode> with identityTtl 'day' to consolidate repeated activity.
