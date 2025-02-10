package ca.uhn.fhir.jpa.starter.auth;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.Set;

/**
 * @author Tadej Delopst
 */
@ConfigurationProperties(prefix = "spring.security.oauth2")
public class SecurityProperties {

	private final String jwksUrl;
	private final Set<String> rolesPath;
	private final String usernameClaim;
	private final String nameClaim;
	private final String accessTokenUrl;
	private final String authorizationUrl;

	public SecurityProperties(
		String jwksUrl,
		Set<String> rolesPath,
		String usernameClaim,
		String nameClaim,
		String accessTokenUrl,
		String authorizationUrl) {
		this.jwksUrl = jwksUrl;
		this.rolesPath = rolesPath;
		this.usernameClaim = usernameClaim;
		this.nameClaim = nameClaim;
		this.accessTokenUrl = accessTokenUrl;
		this.authorizationUrl = authorizationUrl;
	}

	public String getJwksUrl() {
		return jwksUrl;
	}

	public Set<String> getRolesPath() {
		return rolesPath;
	}

	public String getUsernameClaim() {
		return usernameClaim;
	}

	public String getNameClaim() {
		return nameClaim;
	}

	public String getAccessTokenUrl() {
		return accessTokenUrl;
	}

	public String getAuthorizationUrl() {
		return authorizationUrl;
	}
}
