package ca.uhn.fhir.jpa.starter.auth;

import java.security.Principal;
import java.util.Set;

/**
 * @author Tadej Delopst
 */
public class User implements Principal {
	private final String username;
	private final String fullName;
	private final Set<UserRole> roles;

	public User(String username, String fullName, Set<UserRole> roles) {
		this.username = username;
		this.fullName = fullName;
		this.roles = roles;
	}

	public String getUsername() {
		return username;
	}

	public String getFullName() {
		return fullName;
	}

	public Set<UserRole> getRoles() {
		return roles;
	}

	@Override
	public String getName() {
		return username;
	}
}
