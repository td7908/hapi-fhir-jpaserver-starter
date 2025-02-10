package ca.uhn.fhir.jpa.starter.auth;

import jakarta.validation.constraints.NotNull;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * @author Tadej Delopst
 */
public class JwtTokenConverter implements Converter<Jwt, Authentication> {

	private final String usernameClaim;
	private final String nameClaim;
	private final Set<String> rolesPath;
	private final Set<String> allowedRoles = Arrays.stream(UserRole.values()).map(Enum::name).collect(Collectors.toSet());

	public JwtTokenConverter(
		String usernameClaim,
		String nameClaim,
		Set<String> rolesPath) {
		this.usernameClaim = usernameClaim;
		this.nameClaim = nameClaim;
		this.rolesPath = rolesPath;
	}

	@SuppressWarnings("ConstantConditions")
	@Override
	public Authentication convert(@NotNull Jwt jwt) {
		Map<String, Object> claims = jwt.getClaims();

		String username = claims.get(usernameClaim).toString();
		String name = claims.get(nameClaim).toString();
		Set<SimpleGrantedAuthority> authorities = new HashSet<>(getRolesForPath(claims));

		return new Authentication(
			new User(
				username,
				name,
				authorities.stream().map(it -> UserRole.valueOf(it.getAuthority())).collect(Collectors.toSet())),
			null,
			authorities,
			jwt.getTokenValue());
	}

	@SuppressWarnings({"unchecked", "MethodWithMultipleLoops"})
	private Set<SimpleGrantedAuthority> getRolesForPath(Map<String, Object> claims) {
		Set<SimpleGrantedAuthority> authorities = new HashSet<>();

		for (String path : rolesPath) {
			Map<String, Object> node = claims;

			for (String element : path.split("/")) {
				Object value = node.get(element);
				if (value instanceof Collection) {
					Collection<String> roles = (Collection<String>)value;
					roles.stream()
						.map(String::toUpperCase)
						.filter(allowedRoles::contains)
						.forEach(it -> authorities.add(new SimpleGrantedAuthority(it)));

				} else if (value instanceof String) {
					if (allowedRoles.contains(((String)value).toLowerCase())) {
						authorities.add(new SimpleGrantedAuthority(((String)value).toUpperCase()));
					}
				} else if (value instanceof Map) {
					node = (Map<String, Object>)value;
				} else {
					break;
				}
			}
		}
		return Collections.unmodifiableSet(authorities);
	}
}
