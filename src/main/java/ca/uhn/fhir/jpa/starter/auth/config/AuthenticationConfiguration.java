package ca.uhn.fhir.jpa.starter.auth.config;

import ca.uhn.fhir.jpa.starter.auth.JwtTokenConverter;
import ca.uhn.fhir.jpa.starter.auth.SecurityProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authorization.method.AuthorizationManagerBeforeMethodInterceptor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

/**
 * @author Tadej Delopst
 */
@Configuration
@EnableWebSecurity
@EnableConfigurationProperties(SecurityProperties.class)
public class AuthenticationConfiguration {

	private final SecurityProperties securityProperties;

	public AuthenticationConfiguration(@Autowired SecurityProperties securityProperties) {
		this.securityProperties = securityProperties;
	}

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		return http
			.csrf(AbstractHttpConfigurer::disable)
			.httpBasic(AbstractHttpConfigurer::disable)
			.cors(cors -> cors.configurationSource(toCorsConfigurationSource()))
			.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
			.headers(headers -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable))
			.authorizeHttpRequests(authorize -> authorize
				.requestMatchers(HttpMethod.OPTIONS).permitAll()
				.requestMatchers(HttpMethod.GET, "/rest/v1/app").permitAll()
				.requestMatchers(HttpMethod.GET, "/health").permitAll()
				.requestMatchers("/fhir/**").authenticated()
			)
			.oauth2ResourceServer(oauth2 -> oauth2
				.jwt(jwt -> jwt
					.decoder(NimbusJwtDecoder.withJwkSetUri(securityProperties.getJwksUrl())
									.jwsAlgorithm(SignatureAlgorithm.from("RS256"))
									.build())
					.jwtAuthenticationConverter(new JwtTokenConverter(
						securityProperties.getUsernameClaim(),
						securityProperties.getNameClaim(),
						securityProperties.getRolesPath()))
				)
			)
			.build();
	}

	@Bean
	public AuthorizationManagerBeforeMethodInterceptor authorizationManagerBeforeMethodInterceptor() {
		return AuthorizationManagerBeforeMethodInterceptor.secured();
	}

	@SuppressWarnings("DuplicatedCode")
	private CorsConfigurationSource toCorsConfigurationSource() {
		UrlBasedCorsConfigurationSource urlBasedCorsConfigurationSource = new UrlBasedCorsConfigurationSource();
		CorsConfiguration corsConfiguration = new CorsConfiguration().applyPermitDefaultValues();
		corsConfiguration.addAllowedHeader(CorsConfiguration.ALL);
		corsConfiguration.addAllowedOriginPattern(CorsConfiguration.ALL);
		corsConfiguration.addAllowedMethod(CorsConfiguration.ALL);
		corsConfiguration.setAllowCredentials(true);

		corsConfiguration.setMaxAge(24L * 3600L);
		urlBasedCorsConfigurationSource.registerCorsConfiguration("/**", corsConfiguration);
		return urlBasedCorsConfigurationSource;
	}
}
