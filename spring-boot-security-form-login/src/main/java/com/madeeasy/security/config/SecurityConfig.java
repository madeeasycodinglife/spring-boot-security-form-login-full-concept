package com.madeeasy.security.config;


import com.madeeasy.security.error.CustomAuthenticationEntryPoint;
import com.madeeasy.security.error.handler.CustomAccessDeniedHandler;
import com.madeeasy.security.service.MyUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.security.web.header.writers.StaticHeadersWriter;

import javax.sql.DataSource;

@EnableWebSecurity
//@EnableWebSecurity(debug = true)
@Configuration
public class SecurityConfig {

    @Autowired
    private MyUserDetailsService myUserDetailsService;
    @Autowired
    private CustomAccessDeniedHandler customAccessDeniedHandler;
    @Autowired
    private CustomAuthenticationEntryPoint customAuthenticationEntryPoint;
    @Autowired
    private DataSource dataSource;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .csrf((csrf) -> csrf.disable())
                /** //-------------------- OR ----------------------
                 *
                 * .csrf(csrf -> csrf
                 *                         .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                 *        )
                 */
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/customers/welcome").permitAll()
                        .requestMatchers("/access-denied").permitAll()
                        .requestMatchers(HttpMethod.POST, "/customers/").permitAll()
                        .requestMatchers(HttpMethod.GET, "/customers/get-all-customers").hasRole("USER")
                        .requestMatchers(HttpMethod.GET, "/customers/{customerId}").hasRole("MANAGER")
                )
                .headers(headers -> {
                            headers.
                                    xssProtection(Customizer.withDefaults())
                                    .contentSecurityPolicy(contentSecurityPolicyConfig -> contentSecurityPolicyConfig.policyDirectives("script-src 'src'"))
                                    .frameOptions(frameOptionsConfig -> frameOptionsConfig.sameOrigin())
                                    .httpStrictTransportSecurity(hsts -> hsts
                                            .includeSubDomains(true)
                                            .preload(true)
                                            .maxAgeInSeconds(31536000)
                                    )
                                    .addHeaderWriter(new StaticHeadersWriter("X-Content-Security-policy",
                                            "default-src 'src'")
                                    )
                                    .addHeaderWriter(new StaticHeadersWriter("pabitra", "kist college"))
                                    .cacheControl(Customizer.withDefaults())
                                    .contentTypeOptions(Customizer.withDefaults());
                        }
                )
                .formLogin(formLogin -> formLogin
                        .loginPage("/login")
                        .usernameParameter("email")
                        .passwordParameter("password")
                        .loginProcessingUrl("/process-login")
                        .defaultSuccessUrl("/customers/welcome", true)
                        .failureUrl("/login?error=true")
                        .permitAll()
                )
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/login?logout=true")
                        .invalidateHttpSession(true)
                        .clearAuthentication(true)
                        .deleteCookies("JSESSIONID")
                        .permitAll()
                )
                .exceptionHandling(exceptionHandling -> exceptionHandling
                        // if not authenticated
                        .authenticationEntryPoint(customAuthenticationEntryPoint)
                        // if not authorized
                        .accessDeniedHandler(customAccessDeniedHandler)
                )
                .sessionManagement(session -> session
                        .maximumSessions(1)
                        /**
                         * Maximum sessions of 1 for this principal exceeded [error message]
                         */
                        .maxSessionsPreventsLogin(true)
                )
                .sessionManagement(session -> session
                        /**
                         *  if you may want to redirect to a specific endpoint when a user makes a
                         *  request with an already-expired session.
                         */
                        /**
                         * Typically, the default session timeout is set to 30 minutes.
                         */
                        .invalidSessionUrl("/invalid-session")
                        .sessionFixation(sessionFixation -> sessionFixation.newSession())
                        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED) // if your application is API-driven or stateless use NEVER or STATELESS respectively
                )
                .rememberMe(rememberMe -> rememberMe
                        /**
                         * note that, by default, the remember-me cookie won’t survive when the application restarted.
                         * That means when the application restarts, all previous cookies become invalid and the user
                         * must log in manually. You can override this default behavior by supplying a fixed key like this: [key]
                         *
                         * It’s because by default, Spring Security supplies a random key at application’s startup. So if you fix the key,
                         * remember-me cookies are still valid until expire.
                         */
                        .key("key") // cookies will survive if restarted
                        .rememberMeParameter("remember-me-custom") // it should match with login page remember me parameter
                        .rememberMeCookieName("remember-me-browser-console") // it will be stored in browser and its name will be "remember-me-browser-console"
                        .tokenRepository(persistentTokenRepository())
                        .tokenValiditySeconds(86400)
                )
                .build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setUserDetailsService(myUserDetailsService);
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder());
        return daoAuthenticationProvider;
    }

    /**
     * this is for spring security to save and retrieve persistent token for remember me authentication
     * sql query:
     * CREATE TABLE `persistent_logins` (
     * `username` VARCHAR(64) NOT NULL,
     * `series` VARCHAR(64) NOT NULL,
     * `token` VARCHAR(64) NOT NULL,
     * `last_used` TIMESTAMP NOT NULL,
     * PRIMARY KEY (`series`));
     * NOTE : write the sql query in same database which is currently used by the .yml or .properties file
     */
    @Bean
    public PersistentTokenRepository persistentTokenRepository() {
        JdbcTokenRepositoryImpl tokenRepo = new JdbcTokenRepositoryImpl();
        tokenRepo.setDataSource(dataSource);
        return tokenRepo;
    }

}
