package seg3x02.tempconverterapi.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.web.SecurityFilterChain

@Configuration
class SecurityConfig {

    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http
            .authorizeHttpRequests { auth ->
                auth
                    .requestMatchers("/convert/**").hasRole("USER") // Restrict to USER role
                    .anyRequest().authenticated()
            }
            .httpBasic()
            .and()
            .csrf().disable()
        return http.build()
    }

    @Bean
    fun inMemoryUserDetails(manager: AuthenticationManagerBuilder): AuthenticationManagerBuilder {
        manager.inMemoryAuthentication()
            .withUser("user1")
            .password(passwordEncoder().encode("pass1"))
            .roles("USER")
            .and()
            .withUser("user2")
            .password(passwordEncoder().encode("pass2"))
            .roles("USER")
        return manager
    }

    @Bean
    fun passwordEncoder(): PasswordEncoder {
        return BCryptPasswordEncoder()
    }
}
