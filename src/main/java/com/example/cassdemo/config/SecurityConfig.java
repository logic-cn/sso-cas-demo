package com.example.cassdemo.config;

import java.util.Collections;

import lombok.extern.slf4j.Slf4j;
import org.jasig.cas.client.session.SingleSignOutFilter;
import org.jasig.cas.client.validation.Cas20ServiceTicketValidator;
import org.jasig.cas.client.validation.TicketValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.cas.ServiceProperties;
import org.springframework.security.cas.authentication.CasAuthenticationProvider;
import org.springframework.security.cas.web.CasAuthenticationEntryPoint;
import org.springframework.security.cas.web.CasAuthenticationFilter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;

@Slf4j
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private CasProperties casProperties;

    @Bean
    public ServiceProperties serviceProperties() {
        ServiceProperties sp = new ServiceProperties();
        sp.setService(casProperties.getClientHostUrl() + "/login/cas");
        sp.setSendRenew(false);
        log.info("Service properties set with service URL: {}", sp.getService());
        return sp;
    }

    @Bean
    public CasAuthenticationEntryPoint casAuthenticationEntryPoint(ServiceProperties sp) {
        CasAuthenticationEntryPoint entryPoint = new CasAuthenticationEntryPoint();
        entryPoint.setLoginUrl(casProperties.getServerLoginUrl());
        entryPoint.setServiceProperties(sp);
        log.info("CAS authentication entry point set with login URL: {}", casProperties.getServerLoginUrl());
        return entryPoint;
    }

    @Bean
    public CasAuthenticationFilter casAuthenticationFilter(AuthenticationManager authenticationManager,
                    ServiceProperties sp) throws Exception {
        CasAuthenticationFilter filter = new CasAuthenticationFilter();
        filter.setServiceProperties(sp);
        filter.setAuthenticationManager(authenticationManager);
        filter.setFilterProcessesUrl("/login/cas");
        log.info("CAS authentication filter configured");
        return filter;
    }

    @Bean
    public CasAuthenticationProvider casAuthenticationProvider(ServiceProperties sp,
                    UserDetailsService userDetailsService) {
        CasAuthenticationProvider provider = new CasAuthenticationProvider();
        provider.setServiceProperties(sp);
        provider.setTicketValidator(ticketValidator());
        provider.setUserDetailsService(userDetailsService);
        provider.setKey("CAS_PROVIDER_LOCALHOST");
        log.info("CAS authentication provider configured");
        return provider;
    }

    @Bean
    public TicketValidator ticketValidator() {
        return new Cas20ServiceTicketValidator(casProperties.getServerUrlPrefix());
    }

    @Bean
    public LogoutFilter casLogoutFilter() {
        // 修改为支持 GET 和 POST 请求
        String logoutUrl = casProperties.getServerLogoutUrl() + "?service=" + casProperties.getClientHostUrl();
        LogoutFilter logoutFilter = new LogoutFilter(logoutUrl, new SecurityContextLogoutHandler());
        logoutFilter.setLogoutRequestMatcher(new OrRequestMatcher(new AntPathRequestMatcher("/app/logout", "POST"),
                        new AntPathRequestMatcher("/app/logout", "GET")));
        log.info("CAS logout filter configured");
        return logoutFilter;
    }

    @Bean
    public SingleSignOutFilter singleSignOutFilter() {
        SingleSignOutFilter singleSignOutFilter = new SingleSignOutFilter();
        singleSignOutFilter.setIgnoreInitConfiguration(true);
        return singleSignOutFilter;
    }

    // 添加 SingleSignOutHttpSessionListener (可选，用于集群环境)
    // @Bean
    // public ServletListenerRegistrationBean<SingleSignOutHttpSessionListener>
    // singleSignOutHttpSessionListener() {
    // return new ServletListenerRegistrationBean<>(new SingleSignOutHttpSessionListener());
    // }


    @Bean
    public AuthenticationManager authenticationManager(CasAuthenticationProvider casAuthenticationProvider) {
        return new ProviderManager(Collections.singletonList(casAuthenticationProvider));
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return username -> {
            // 在 CAS 场景下，根据用户名返回用户信息
            // 实际应用中应该从数据库或其他用户存储中加载用户信息
            return User.withUsername(username).password("{noop}").roles("USER").build();
        };
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, CasAuthenticationEntryPoint entryPoint,
                    CasAuthenticationFilter casFilter, LogoutFilter logoutFilter) throws Exception {
        http.authorizeRequests(authorize -> authorize
                        .antMatchers("/", "/public/**", "/css/**", "/js/**", "/webjars/**", "/error", "/login/cas")
                        .permitAll().anyRequest().authenticated())
                        .exceptionHandling(exception -> exception.authenticationEntryPoint(entryPoint)
                                        .accessDeniedPage("/access-denied"))
                        .addFilter(casFilter).addFilterBefore(logoutFilter, LogoutFilter.class)
                        .addFilterBefore(singleSignOutFilter(), CasAuthenticationFilter.class)
                        .csrf(AbstractHttpConfigurer::disable)
                        .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                                        .invalidSessionUrl("/"))
                        .logout(logout -> logout.logoutUrl("/app/logout").logoutSuccessUrl("/")
                                        .invalidateHttpSession(true).deleteCookies("JSESSIONID").permitAll());
        log.info("Security filter chain configured");
        return http.build();
    }
}
