package org.example.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.*;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Slf4j
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

//
//    @Autowired
//    private static final BCryptPasswordEncoder passwordEncoder =new BCryptPasswordEncoder();

//    private static final String DEMO_RESOURCE_ID = "order";

//    @Override
//    public void configure(ResourceServerSecurityConfigurer resources) {
//        resources.resourceId(DEMO_RESOURCE_ID).stateless(true);
//    }


    /**
     *???????????? ?????????????????????
     */
//    @Bean
//    @Override
//    protected UserDetailsService userDetailsService() {
//        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
//        manager.createUser(User.withUsername("user_1").password("123456").authorities("USER").build());
//        manager.createUser(User.withUsername("user_2").password("123456").authorities("USER").build());
//        return manager;
//    }


    /*
     * LoginService ???????????????????????????????????????????????? AuthenticationManager ?????? bean
     */
    @Override
    @Bean(name = BeanIds.AUTHENTICATION_MANAGER)
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    public static NoOpPasswordEncoder passwordEncoder() {
        return (NoOpPasswordEncoder) NoOpPasswordEncoder.getInstance();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth
                // ?????????????????? InMemoryUserDetailsManager
                .inMemoryAuthentication()
                // ????????? PasswordEncoder ???????????????
                .passwordEncoder(passwordEncoder())
                // ????????????
                .withUser("systex").password("fstop2022").roles("ADMIN");
    }

    /**
     *?????????????????????
     */
    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring();
    }

}

//==========================================================================================================
//    // Spring ????????????????????????????????????????????????????????? SpringUserService
//    private final UserDetailsService userDetailsService;
//
//    // BCrypt ??????????????????"??????Hash???????????????" ???????????????(??????????????????)
//    @Scope
//    public PasswordEncoder passwordEncoder() {
//        return new BCryptPasswordEncoder();
//    }
//
//    /*
//     * ?????? UserDetailsService ??? ???????????????
//     */
//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.inMemoryAuthentication().passwordEncoder(new BCryptPasswordEncoder()).withUser("chen").password(new BCryptPasswordEncoder().encode("fstop2022")).roles("USER");
//        log.info("@@@ " + new BCryptPasswordEncoder().encode("fstop2022"));
//    }
//
//
//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//
//        http
//                .csrf().disable()   // ????????? CSRF???????????????????????????????????????
//                .authorizeRequests()    // ????????????????????????
//                .antMatchers("/oauth/**").permitAll()
//                .anyRequest().authenticated()  // ????????? API ????????????????????????????????????
//                .and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS); // ??? Session ???????????????
//        http
//                .formLogin().loginProcessingUrl("/login")
//                .usernameParameter("chen").passwordParameter("fstop2022")
//                .defaultSuccessUrl("/default", true);
//    }
//}

//==================================================================================================================
//    @Resource(name = "userService")
//    private UserDetailsService userDetailsService;
//
//    @Autowired
//    private ClientDetailsService clientDetailsService;
//
//    private static final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
//
//
//    @Override
//    @Bean
//    public AuthenticationManager authenticationManagerBean() throws Exception {
//        return super.authenticationManagerBean();
//    }
//
////    @Autowired
////    public void globalUserDetails(AuthenticationManagerBuilder auth) throws Exception {
////        auth.userDetailsService(userDetailsService)
////                .passwordEncoder(passwordEncoder);
////    }
//
//    @Autowired
//    public void globalUserDetails(AuthenticationManagerBuilder auth) throws Exception {
//        auth.inMemoryAuthentication().passwordEncoder(new BCryptPasswordEncoder()).withUser("chen").password(new BCryptPasswordEncoder().encode("fstop2022")) .roles("USER");
//    }
//
//
//    @Scope
//    public final TokenStoreUserApprovalHandler userApprovalHandler(TokenStore tokenStore) {
//        TokenStoreUserApprovalHandler handler = new TokenStoreUserApprovalHandler();
//        handler.setTokenStore(tokenStore);
//        handler.setRequestFactory(new DefaultOAuth2RequestFactory(clientDetailsService));
//        handler.setClientDetailsService(clientDetailsService);
//        return handler;
//    }
//
//    @Scope
//    public final ApprovalStore approvalStore(TokenStore tokenStore) {
//        TokenApprovalStore store = new TokenApprovalStore();
//        store.setTokenStore(tokenStore);
//        return store;
//    }
//
//    @Autowired
//    public BCryptPasswordEncoder encoder() {
//        return new BCryptPasswordEncoder();
//    }
//
//    @Scope
//    public FilterRegistrationBean corsFilter() {
//        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
//        CorsConfiguration config = new CorsConfiguration();
//        config.setAllowCredentials(true);
//        config.addAllowedOrigin("*");
//        config.addAllowedHeader("*");
//        config.addAllowedMethod("*");
//        source.registerCorsConfiguration("/**", config);
//        FilterRegistrationBean bean = new FilterRegistrationBean(new CorsFilter(source));
//        bean.setOrder(0);
//        return bean;
//    }
//
//}

//    ======================================================================================================
//    @Autowired
//    private CustomDetailsService customDetailsService;
//
//    //????????????@Bean
////    @Bean
////    @Order(3)
////    @ConditionalOnBean(AuthenticationManager.class)
//    @Scope
//    public PasswordEncoder encoder() {
//        return new BCryptPasswordEncoder();
//    }
//
//    @Override
//    @Autowired
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.userDetailsService(customDetailsService).passwordEncoder(encoder());
//    }
//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        http.authorizeRequests().anyRequest().authenticated().and().sessionManagement()
//                .sessionCreationPolicy(SessionCreationPolicy.NEVER);
//    }
//    @Override
//    public void configure(WebSecurity web) throws Exception {
//        web.ignoring();
//    }
//    @Override
//    @Bean
////    @Primary
//    public AuthenticationManager authenticationManagerBean() throws Exception {
//        return super.authenticationManagerBean();
//    }
//}
