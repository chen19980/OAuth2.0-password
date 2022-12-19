package org.example.config;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Scope;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.error.OAuth2AccessDeniedHandler;
import org.springframework.security.oauth2.provider.token.RemoteTokenServices;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@RequiredArgsConstructor
@EnableResourceServer
public class ResourceConfig extends ResourceServerConfigurerAdapter {
    public static final String RESOURCE_ID = "res1";

    //资源服务令牌解析服务
    @Bean
    public ResourceServerTokenServices tokenService() {
        //使用远程服务请求授权服务器校验token,必须指定校验token 的url、client_id，client_secret
        RemoteTokenServices service = new RemoteTokenServices();
        service.setCheckTokenEndpointUrl("http://localhost:8080/oauth/check_token");
        // 声明只有该client 的接入方才能访问该资源服务
        service.setClientId("chen");
        service.setClientSecret("fstop2022");
        return service;
    }

    @Override
    public void configure(ResourceServerSecurityConfigurer resources) {
        // 声明该资源服务id，以及认证的tokenSerivce对象
        resources
                .resourceId(RESOURCE_ID)
                .tokenServices(tokenService());
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .authorizeRequests()
                .antMatchers("/login").permitAll()
                .antMatchers("/client-login").permitAll()
                .and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    }
}
//======================================================================================================================
//    @Override
//    public void configure(HttpSecurity http) throws Exception {
//        http
//                .authorizeRequests()
//                // 设置 /login 无需权限访问
//                .antMatchers("/login").permitAll()
//                // 设置 /client-login 无需权限访问
//                .antMatchers("/client-login").permitAll()
//                // 设置其它请求，需要认证后访问
//                .anyRequest().authenticated();
//    }
//}
//=======================================================================================================================
//    private static final String RESOURCE_ID = "resource_id";
//
//    @Override
//    public void configure(ResourceServerSecurityConfigurer resources) {
//        resources.resourceId(RESOURCE_ID).stateless(false);
//    }
//
//    @Override
//    public void configure(HttpSecurity http) throws Exception {
//        http
//                .csrf().disable()
//                .authorizeRequests()
//                .antMatchers("/login").permitAll()
//                .and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
//                .and().exceptionHandling().accessDeniedHandler(new OAuth2AccessDeniedHandler());
////
////                .csrf().disable()
////                .authorizeRequests()
////                .antMatchers("/login").permitAll()
////                .anyRequest().authenticated()
////                .and().exceptionHandling().accessDeniedHandler(new OAuth2AccessDeniedHandler());
//    }
//}

//    =================================================================
//    @Scope
//    public JwtAccessTokenConverter tokenEnhancer() {
//        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
//        return converter;
//    }
//========================================================================
//    private static final String RESOURCE_ID = "resource_id";
//
//    @Override
//    public void configure(ResourceServerSecurityConfigurer resources) {
//        resources.resourceId(RESOURCE_ID).stateless(false);
//    }
//
//    @Override
//    public void configure(ResourceServerSecurityConfigurer resources) {
//        resources
//                .tokenStore(new JwtTokenStore(tokenEnhancer()));
//    }

//    =====================================================================================

//    @Override
//    public void configure(HttpSecurity http) throws Exception {
//        http
//                .headers().frameOptions().disable()
//                .and()
//                .csrf().disable()
//
//                // 配置受formLogin 保护的资源端点， 不配置且不放行则 401； 当然，oauth2的端点不需要配置在这里，否则画蛇添足导致oauth2登录不正常！
//                .requestMatchers()
//                .antMatchers("/myLogin", "/doLogin", "/oauth/authorize"
//                        , "/protected/**", "/mustLogin/**", "/securedPage*"
//                        , "/myLogout*", "/logout?logout*" // login?logout 也需要保护起来，否则401 —— 这样也不行 todo
//                        // 首页也最好保护起来，否则..
//                        , "/", "/index", "/tourist*", "/a*")// 这里antMatchers必须要包括/doLogin， 否则永远都是登录页面
//                .and()
//                .authorizeRequests()
//
//                //antMatchers这里 "/user/me"不能放行，如果放行，则不能获取到Principal参数 —— 错错错，再次测试发现 这里 "/user/me"是否放行 都不要紧； 不知道哪里搞错了
//                .antMatchers("/tourist", "/myLogin", "/logout?logout*", "/doLogin", "/user/me123", "/oauth/authorize")
//                .permitAll()
//                .anyRequest().authenticated()
//                .and()
//                .formLogin()
//                .loginPage("/myLogin")
//                // 它的作用是什么？ 仅仅是一个通知作用吧..不对！ 测试发现，只有配置了loginPage，那么就一定需要配置loginProcessingUrl， 而且需要匹配！
//                .loginProcessingUrl("/doLogin")
//                .defaultSuccessUrl("/index", false)
//                .permitAll()
////                .and()
////                .authorizeRequests()
////                .anyRequest().authenticated() // 不能加这行，
////                否则：一直401 <oauth><error_description>Full authentication is required to access this resource</error_description><error>unauthorized</error></oauth>
//                .and()
//                .logout()
//
//                // 设置logoutUrl之后，再访问/logout会出现401（如果不放行）， 或者404
//                // 测试发现， /myLogout、 /logout 两个端点都可以注销成功，why？ 按理说只有一个;  测试发现如果antMatchers 发现/logout，则只有logoutUrl可以注销，而且访问 /logout不会注销，而是404
//                // 测试发现有时候/myLogout 并没真正的注销，而是401，why？ 原因是logoutUrl需要受保护
//                // 这里需要 保护起来， 否则也是 401， Full authentication is required to access this resource
//                .logoutUrl("/myLogout")
//                // defaultTarget must start with '/' or with 'http(s)'
//                .logoutSuccessUrl("/myLogoutSuccessUrl")
//                .permitAll()
//                // .logoutSuccessHandler(tigerLogoutSuccessHandler)  //url和Handler只能配置一个
////        .deleteCookies("JSESSIONID")//清除cook键值
//
//                .and()
//
//                // 这里的sessionManagement 并不能影响到AuthorizationServer， 因为..
//                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
//        ;
//
//    }
//=======================================================================================================
//    @Override
//    public void configure(WebSecurity web) throws Exception {
//        web.ignoring() // 設定不經過登入驗證 filter 的路徑
//                .antMatchers(HttpMethod.POST, "/users") // 註冊
//                .antMatchers("/login") // 登入
//                .antMatchers("/refreshtoken") // refresh token
//                .antMatchers("/validate_by_annotation") // validate_by_annotation
//                .antMatchers("/generate_apikey") // apiKey
//                .antMatchers("/insert_apikey") // apiKey
//                .antMatchers("/retrive_apikey") // apiKey
//                .antMatchers("/generate_rsakey") // rsaKey
//                .antMatchers("/insert_rsakey") // rsaKey
//                .antMatchers("/retrive_rsakey"); // rsaKey
//    }
//}
