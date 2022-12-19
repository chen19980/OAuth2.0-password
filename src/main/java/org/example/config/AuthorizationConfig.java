package org.example.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.*;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;


@Configuration
@EnableAuthorizationServer
public class AuthorizationConfig extends AuthorizationServerConfigurerAdapter {

    static final String CLIENT_ID = "chen";
    static final String CLIENT_SECRET = "fstop2022";
    static final String GRANT_TYPE_ACCESS = "password";
    static final String GRANT_TYPE_REFRESH = "refresh_token";
    static final String SCOPE_READ = "read";
    static final String SCOPE_WRITE = "write";
    static final int ACCESS_TOKEN_VALIDITY_SECONDS = 1 * 60 * 60;
    static final int REFRESH_TOKEN_VALIDITY_SECONDS = 6 * 60 * 60;


//    /**
//     * token校验的话，就需要注入TokenServices
//     */
//    @Autowired
//    private TokenService tokenService;

    @Autowired
    private static final BCryptPasswordEncoder passwordEncoder =new BCryptPasswordEncoder();

    /**
     * 是负责从数据库读取用户数据的，用户数据包含密码信息，判断前端传入的用户名和密码是否正确
     */
    @Autowired
    private UserDetailsService userDetailsService;

    /**
     * 用户认证 Manager
     */
    @Autowired
    private AuthenticationManager authenticationManager;

    /**
     * 令牌存储（jwt存储令牌）
     */
    @Bean
    public JwtTokenStore tokenStore() {
        return new JwtTokenStore(jwtAccessTokenConverter());
    }

    /**
     * 生成token的轉換器 轉換成 JWT
     */
    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter() {
        JwtAccessTokenConverter jwtAccessTokenConverter = new JwtAccessTokenConverter();
        jwtAccessTokenConverter.setSigningKey("systex2022");  //讀取資源->公鑰解密驗證
        return jwtAccessTokenConverter;
    }


    /**
     * 授权服务器端点的 非安全性配置（请求到 TokenEndpoint ）
     * 配置授权（authorization）以及令牌（token）的访问端点和令牌服务(token services)
     * 注入userdetailService 確認使用者資訊
     */
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints
                .authenticationManager(authenticationManager)
                .tokenStore(tokenStore())  // token的儲存方式
                .accessTokenConverter(jwtAccessTokenConverter())  // 配置JwtAccessToken转换器
                .userDetailsService(userDetailsService);
//                .reuseRefreshTokens(false).userDetailsService(userDetailsService)  //refresh_token需要userDetailsService
//                .tokenEnhancer(jwtAccessTokenConverter());    //增加令牌資訊
    }


    /**
     * 安全检查流程,用来配置令牌端点（Token Endpoint）的安全与权限访问
     * 设置 /oauth/check_token 端点，通过认证后可访问。
     * 这里的认证，指的是使用 client-id + client-secret 进行的客户端认证，不要和用户认证混淆。
     * 其中，/oauth/check_token 端点对应 CheckTokenEndpoint 类，用于校验访问令牌的有效性。
     * 在客户端访问资源服务器时，会在请求中带上访问令牌。
     * 在资源服务器收到客户端的请求时，会使用请求中的访问令牌，找授权服务器确认该访问令牌的有效性。
     * 授权服务器端点的 安全性配置（请求到 TokenEndpoint 之前）
     * 用来配置令牌端点(Token Endpoint)的安全约束.
     */
    @Override
    public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
        oauthServer
                .allowFormAuthenticationForClients()   //允许表单认证。针对/oauth/token端点。
                .checkTokenAccess("isAuthenticated()")  //开启  /oauth/check_token验证端口认证权限访问
                .tokenKeyAccess("permitAll()");  // 开启  /oauth/token_key验证端口无权限访问
    }


    /**
     * 用来配置客户端详情服务（ClientDetailsService）
     * 补充知识：为什么要创建 Client 的 client-id 和 client-secret 呢？
     * 通过 client-id 编号和 client-secret，授权服务器可以知道调用的来源以及正确性。这样，
     * 即使“坏人”拿到 Access Token ，但是没有 client-id 编号和 client-secret，也不能和授权服务器发生有效的交互。
     */
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
//        clients
//                .withClientDetails(clientDetailsService);   //认证信息从数据库获取
        clients
                .inMemory()
                .withClient(CLIENT_ID)
                .secret(CLIENT_SECRET)
                .scopes(SCOPE_READ, SCOPE_WRITE)
                .authorizedGrantTypes(GRANT_TYPE_ACCESS, GRANT_TYPE_REFRESH)
                .accessTokenValiditySeconds(ACCESS_TOKEN_VALIDITY_SECONDS)
                .refreshTokenValiditySeconds(REFRESH_TOKEN_VALIDITY_SECONDS);
    }

}


//    ==================================================================================================================
//
//    用於確定給定客戶端身份驗證請求是否已被當前用戶批准的基本接口。
//    @Scope
//    public UserApprovalHandler userApprovalHandler() {
//        return new UserApprovalHandler() {
//
////          測試指定的授權請求是否已被當前用戶批准
//            @Override
//            public boolean isApproved(AuthorizationRequest authorizationRequest, Authentication authentication) {
//                return true;
//            }
//
////          提供一個掛鉤，允許預先批准請求（跳過用戶批准頁面）。
//            @Override
//            public AuthorizationRequest checkForPreApproval(AuthorizationRequest authorizationRequest, Authentication authentication) {
//                return null;
//            }
//
////          提供在設置之後但在檢查批准之前 更新授權請求的機會 。
//            @Override
//            public AuthorizationRequest updateAfterApproval(AuthorizationRequest authorizationRequest, Authentication authentication) {
//                return null;
//            }
//
////          為授權服務器生成請求以請求用戶的批准
//            @Override
//            public Map<String, Object> getUserApprovalRequest(AuthorizationRequest authorizationRequest, Authentication authentication) {
//                return null;
//            }
//        };
//    }
//}
