package org.example.service.Impl;


import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.Entity.User;
import org.example.repository.UserDao;
import org.example.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-security-oauth2-example
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 31/12/17
 * Time: 15.55
 * To change this template use File | Settings | File Templates.
 */

@Slf4j
@Service(value = "userService")
public class UserServiceImpl implements UserDetailsService, UserService {

    @Autowired
    private UserDao userDao;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        log.debug("权限框架-加载用户");
        List<GrantedAuthority> auths = new ArrayList<>();

        User user = new User();
        user.setUsername(username);

        if (user == null) {
            log.debug("找不到该用户 用户名:{}", username);
            throw new UsernameNotFoundException("找不到该用户！");
        }

//        List<BaseRole> roles = baseRoleService.selectRolesByUserId(baseUser.getId());
//        if (roles != null) {
//            //设置角色名称
//            for (BaseRole role : roles) {
//                SimpleGrantedAuthority authority = new SimpleGrantedAuthority(role.getRoleCode());
//                auths.add(authority);
//            }
//        }

        return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(), true, true, true, true, auths);
    }


//    public UserDetails loadUserByUsername(String userId) throws UsernameNotFoundException {
//        log.info("用户认证，userID：{}", userId);
//        User user = userDao.findByUsername(userId);
//        if (user == null) {
//            throw new UsernameNotFoundException("Invalid username or password.");
//        }
//        return new org.springframework.security.core.userdetails.User(String.valueOf(user.getId()), user.getPassword(), getAuthority());
//    }

    private List<SimpleGrantedAuthority> getAuthority() {
        return Arrays.asList(new SimpleGrantedAuthority("ROLE_ADMIN"));
    }

    public List<User> findAll() {
        List<User> list = new ArrayList<>();
        userDao.findAll().iterator().forEachRemaining(list::add);
        return list;
    }

    @Override
    public void delete(long id) {
        userDao.deleteById(id);
    }

    @Override
    public User save(User user) {
        return userDao.save(user);
    }
}
