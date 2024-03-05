package com.sport.repository;

import com.sport.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.security.config.annotation.web.oauth2.login.UserInfoEndpointDsl;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User,Integer> {
    public Optional<User> findByEmail(String email);
}
