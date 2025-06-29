package com.marketplace.project.repository.user;


import org.springframework.data.jpa.repository.JpaRepository;

import com.marketplace.project.models.user.Role;
import com.marketplace.project.models.user.User;

import java.util.List;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    
    Optional<User> findByEmail(String email);
    
    boolean existsByEmail(String email);

    List<User> findByRole(Role role);

    Optional<User> findFirstByRole(Role role);

}

