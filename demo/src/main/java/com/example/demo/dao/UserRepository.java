package com.example.demo.dao;

import java.util.List;
import java.util.Optional;

import com.example.demo.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;



@Repository
public interface UserRepository extends JpaRepository<User, Long> {
  Optional<User> findByUsername(String username);
  List<User> findByUsernameOrEmail(String name, String phone);

  Boolean existsByUsername(String username);

  Boolean existsByEmail(String email);
}
