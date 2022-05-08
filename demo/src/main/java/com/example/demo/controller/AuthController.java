package com.example.demo.controller;

import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

import javax.validation.Valid;

import com.example.demo.dao.RoleRepository;
import com.example.demo.dao.UserRepository;
import com.example.demo.entity.ERole;
import com.example.demo.entity.Role;
import com.example.demo.entity.User;
import com.example.demo.payload.request.LoginRequest;
import com.example.demo.payload.request.SignupRequest;
import com.example.demo.payload.request.UpdateRequest;
import com.example.demo.payload.response.MessageResponse;
import com.example.demo.payload.response.UserInfoResponse;
//import com.example.demo.security.JwtUtils;
import com.example.demo.security.jwt.JwtUtils;
import com.example.demo.security.services.UserDetailsImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;


@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {
  @Autowired
  AuthenticationManager authenticationManager;

  @Autowired
  UserRepository userRepository;

  @Autowired
  RoleRepository roleRepository;
  @Autowired
  PasswordEncoder encoder;

  @Autowired
  JwtUtils jwtUtils;

  @PostMapping("/signin")
  public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

    Authentication authentication = authenticationManager
        .authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

    SecurityContextHolder.getContext().setAuthentication(authentication);

    UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

    ResponseCookie jwtCookie = jwtUtils.generateJwtCookie(userDetails);
    String jwt = jwtUtils.generateJwtToken(authentication);

    List<String> roles = userDetails.getAuthorities().stream()
            .map(item -> item.getAuthority())
            .collect(Collectors.toList());

    return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, jwtCookie.toString())
        .body(new UserInfoResponse(jwt,userDetails.getId(),
                                   userDetails.getUsername(),
                                    userDetails.getEmail(),
                                    roles
                                   ));
  }

  @PostMapping("/signup")
  public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
    if (userRepository.existsByUsername(signUpRequest.getUsername())) {
      return ResponseEntity.badRequest().body(new MessageResponse("Error: Username is already taken!"));
    }

    if (userRepository.existsByEmail(signUpRequest.getEmail())) {
      return ResponseEntity.badRequest().body(new MessageResponse("Error: Email is already in use!"));
    }

    // Create new user's account
    User user = new User(signUpRequest.getUsername(),
                          signUpRequest.getEmail(),

                          encoder.encode(signUpRequest.getPassword()));
    Set<String> strRoles = signUpRequest.getRole();
    Set<Role> roles = new HashSet<>();

    if (strRoles == null) {
      Role userRole = roleRepository.findByName(ERole.ROLE_USER)
              .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
      roles.add(userRole);
    } else {
      strRoles.forEach(role -> {
        switch (role) {
          case "admin":
            Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(adminRole);
            break;
          case "sup":
            Role supRole = roleRepository.findByName(ERole.ROLE_SUPERUSER)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(supRole);
            break;
          case "new":
            Role newRole = roleRepository.findByName(ERole.ROLE_NEW)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(newRole);
            break;
          default:
            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(userRole);
        }
      });
    }
    user.setRoles(roles);

    userRepository.save(user);

    return ResponseEntity.ok(new MessageResponse("User registered successfully!" + "status :Success"+ LocalDateTime.now()));
  }

  @PostMapping("/signout")
  public ResponseEntity<?> logoutUser() {
    ResponseCookie cookie = jwtUtils.getCleanJwtCookie();
    return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, cookie.toString())
        .body(new MessageResponse("You've been signed out!"));
  }

  @GetMapping("/users")
  public List<User> getusers(){return userRepository.findAll();}
  @GetMapping("/roles")
  public List<Role> getroles(){return roleRepository.findAll();}


  @PostMapping("/add")
  public ResponseEntity<?> registerUser1(@Valid @RequestBody SignupRequest signUpRequest) {
    if (userRepository.existsByUsername(signUpRequest.getUsername())) {
      return ResponseEntity.badRequest().body(new MessageResponse("Error: Username is already taken!"));
    }

    if (userRepository.existsByEmail(signUpRequest.getEmail())) {
      return ResponseEntity.badRequest().body(new MessageResponse("Error: Email is already in use!"));
    }

    // Create new user's account
    User user = new User(signUpRequest.getUsername(),
            signUpRequest.getEmail(),

            encoder.encode(signUpRequest.getPassword()));
    Set<String> strRoles = signUpRequest.getRole();
    Set<Role> roles = new HashSet<>();

    if (strRoles == null) {
      Role userRole = roleRepository.findByName(ERole.ROLE_USER)
              .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
      roles.add(userRole);
    } else {
      strRoles.forEach(role -> {
        switch (role) {
          case "admin":
            Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(adminRole);
            break;
          case "sup":
            Role supRole = roleRepository.findByName(ERole.ROLE_SUPERUSER)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(supRole);
            break;
          case "new":
            Role newRole = roleRepository.findByName(ERole.ROLE_NEW)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(newRole);
            break;
          default:
            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(userRole);
        }
      });
    }
    user.setRoles(roles);
    userRepository.save(user);

    return ResponseEntity.ok(new MessageResponse("User registered successfully!" + "status :Success"+ LocalDateTime.now()));
  }

  @PutMapping(value = "update1/{id}")
  public String updatePro1( @PathVariable long id , @RequestBody SignupRequest signupRequest ){
    User upadtePro=userRepository.findById(id).get();

    upadtePro.setUsername(signupRequest.getUsername());
    upadtePro.setEmail(signupRequest.getEmail());
    upadtePro.setPassword(encoder.encode(signupRequest.getPassword()));
    Set<String> strRoles = signupRequest.getRole();
    Set<Role> roles = new HashSet<>();

    if (strRoles == null) {
      Role userRole = roleRepository.findByName(ERole.ROLE_USER)
              .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
      roles.add(userRole);
    } else {
      strRoles.forEach(role -> {
        switch (role) {
          case "admin":
            Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(adminRole);
            break;
          case "sup":
            Role supRole = roleRepository.findByName(ERole.ROLE_SUPERUSER)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(supRole);
            break;
          case "new":
            Role newRole = roleRepository.findByName(ERole.ROLE_NEW)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(newRole);
            break;
          default:
            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(userRole);
        }
      });
    }
    upadtePro.setRoles(roles);

    userRepository.save(upadtePro);
    return "update succes"+signupRequest.getRole();
  }
  @PutMapping(value = "update2/{id}")
  public String updatePro1( @PathVariable long id , @RequestBody UpdateRequest signupRequest ){
    User upadtePro=userRepository.findById(id).get();
if (!(signupRequest.getUsername()==null)){
    upadtePro.setUsername(signupRequest.getUsername());}
    if (!(signupRequest.getEmail()==null)){
    upadtePro.setEmail(signupRequest.getEmail());}
    if (!(signupRequest.getPassword()==null)){
   upadtePro.setPassword(encoder.encode(signupRequest.getPassword()));}
    Set<String> strRoles = signupRequest.getRole();
    Set<Role> roles = new HashSet<>();

    if (strRoles == null) {
      Role userRole = roleRepository.findByName(ERole.ROLE_USER)
              .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
      roles.add(userRole);
    } else {
      strRoles.forEach(role -> {
        switch (role) {
          case "admin":
            Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(adminRole);
            break;
          case "sup":
            Role supRole = roleRepository.findByName(ERole.ROLE_SUPERUSER)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(supRole);
            break;
          case "new":
            Role newRole = roleRepository.findByName(ERole.ROLE_NEW)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(newRole);
            break;
          default:
            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(userRole);
        }
      });
    }
    upadtePro.setRoles(roles);
//    upadtePro.setRoles(signupRequest.getRole());



    // upadtePro.setCategory(res_partner.getCategory());
    userRepository.save(upadtePro);
    return "update succes"+signupRequest.getRole();
  }

  @DeleteMapping(value = "delete/{id}")
  public String deletePro( @PathVariable long id){
    User deletePro=userRepository.findById(id).get();
    userRepository.delete(deletePro);

    return "delete user with id"+id;
  }
  @GetMapping(value = "/username")
  public  List<User> findByUsernameOrEmail(@RequestParam String param){
    return  userRepository.findByUsernameOrEmail(param ,param);
}}
