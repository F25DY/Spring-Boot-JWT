package com.jwt.artifactjwt.repository;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;
import com.jwt.artifactjwt.model.AppUser;

public interface UserRepository extends JpaRepository<AppUser, Long> {
    Optional<AppUser> findByUsername(String username);
    Boolean existsByUsername(String username);

}


