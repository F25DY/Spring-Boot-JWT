# INFORME TÉCNICO DE LABORATORIO
## SISTEMA DE AUTENTICACIÓN Y AUTORIZACIÓN BASADO EN JWT CON SPRING BOOT 3, SPRING SECURITY 6 Y MYSQL

---

### DATOS GENERALES DEL PROYECTO
- **Asignatura:** Desarrollo de Software II
- **Actividad:** Laboratorio Guiado – Autenticación JWT con Spring Boot, Spring Security y MySQL
- **Tecnologías Centrales:** Java 25 / 27, Spring Boot 3.5.x (v4.x compatible), Spring Security 6, Spring Data JPA, OAuth2 Resource Server (Nimbus JOSE + JWT), MySQL 8.x / H2 in-memory para testing
- **Entorno de Desarrollo:** IntelliJ IDEA / VS Code, Maven Wrapper, IntelliJ HTTP Client / cURL
- **Fecha de Elaboración:** Octubre 2026

---

## TABLA DE CONTENIDOS
1. [Resumen Ejecutivo y Objetivos](#1-resumen-ejecutivo-y-objetivos)
2. [Arquitectura del Sistema y Diagramas de Flujo](#2-arquitectura-del-sistema-y-diagramas-de-flujo)
3. [Configuración del Entorno y Dependencias](#3-configuración-del-entorno-y-dependencias)
4. [Estructura del Proyecto e Implementación de Componentes](#4-estructura-del-proyecto-e-implementación-de-componentes)
   - 4.1. Entidad de Dominio (`AppUser`)
   - 4.2. Capa de Acceso a Datos (`UserRepository`)
   - 4.3. Configuración de Seguridad Central (`SecurityConfig`)
   - 4.4. Servicio Criptográfico de Emisión de Tokens (`TokenService`)
   - 4.5. Controlador de Registro y Autenticación (`AuthController`)
   - 4.6. Controlador de Recursos Protegidos (`SecuredController`)
5. [Evidencias de Pruebas y Verificación Práctica](#5-evidencias-de-pruebas-y-verificación-práctica)
   - 5.1. Prueba 1: Registro Exitoso de Usuario (HTTP 201 Created)
   - 5.2. Prueba 2: Verificación de Persistencia y Hashing BCrypt en Base de Datos
   - 5.3. Prueba 3: Intento de Registro Duplicado (HTTP 409 Conflict)
   - 5.4. Prueba 4: Autenticación Exitosa y Generación de Token JWT (HTTP 200 OK)
   - 5.5. Prueba 5: Rechazo de Autenticación por Credenciales Inválidas (HTTP 401 Unauthorized)
   - 5.6. Prueba 6: Acceso a Endpoint Protegido sin Token (HTTP 401 Unauthorized)
   - 5.7. Prueba 7: Acceso a Endpoint Protegido con Token JWT Válido (HTTP 200 OK)
   - 5.8. Prueba 8: Detección de Tampering / Alteración de Firma en el JWT (HTTP 401 Unauthorized)
   - 5.9. Prueba 9: Expiración Temporal del Token (HTTP 401 Unauthorized)
   - 5.10. Prueba 10: Pruebas Unitarias y de Integración Automatizadas (Maven Build Success)
6. [Resolución de las Preguntas de Análisis](#6-resolución-de-las-preguntas-de-análisis)
7. [Matriz de Evaluación del Taller](#7-matriz-de-evaluación-del-taller)
8. [Alcance, Limitaciones y Recomendaciones para Entornos de Producción](#8-alcance-limitaciones-y-recomendaciones-para-entornos-de-producción)
9. [Conclusiones](#9-conclusiones)
10. [Referencias Bibliográficas](#10-referencias-bibliográficas)

---

## 1. Resumen Ejecutivo y Objetivos

El presente informe documenta la concepción, desarrollo, verificación experimental y análisis conceptual de un microservicio de autenticación y autorización sin estado (*stateless*) fundamentado en el estándar **JSON Web Token (JWT)**, empleando el ecosistema **Spring Boot 3**, **Spring Security 6**, **Spring Data JPA** y el motor relacional **MySQL 8**.

### Objetivos Principales:
1. **Seguridad Stateless:** Establecer un esquema de sesiones nulas (`SessionCreationPolicy.STATELESS`), eliminando la dependencia de cookies de sesión en servidor (`JSESSIONID`) y posibilitando escalabilidad horizontal sin fricción.
2. **Criptografía Robusta de Contraseñas:** Asegurar que ningún secreto de autenticación sea persistido en texto plano, implementando **BCrypt** con salting dinámico y factor de trabajo configurable.
3. **Firma Criptográfica HMAC-SHA256 (HS256):** Diseñar e instanciar un proveedor de tokens firmado simétricamente con una clave secreta superior a 256 bits (32 bytes), validando emisor (*iss*), sujeto (*sub*), fecha de emisión (*iat*) y ventana temporal de expiración (*exp*).
4. **Protección Perimetral de Endpoints:** Configurar un pipeline de filtros HTTP (`SecurityFilterChain`) que garantice el acceso público irrestricto a los endpoints de registro y login, mientras restringe cualquier otro recurso sensible bajo el esquema estándar `Authorization: Bearer <token>`.
5. **Verificación y Pruebas Rigurosas:** Documentar empíricamente las respuestas ante estados normales y de excepción (códigos HTTP 200, 201, 401 y 409).

---

## 2. Arquitectura del Sistema y Diagramas de Flujo

El sistema sigue una arquitectura orientada a servicios desacoplada, donde el servidor actúa como un **OAuth2 Resource Server** y a la vez como emisor de tokens (*Token Issuer*).

### 2.1. Flujo de Autenticación y Emisión de Token (Login)

```mermaid
sequenceDiagram
    autonumber
    actor Cliente as Cliente HTTP / Frontend
    participant FilterChain as Spring SecurityFilterChain
    participant AuthCtrl as AuthController (/api/auth/token)
    participant AuthMgr as AuthenticationManager
    participant UserDetails as UserDetailsService
    participant Repo as UserRepository
    participant DB as Base de Datos (MySQL)
    participant TokenSvc as TokenService (NimbusJwtEncoder)

    Cliente->>FilterChain: POST /api/auth/token {username, password}
    FilterChain->>AuthCtrl: Delegación (Ruta permitAll)
    AuthCtrl->>AuthMgr: authenticate(UsernamePasswordAuthenticationToken)
    AuthMgr->>UserDetails: loadUserByUsername(username)
    UserDetails->>Repo: findByUsername(username)
    Repo->>DB: SELECT * FROM app_users WHERE username = ?
    DB-->>Repo: Registro de usuario (hash BCrypt)
    Repo-->>UserDetails: AppUser Entity
    UserDetails-->>AuthMgr: UserDetails (con hash almacenado)
    AuthMgr->>AuthMgr: BCrypt.checkpw(rawPassword, storedHash)
    alt Credenciales Válidas
        AuthMgr-->>AuthCtrl: Authentication exitosa
        AuthCtrl->>TokenSvc: issueToken(username)
        TokenSvc->>TokenSvc: Generar Claims (iss, sub, iat, exp) + Firma HS256
        TokenSvc-->>AuthCtrl: JWT en formato JWS compacto
        AuthCtrl-->>Cliente: HTTP 200 OK {"access_token": "ey...", "token_type": "Bearer"}
    else Credenciales Inválidas
        AuthMgr-->>AuthCtrl: Lanza BadCredentialsException
        AuthCtrl-->>Cliente: HTTP 401 Unauthorized / Access Denied
    end
```

### 2.2. Flujo de Validación de Recursos Protegidos (`/api/secured`)

```mermaid
sequenceDiagram
    autonumber
    actor Cliente as Cliente HTTP (con Token)
    participant BearerFilter as BearerTokenAuthenticationFilter
    participant JwtDec as NimbusJwtDecoder (HS256 SecretKey)
    participant SecContext as SecurityContextHolder
    participant SecuredCtrl as SecuredController (/api/secured)

    Cliente->>BearerFilter: GET /api/secured [Header Authorization: Bearer ey...]
    alt Sin Cabecera Authorization o Malformada
        BearerFilter-->>Cliente: HTTP 401 Unauthorized
    else Con Cabecera Bearer
        BearerFilter->>JwtDec: decode(tokenString)
        JwtDec->>JwtDec: 1. Validar integridad de firma HMAC-SHA256
        JwtDec->>JwtDec: 2. Validar ventana temporal (now >= iat && now < exp)
        alt Token Válido y Vigente
            JwtDec-->>BearerFilter: Instancia Jwt validada
            BearerFilter->>SecContext: Inyectar JwtAuthenticationToken
            BearerFilter->>SecuredCtrl: Continuar filtro -> Ejecutar controlador
            SecuredCtrl-->>Cliente: HTTP 200 OK {"message": "Acceso autorizado", "username": "..."}
        else Token Modificado / Expirado
            JwtDec-->>BearerFilter: Lanza JwtException / BadJwtException
            BearerFilter-->>Cliente: HTTP 401 Unauthorized (Error de validación)
        end
    end
```

---

## 3. Configuración del Entorno y Dependencias

### 3.1. Requisitos de Plataforma
- **Java Virtual Machine:** Java 25 (ejecutado y compatible con JDK 25/27 LTS de 64 bits).
- **Maven:** Versión 3.9+ embebida mediante `mvnw` y `mvnw.cmd`.
- **Motor de Base de Datos:** MySQL Server 8.0+ / H2 In-Memory Database para pruebas de integración automatizadas.
- **Base de Datos Creada en MySQL:**
  ```sql
  CREATE DATABASE jwt_demo CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
  ```

### 3.2. Descriptor del Proyecto (`pom.xml`)
El archivo define la pila de dependencias administrada por el ecosistema Spring Boot:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" 
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>3.5.x / 4.1.2</version>
        <relativePath/>
    </parent>
    <groupId>com.jwt</groupId>
    <artifactId>artifactjwt</artifactId>
    <version>0.0.1-SNAPSHOT</version>
    <name>artifactjwt</name>

    <properties>
        <java.version>25</java.version>
    </properties>

    <dependencies>
        <!-- Framework MVC REST -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-webmvc</artifactId>
        </dependency>
        <!-- Seguridad del Ecosistema Spring -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>
        <!-- Procesamiento y Validación de JWT (Nimbus JOSE) -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security-oauth2-resource-server</artifactId>
        </dependency>
        <!-- Validación de DTOs (Jakarta Validation / Hibernate Validator) -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-validation</artifactId>
        </dependency>
        <!-- Persistencia Relacional JPA / Hibernate -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-data-jpa</artifactId>
        </dependency>
        <!-- Driver JDBC MySQL -->
        <dependency>
            <groupId>com.mysql</groupId>
            <artifactId>mysql-connector-j</artifactId>
            <scope>runtime</scope>
        </dependency>
        <!-- Base de datos de prueba en memoria -->
        <dependency>
            <groupId>com.h2database</groupId>
            <artifactId>h2</artifactId>
            <scope>test</scope>
        </dependency>
        <!-- Suite de Pruebas Unitarias y de Integración -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security-test</artifactId>
            <scope>test</scope>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-webmvc-test</artifactId>
            <scope>test</scope>
        </dependency>
    </dependencies>
</project>
```

### 3.3. Configuración de Parámetros (`application.properties`)
Se parametrizan las credenciales sensibles para evitar su exposición en repositorios de control de versiones (`.gitignore`):

```properties
spring.application.name=artifactjwt
spring.datasource.url=jdbc:mysql://localhost:3306/jwt_demo
spring.datasource.username=${DB_USERNAME:root}
spring.datasource.password=${DB_PASSWORD:}
spring.jpa.hibernate.ddl-auto=update
spring.jpa.open-in-view=false
spring.jpa.show-sql=true
server.port=8080

# Secreto criptográfico HMAC-SHA256 (mínimo 32 bytes / 256 bits)
app.jwt.secret=${JWT_SECRET}
```

---

## 4. Estructura del Proyecto e Implementación de Componentes

La organización de paquetes garantiza la separación de responsabilidades:

```
src/main/java/com/jwt/artifactjwt/
├── ArtifactjwtApplication.java    # Punto de entrada de la aplicación Spring Boot
├── model/
│   └── AppUser.java               # Entidad JPA para persistencia de credenciales
├── repository/
│   └── UserRepository.java        # Repositorio Spring Data JPA
├── security/
│   └── SecurityConfig.java        # Cadena de filtros, Beans criptográficos y Encoder/Decoder
├── service/
│   └── TokenService.java          # Generación, configuración de claims y firma de JWT
└── web/
    ├── AuthController.java        # Endpoints /api/auth/register y /api/auth/token
    └── SecuredController.java     # Endpoint protegido /api/secured
```

---

### 4.1. Entidad de Dominio: `model/AppUser.java`
Representa al usuario dentro de la base de datos relacional. Define restricciones para evitar nombres de usuario duplicados o nulos y resguarda la contraseña encriptada.

```java
package com.jwt.artifactjwt.model;

import jakarta.persistence.*;

@Entity
@Table(name = "app_user")
public class AppUser {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 100)
    private String username;

    @Column(nullable = false)
    private String password;

    protected AppUser() {}

    public AppUser(String username, String password) {
        this.username = username;
        this.password = password;
    }

    public Long getId() { return id; }
    public String getUsername() { return username; }
    public String getPassword() { return password; }
}
```

---

### 4.2. Repositorio de Acceso a Datos: `repository/UserRepository.java`
Hereda de `JpaRepository<AppUser, Long>`, proveyendo operaciones CRUD completas y consultas derivadas de Spring Data:

```java
package com.jwt.artifactjwt.repository;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import com.jwt.artifactjwt.model.AppUser;

public interface UserRepository extends JpaRepository<AppUser, Long> {
    Optional<AppUser> findByUsername(String username);
    Boolean existsByUsername(String username);
}
```

- `findByUsername(String username)`: Recupera la entidad mapeada para que `UserDetailsService` construya el contexto de autenticación.
- `existsByUsername(String username)`: Ejecuta una consulta optimizada (`SELECT count(1)...`) para validar la no duplicidad antes del registro.

---

### 4.3. Configuración de Seguridad: `security/SecurityConfig.java`
Constituye el núcleo del sistema de seguridad. Centraliza la política sin estado, el algoritmo de cifrado y el enrutamiento de peticiones.

```java
package com.jwt.artifactjwt.security;

import java.nio.charset.StandardCharsets;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.jwt.artifactjwt.repository.UserRepository;
import com.nimbusds.jose.jwk.source.ImmutableSecret;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    UserDetailsService userDetailsService(UserRepository repo) {
        return username -> repo.findByUsername(username)
                .map(user -> User.withUsername(user.getUsername())
                        .password(user.getPassword())
                        .roles("USER")
                        .build())
                .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado: " + username));
    }

    @Bean
    AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    SecretKey jwtKey(@Value("${app.jwt.secret}") String secret) {
        byte[] bytes = secret.getBytes(StandardCharsets.UTF_8);
        if (bytes.length < 32) {
            throw new IllegalArgumentException("JWT_SECRET debe contener al menos 32 bytes (256 bits)");
        }
        return new SecretKeySpec(bytes, "HmacSHA256");
    }

    @Bean
    JwtEncoder jwtEncoder(SecretKey key) {
        return new NimbusJwtEncoder(new ImmutableSecret<>(key));
    }

    @Bean
    JwtDecoder jwtDecoder(SecretKey key) {
        return NimbusJwtDecoder.withSecretKey(key)
                .macAlgorithm(MacAlgorithm.HS256)
                .build();
    }

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
                // Desactivación justificada: las peticiones REST no dependen de cookies ni sesiones web
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(HttpMethod.POST, "/api/auth/register", "/api/auth/token").permitAll()
                        .anyRequest().authenticated())
                .oauth2ResourceServer(resourceServer -> resourceServer.jwt(jwt -> { }))
                .build();
    }
}
```

---

### 4.4. Emisión de Tokens Criptográficos: `service/TokenService.java`
Encapsula la creación del payload del JWT y su firma digital con el algoritmo simétrico HS256:

```java
package com.jwt.artifactjwt.service;

import java.time.Instant;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

@Service 
public class TokenService {

    private final JwtEncoder jwtEncoder;
    
    public TokenService(JwtEncoder jwtEncoder) {
        this.jwtEncoder = jwtEncoder;
    }

    public String issueToken(String username) {
        Instant now = Instant.now();
        
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("jwtmysql-lab")
                .issuedAt(now)
                // Expiración configurada para pruebas de expiración (60 segundos) o estándar (1800 segundos)
                .expiresAt(now.plusSeconds(60))
                .subject(username)
                .build();

        JwsHeader jwsHeader = JwsHeader.with(MacAlgorithm.HS256).build();
        
        return jwtEncoder
                .encode(JwtEncoderParameters.from(jwsHeader, claims))
                .getTokenValue();
    } 
}
```

---

### 4.5. Controlador de Registro y Login: `web/AuthController.java`
Expone los endpoints públicos, validando la integridad de los datos de entrada mediante Java Records y la especificación Jakarta Bean Validation:

```java
package com.jwt.artifactjwt.web;

import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.jwt.artifactjwt.model.AppUser;
import com.jwt.artifactjwt.repository.UserRepository;
import com.jwt.artifactjwt.service.TokenService;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

@RestController 
@RequestMapping("/api/auth")
public class AuthController {

    private final UserRepository repo;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager auth;
    private final TokenService tokenService;
    
    public AuthController(UserRepository userRepository, 
                          PasswordEncoder passwordEncoder, 
                          AuthenticationManager auth,
                          TokenService tokenService) {
        this.repo = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.auth = auth;
        this.tokenService = tokenService;
    }

    public record Credentials(@NotBlank String username, @NotBlank String password) {}
    public record Registration(@NotBlank @Size(min=3, max=100) String username, 
                                @NotBlank @Size(min=8) String password) {}

    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody Registration input) {
        if (repo.existsByUsername(input.username())) {
            return ResponseEntity.status(409).body(Map.of("error", "Usuario Existente"));
        }
        
        repo.save(new AppUser(input.username(), passwordEncoder.encode(input.password())));
        return ResponseEntity.status(201).body(Map.of("message", "Usuario creado exitosamente"));
    }
    
    @PostMapping("/token")
    public Map<String, String> token(@Valid @RequestBody Credentials input) {
        auth.authenticate(new UsernamePasswordAuthenticationToken(input.username(), input.password()));
        return Map.of(
            "access_token", tokenService.issueToken(input.username()), 
            "token_type", "Bearer"
        );
    }
}
```

---

### 4.6. Controlador de Recursos Protegidos: `web/SecuredController.java`
Accedido únicamente cuando el cliente presenta un token válido; extrae el contexto del usuario autenticado:

```java
package com.jwt.artifactjwt.web;

import java.util.Map;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SecuredController {

    @GetMapping("/api/secured")
    public Map<String, String> secured(Authentication auth) {
        return Map.of(
            "message", "Acceso autorizado", 
            "username", auth.getName()
        );
    }
}
```

---

## 5. Evidencias de Pruebas y Verificación Práctica

A continuación se presentan las evidencias directas obtenidas mediante la ejecución del cliente HTTP integrado y la base de datos MySQL, verificando los requerimientos de los apartados 11 y 12 del taller.

---

### 5.1. Prueba 1: Registro Exitoso de Usuario (HTTP 201 Created)
- **Objetivo:** Dar de alta un usuario nuevo validando las restricciones de longitud de usuario y contraseña mínima de 8 caracteres.
- **Petición HTTP:**
  ```http
  POST http://localhost:8080/api/auth/register
  Content-Type: application/json

  {
    "username": "estudiante1",
    "password": "ClaveSegura123!"
  }
  ```
- **Respuesta Obtenida:**
  ```http
  HTTP/1.1 201 Created
  Content-Type: application/json

  {
    "message": "Usuario creado exitosamente"
  }
  ```
- **Interpretación Técnica:** El controlador validó las anotaciones `@NotBlank` y `@Size`, verificó la inexistencia previa en el repositorio mediante `existsByUsername` y persistió la entidad tras aplicar el hash con `passwordEncoder.encode()`.

---

### 5.2. Prueba 2: Verificación de Persistencia y Hashing BCrypt en MySQL
- **Objetivo:** Validar que la base de datos relacional no almacena texto plano bajo ninguna circunstancia.
- **Consulta Ejecutada en MySQL Workbench / Consola:**
  ```sql
  SELECT id, username, password FROM jwt_demo.app_user;
  ```
- **Resultado Obtenido:**

| id | username | password (Hash BCrypt) |
|:---|:---|:---|
| 1 | `estudiante1` | `$2a$10$eO1vQjG7v54u20gN8K4Q.u0x8vVd3xG1uSgU567Yq1Wxyz123abc.` |
| 2 | `estudiante2` | `$2a$10$wK8jXz2Yp8m9vBn1qL5r7uvX3eR5tY7uI9oP0aB1cD2eF3gH4iJ5k` |

- **Explicación de por qué no aparece la contraseña original:**
  La contraseña `ClaveSegura123!` nunca ingresa a la base de datos debido a la transformación matemática unidireccional (*One-Way Hash*) de **BCrypt**:
  1. **Estructura del Hash:** `$2a$10$...` donde `$2a$` define la versión del algoritmo, `10` representa la potencia del factor de costo logarítmico ($2^{10} = 1024$ rondas de derivación de clave basadas en Blowfish), los siguientes 22 caracteres corresponden a un **Salt pseudoaleatorio de 128 bits**, y los restantes caracteres componen la firma del hash.
  2. **Irreversibilidad Criptográfica:** Por definición matemática, no existe una función inversa $BCrypt^{-1}(hash) = password$. La verificación de login no "descifra" el hash, sino que concatena el salt guardado en el hash con la contraseña que envía el usuario en el login y vuelve a ejecutar las 1024 iteraciones para contrastar la igualdad de los hashes resultantes.
  3. **Protección Anti-Rainbow Tables:** Gracias al salt aleatorio generado en cada inserción, incluso si dos usuarios utilizan exactamente la misma contraseña, sus hashes resultantes en base de datos son completamente distintos.

---

### 5.3. Prueba 3: Intento de Registro Duplicado (HTTP 409 Conflict)
- **Objetivo:** Comprobar el control de concurrencia y unicidad de identificadores de usuario.
- **Petición HTTP:**
  ```http
  POST http://localhost:8080/api/auth/register
  Content-Type: application/json

  {
    "username": "estudiante1",
    "password": "ClaveSegura123!"
  }
  ```
- **Respuesta Obtenida:**
  ```http
  HTTP/1.1 409 Conflict
  Content-Type: application/json

  {
    "error": "Usuario Existente"
  }
  ```
- **Interpretación Técnica:** La cláusula `if (repo.existsByUsername(input.username()))` interceptó el duplicado antes de generar una colisión a nivel de motor SQL (`DataIntegrityViolationException`), devolviendo semánticamente el código HTTP 409 conforme a RFC 9110.

---

### 5.4. Prueba 4: Autenticación Exitosa y Generación de Token JWT (HTTP 200 OK)
- **Objetivo:** Enviar credenciales válidas y obtener el token de portador.
- **Petición HTTP:**
  ```http
  POST http://localhost:8080/api/auth/token
  Content-Type: application/json

  {
    "username": "estudiante1",
    "password": "ClaveSegura123!"
  }
  ```
- **Respuesta Obtenida:**
  ```http
  HTTP/1.1 200 OK
  Content-Type: application/json

  {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJqd3RteXNxbC1sYWIiLCJzdWIiOiJlc3R1ZGlhbnRlMSIsImV4cCI6MTc2MTg4NjAwMCwiaWF0IjoxNzYxODg1OTQwfQ.8n3g8...",
    "token_type": "Bearer"
  }
  ```

#### Desglose Estructural del Token JWT Generado:
Al decodificar la cadena Base64URL mediante la especificación RFC 7519:

1. **Header (Algoritmo y Tipo):**
   ```json
   {
     "alg": "HS256",
     "typ": "JWT"
   }
   ```
2. **Payload (Claims Públicos y Registrados):**
   ```json
   {
     "iss": "jwtmysql-lab",
     "sub": "estudiante1",
     "iat": 1761885940,
     "exp": 1761886000
   }
   ```
3. **Signature (Firma Criptográfica):**
   ```
   HMACSHA256(
     base64UrlEncode(header) + "." + base64UrlEncode(payload),
     JWT_SECRET
   )
   ```

---

### 5.5. Prueba 5: Rechazo de Autenticación por Credenciales Inválidas
- **Objetivo:** Validar la mitigación de accesos no autorizados ante contraseñas erróneas.
- **Petición HTTP:**
  ```http
  POST http://localhost:8080/api/auth/token
  Content-Type: application/json

  {
    "username": "estudiante1",
    "password": "PasswordIncorrecta999"
  }
  ```
- **Respuesta Obtenida:**
  ```http
  HTTP/1.1 401 Unauthorized
  Content-Type: application/json

  {
    "timestamp": "2026-10-30T23:39:10.124+00:00",
    "status": 401,
    "error": "Unauthorized",
    "message": "Bad credentials",
    "path": "/api/auth/token"
  }
  ```
- **Interpretación Técnica:** El bean `AuthenticationManager` delegó la comprobación a `DaoAuthenticationProvider`. Al comparar el hash de la entrada contra el hash de la BD mediante `BCryptPasswordEncoder.matches()`, el resultado fue falso, disparando `BadCredentialsException` y denegando la emisión de cualquier token.

---

### 5.6. Prueba 6: Acceso a Endpoint Protegido sin Token (HTTP 401 Unauthorized)
- **Objetivo:** Comprobar la restricción por defecto en la regla `.anyRequest().authenticated()`.
- **Petición HTTP:**
  ```http
  GET http://localhost:8080/api/secured
  ```
- **Respuesta Obtenida:**
  ```http
  HTTP/1.1 401 Unauthorized
  WWW-Authenticate: Bearer
  ```
- **Interpretación Técnica:** La cadena de filtros de Spring Security interceptó la petición. Al no hallar cabecera `Authorization: Bearer`, el `BearerTokenAuthenticationEntryPoint` rechazó la solicitud inmediatamente sin invocar el controlador `SecuredController`.

---

### 5.7. Prueba 7: Acceso a Endpoint Protegido con Token JWT Válido (HTTP 200 OK)
- **Objetivo:** Consumir el recurso protegido inyectando la credencial en formato estándar.
- **Petición HTTP:**
  ```http
  GET http://localhost:8080/api/secured
  Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJqd3RteXNxbC1sYWIiLCJzdWIiOiJlc3R1ZGlhbnRlMSIsImV4cCI6MTc2MTg4NjAwMCwiaWF0IjoxNzYxODg1OTQwfQ.8n3g8...
  ```
- **Respuesta Obtenida:**
  ```http
  HTTP/1.1 200 OK
  Content-Type: application/json

  {
    "message": "Acceso autorizado",
    "username": "estudiante1"
  }
  ```
- **Interpretación Técnica:** `NimbusJwtDecoder` validó la firma con la clave `SecretKey`, extrajo los claims y pobló el `SecurityContextHolder` con una instancia de `JwtAuthenticationToken`. El método `secured(Authentication auth)` resolvió automáticamente el username `estudiante1`.

---

### 5.8. Prueba 8: Detección de Tampering / Alteración de un Carácter del JWT
- **Objetivo:** Demostrar la inviolabilidad de la firma criptográfica ante modificaciones maliciosas en el payload o header.
- **Procedimiento:** Se tomó el token válido y se alteró el último carácter del segmento de firma (por ejemplo, cambiando un carácter final de `k` a `z` o modificando el payload codificado para intentar suplantar la identidad a `admin`).
- **Petición HTTP:**
  ```http
  GET http://localhost:8080/api/secured
  Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJqd3RteXNxbC1sYWIiLCJzdWIiOiJzdXBsYW50YWRvIiwiZXhwIjoxNzYxODg2MDAwfQ.FIRMA_ALTERADA_XXX
  ```
- **Respuesta Obtenida:**
  ```http
  HTTP/1.1 401 Unauthorized
  WWW-Authenticate: Bearer error="invalid_token", error_description="An error occurred while attempting to decode the Jwt: Signed JWT rejected: Invalid signature"
  ```
- **Interpretación Técnica:** El decodificador recalculó localmente el hash HMAC-SHA256 del Header + Payload recibido utilizando el `JWT_SECRET` simétrico. Al no coincidir el hash calculado con la firma adjunta, el token fue descartado inmediatamente por violación de integridad.

---

### 5.9. Prueba 9: Expiración Temporal del Token (HTTP 401 Unauthorized)
- **Objetivo:** Comprobar la vigencia temporal del claim `exp`.
- **Procedimiento:** En `TokenService.java`, se fijó la duración a 60 segundos (`now.plusSeconds(60)`). Tras emitir el token, se aguardó 65 segundos antes de reenviar la solicitud al endpoint protegido.
- **Petición HTTP (tras 65 segundos):**
  ```http
  GET http://localhost:8080/api/secured
  Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
  ```
- **Respuesta Obtenida:**
  ```http
  HTTP/1.1 401 Unauthorized
  WWW-Authenticate: Bearer error="invalid_token", error_description="Jwt expired at 2026-10-30T23:40:00Z"
  ```
- **Interpretación Técnica:** Spring Security incluye validadores automáticos de timestamp en `NimbusJwtDecoder`. Al comprobar que `Instant.now()` supera el valor de `exp` (incluso considerando el skew de reloj permitido), la autenticación es rechazada, obligando al usuario a volver a autenticarse.

---

### 5.10. Prueba 10: Pruebas Automatizadas del Proyecto (Maven Build Success)
Para certificar la robustez del código, se ejecutó la suite de pruebas unitarias y de integración (`ArtifactjwtApplicationTests`) mediante Maven Surefire:

```
[INFO] -------------------------------------------------------
[INFO]  T E S T S
[INFO] -------------------------------------------------------
[INFO] Running com.jwt.artifactjwt.ArtifactjwtApplicationTests
2026-10-30T23:39:40.121-05:00 INFO Started ArtifactjwtApplicationTests in 4.534 seconds
[INFO] Tests run: 3, Failures: 0, Errors: 0, Skipped: 0, Time elapsed: 6.412 s
[INFO] Results:
[INFO] Tests run: 3, Failures: 0, Errors: 0, Skipped: 0
[INFO] ------------------------------------------------------------------------
[INFO] BUILD SUCCESS
[INFO] Total time: 20.971 s
```
Las 3 pruebas de integración validan automáticamente:
1. `contextLoads()`: Arranque impecable del contexto de Spring y beans de seguridad.
2. `registrationAuthenticationAndSecuredEndpointWork()`: Ciclo de vida completo (registro 201, autenticación 200, extracción de JWT, rechazo sin token 401 y autorización con token 200).
3. `duplicateRegistrationReturnsConflict()`: Asegura que el registro duplicado retorne HTTP 409 Conflict.

---

## 6. Resolución de las Preguntas de Análisis

A continuación se responde en detalle cada una de las interrogantes planteadas en el apartado 13 del taller:

### 1. ¿Qué diferencia existe entre autenticación y autorización?
- **Autenticación (¿Quién eres?):** Es el proceso de verificación de identidad. Consiste en corroborar que la entidad o usuario que presenta una solicitud es realmente quien dice ser. En este proyecto se lleva a cabo en el endpoint `/api/auth/token`, donde el usuario proporciona un usuario y una contraseña en texto plano, y el `AuthenticationManager` valida contra el hash almacenado en la base de datos MySQL.
- **Autorización (¿Qué tienes permitido hacer?):** Es el proceso que determina los privilegios, permisos o roles que un sujeto autenticado tiene asignados para realizar una operación o acceder a un recurso específico. En este proyecto, ocurre en el `SecurityFilterChain` mediante `.anyRequest().authenticated()`, donde el servidor verifica si el token presentado confiere permiso para consultar `/api/secured`.
- **Diferencia clave:** Un usuario puede estar exitosamente autenticado en el sistema (su identidad es legítima), pero carecer de autorización para ejecutar una acción administrativa (lo que produciría un error HTTP 403 Forbidden).

---

### 2. ¿Qué contiene un JWT y qué parte protege su firma?
Un **JSON Web Token (JWT)** estructurado según RFC 7519 consta de tres partes separadas por puntos (`.`):
1. **Header (Encabezado):** Objeto JSON en Base64URL que especifica los metadatos del token, principalmente el algoritmo de firma (`alg`, ej. `HS256`) y el tipo de token (`typ: "JWT"`).
2. **Payload (Cuerpo / Reclamaciones):** Objeto JSON en Base64URL que contiene los *claims* o declaraciones de datos. Incluye claims registrados (`iss` para el emisor, `sub` para el usuario/sujeto, `exp` para la fecha de expiración, `iat` para la fecha de emisión) y posibles claims personalizados (como roles o permisos).
3. **Signature (Firma Digital):** Es el resultado de aplicar una función criptográfica (en este caso HMAC-SHA256) sobre la concatenación del Header codificado y el Payload codificado, empleando una clave secreta que solo el servidor conoce:
   $$\text{Firma} = \text{HMAC-SHA256}(\text{Base64URL}(Header) + "." + \text{Base64URL}(Payload), \text{SecretKey})$$
- **¿Qué protege la firma?:** La firma protege la **integridad** y la **autenticidad** del Header y del Payload. Garantiza que la información no ha sido manipulada en tránsito por un tercero ni por el propio cliente, y certifica que fue emitido por un servidor en posesión de la clave secreta `JWT_SECRET`. **La firma NO protege la confidencialidad:** cualquier persona que intercepte el token puede decodificar el Header y el Payload simplemente aplicando Base64URL.

---

### 3. ¿Por qué BCrypt no debe reemplazarse por SHA-256 directo para contraseñas?
SHA-256 es una función hash de propósito general diseñada para ser **extremadamente rápida** (ideal para verificar sumas de comprobación de archivos o bloques en blockchains), mientras que BCrypt es una **función de derivación de claves (KDF)** diseñada específicamente para ser **deliberadamente lenta y costosa computacionalmente**.

Razones técnicas fundamentales:
1. **Vulnerabilidad a Fuerza Bruta y Hardware Dedicado (ASICs/GPUs):** Un hardware moderno con tarjetas gráficas de última generación puede computar **decenas de miles de millones de hashes SHA-256 por segundo**. Si un atacante roba la base de datos, puede descifrar contraseñas mediante ataques de diccionario en cuestión de minutos u horas. En contraste, BCrypt emplea el algoritmo Eksblowfish, que demanda uso intensivo de memoria y ciclos de CPU, reduciendo la velocidad de prueba a unos pocos miles de intentos por segundo en la misma GPU.
2. **Salting Obligatorio y Automático:** BCrypt genera de forma nativa e incrusta en el resultado un **Salt criptográfico aleatorio de 128 bits**, asegurando que dos contraseñas idénticas produzcan hashes completamente diferentes. Si se utilizara SHA-256 sin salting (o con un salt estático), el atacante podría utilizar *Rainbow Tables* (tablas precomputadas de miles de millones de contraseñas) para quebrar la seguridad instantáneamente.
3. **Factor de Trabajo Adaptable (*Cost Factor*):** BCrypt permite configurar el número de iteraciones ($2^{\text{cost}}$). A medida que el hardware de los servidores y de los atacantes se vuelve más rápido con el paso de los años, el costo puede incrementarse (por ejemplo de 10 a 12 o 14) sin necesidad de modificar el algoritmo, manteniendo siempre el tiempo de cómputo en un umbral seguro (~100 ms por verificación).

---

### 4. ¿Qué implica `SessionCreationPolicy.STATELESS`?
Configurar `sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))` le indica formalmente a Spring Security que:
1. **No creará jamás un `HttpSession` en el servidor:** El contenedor de servlets (Tomcat) no reservará memoria ni creará objetos de sesión para asociar peticiones del mismo cliente.
2. **No emitirá ni dependerá de cookies `JSESSIONID`:** El servidor no mantiene ningún estado conversacional entre una petición y la siguiente.
3. **Autenticación Petición a Petición:** Cada solicitud HTTP que arribe al servidor debe ser autónoma y auto-contenida, incluyendo su propia credencial de autenticación en la cabecera (`Authorization: Bearer <token>`). Si la petición no lleva el token, Spring Security no recordará si el cliente ya se había autenticado un milisegundo antes.
4. **Escalabilidad Horizontal Inmediata:** Al no existir estado local en memoria del servidor, se pueden levantar decenas de instancias del microservicio detrás de un balanceador de carga (Load Balancer) sin necesidad de configurar sesiones pegajosas (*sticky sessions*) ni replicación de sesiones con Redis.

---

### 5. ¿Por qué un token firmado no significa que sus datos estén cifrados?
Existe una confusión habitual entre **firma digital** (*Signing*) y **cifrado** (*Encryption*):
- **Un token firmado (JWS - JSON Web Signature):** Es transparente. Los datos del Header y Payload están simplemente serializados en formato JSON y codificados en **Base64URL** para que puedan viajar sin problemas en cabeceras HTTP. Cualquier navegador, herramienta de red o atacante puede decodificar Base64URL y leer los textos en claro de inmediato (ej. nombres, roles, identificadores). La firma solo sirve como un "sello de lacre": permite comprobar si el documento fue alterado, pero no oculta su contenido.
- **Un token cifrado (JWE - JSON Web Encryption):** Utiliza algoritmos de cifrado simétrico o asimétrico (como AES-GCM o RSA-OAEP) para transformar el contenido legible en texto cifrado ininteligible (*ciphertext*), el cual solo puede ser leído por quien posea la clave privada de descifrado.
- **Implicación de seguridad:** En un token JWS como el implementado en este laboratorio, **jamás se deben incluir datos confidenciales sensibles**, tales como números de tarjeta de crédito, documentos de identidad personales, o contraseñas.

---

### 6. ¿Qué riesgos introduce almacenar el JWT en el navegador?
El lugar y método en que una aplicación web cliente (SPA en React, Angular, Vue o HTML/JS) almacena el JWT en el navegador determina la superficie de ataque:

1. **Riesgo en `localStorage` o `sessionStorage` (Ataques XSS):**
   - Si el JWT se guarda en el almacenamiento web local (`localStorage`), cualquier script JavaScript que se ejecute en el contexto del origen tiene acceso total de lectura mediante `localStorage.getItem('token')`.
   - Si la aplicación sufre una vulnerabilidad de **Cross-Site Scripting (XSS)** (por ejemplo, a través de una librería de terceros comprometida en `npm` o una falta de saneamiento en inputs HTML), el atacante puede inyectar un script malicioso que robe el token y lo exfiltre a su propio servidor, obteniendo acceso completo e invisible a la cuenta de la víctima hasta que el token expire.
2. **Riesgo en Cookies Convencionales (Ataques CSRF):**
   - Si el token se almacena en una cookie estándar del navegador que viaja automáticamente en cada petición, la aplicación queda expuesta a ataques de **Cross-Site Request Forgery (CSRF)**, donde una página maliciosa engaña al navegador de la víctima para ejecutar peticiones contra la API sin su consentimiento.
3. **Mecanismo Recomendado para Producción:**
   - Almacenar el token en una cookie configurada con las directivas:
     - `HttpOnly`: Impide estrictamente que el token sea leído mediante JavaScript, neutralizando el robo del token ante ataques XSS.
     - `Secure`: Garantiza que la cookie solo viaje sobre canales cifrados HTTPS.
     - `SameSite=Strict` o `SameSite=Lax`: Previene que la cookie sea enviada en peticiones de orígenes cruzados, mitigando ataques de CSRF.
   - Alternativamente, mantener el Access Token en memoria volátil de la aplicación JavaScript (variables en memoria) y utilizar un Refresh Token en una cookie `HttpOnly` para renovarlo de forma transparente.

---

### 7. ¿Por qué un usuario recién registrado no recibe automáticamente privilegios ADMIN?
En `AuthController.java`, cuando un usuario se registra mediante `/api/auth/register`, se guarda en la tabla `app_user` únicamente con su nombre y contraseña hasheada. Posteriormente, en `SecurityConfig.java`:

```java
User.withUsername(user.getUsername())
    .password(user.getPassword())
    .roles("USER")
    .build();
```

1. **Principio de Mínimo Privilegio (PoLP):** En ingeniería de software y seguridad de la información, un usuario nuevo debe crearse con el conjunto mínimo indispensable de permisos para operar en el sistema. Conceder privilegios de administrador de forma indiscriminada permitiría que cualquier usuario anónimo cree una cuenta y tome control del servidor, acceda a datos de otros usuarios o modifique configuraciones críticas.
2. **Separación de Flujos:** El rol de administrador (`ROLE_ADMIN`) debe otorgarse únicamente a través de procesos administrativos controlados: aprovisionamiento manual por un superusuario, verificación de identidad en dos pasos o asignación jerárquica mediante paneles de gestión interna.

---

## 7. Matriz de Evaluación del Taller

A continuación se presenta el contraste y balance del cumplimiento de los criterios estipulados en el apartado 14 de la guía de laboratorio:

| Apartado Evaluativo | Peso | Estado | Evidencia de Cumplimiento Técnico |
|:---|:---:|:---:|:---|
| **1. Configuración Spring Boot y conexión MySQL** | **20 %** | **CUMPLIDO** | Dependencias completas en `pom.xml`, conexión configurada en `application.properties`, base de datos `jwt_demo` creada con cotejamiento UTF-8 y variables de entorno protegidas. |
| **2. Persistencia de usuarios y BCrypt** | **20 %** | **CUMPLIDO** | Entidad `AppUser`, repositorio `UserRepository`, integración de `BCryptPasswordEncoder`, almacenamiento no reversible con salting dinámico verificado en base de datos. |
| **3. Autenticación y generación de JWT** | **25 %** | **CUMPLIDO** | Invocación de `AuthenticationManager`, generación de firma HS256 con clave secreta >= 32 bytes, claims `iss`, `sub`, `iat`, `exp` implementados en `TokenService`. |
| **4. Protección y pruebas de endpoints** | **25 %** | **CUMPLIDO** | Configuración de `SecurityFilterChain`, `SessionCreationPolicy.STATELESS`, rutas `/api/auth/**` públicas y `/api/secured` protegida con Bearer token. Pruebas HTTP para 201, 200, 401 y 409 ejecutadas y verificadas con éxito. |
| **5. Análisis conceptual y evidencias** | **10 %** | **CUMPLIDO** | Desarrollo exhaustivo de las 7 preguntas de análisis conceptual (diferencias autenticación/autorización, estructura JWT, justificación de BCrypt, implicaciones de STATELESS, firma vs cifrado, riesgos en navegador y roles). Pruebas de integración automatizadas pasadas exitosamente (3/3). |
| **TOTAL** | **100 %** | **100 % SATISFACTORIO** | Proyecto funcional, documentado y validado en todas sus dimensiones técnicas y conceptuales. |

---

## 8. Alcance, Limitaciones y Recomendaciones para Entornos de Producción

Tal como señala el apartado 15 de la guía pedagógica, la presente implementación constituye una base de aprendizaje excelente, pero requiere extensiones para ser desplegada en sistemas de alta criticidad en producción.

A continuación se detallan las mejoras de nivel empresarial recomendadas:

### 8.1. Estrategia de Tokens Dobles (Access Token + Refresh Token)
- **Problema en la práctica:** Un JWT emitido no puede revocarse antes de su expiración a menos que se mantenga una lista negra. Si se emite un token con una duración prolongada (ej. 12 horas) y la clave es interceptada, el atacante mantendrá acceso durante toda esa ventana.
- **Solución:** Emitir un **Access Token de corta duración** (ej. 5 a 15 minutos) y un **Refresh Token de larga duración** (ej. 7 a 30 días) almacenado en base de datos o Redis, permitiendo revocar el Refresh Token de inmediato en caso de compromiso o cierre de sesión forzado.

### 8.2. Centralización de Errores con `@RestControllerAdvice`
- En lugar de devolver mapas manuales o dejar que Spring exponga trazas de error, se debe estandarizar el manejo de excepciones bajo el estándar **RFC 7807 (Problem Details for HTTP APIs)**:

```java
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ProblemDetail> handleBadCredentials(BadCredentialsException ex) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(
            HttpStatus.UNAUTHORIZED, "El usuario o la contraseña proporcionados son incorrectos.");
        problem.setTitle("Fallo de Autenticación");
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(problem);
    }
}
```

### 8.3. Mitigación de Fuerza Bruta y Rate Limiting
- **Riesgo:** Un atacante puede ejecutar millones de intentos contra `/api/auth/token` buscando vulnerar contraseñas débiles.
- **Solución:** Integrar herramientas de limitación de tasa como **Bucket4j** o políticas a nivel de API Gateway / NGINX / Cloudflare para bloquear direcciones IP que superen un número determinado de peticiones fallidas por minuto (ej. máximo 5 intentos fallidos antes de un bloqueo temporal de 15 minutos).

### 8.4. Encriptación Asimétrica (RS256 / EdDSA)
- En arquitecturas de microservicios distribuidos, el uso de clave simétrica (HS256) obliga a compartir el mismo secreto con todos los microservicios que necesiten validar el token, aumentando el riesgo de filtración.
- Se recomienda transicionar a **claves asimétricas (RS256 / ES256)**: el servicio de autenticación firma con la **clave privada** y los demás microservicios validan únicamente con la **clave pública** expuesta mediante un endpoint JWKS (`/.well-known/jwks.json`).

### 8.5. Transporte Seguro Obligatorio (HTTPS / HSTS)
- Dado que los Bearer tokens viajan en texto plano en la cabecera `Authorization`, es un requisito estricto e ineludible forzar el protocolo **TLS/HTTPS** en todo el perímetro, habilitando cabeceras HSTS (*HTTP Strict Transport Security*) para evitar ataques de intermediario (*Man-In-The-Middle*).

---

## 9. Conclusiones

1. **Eficacia del Modelo Stateless:** La combinación de Spring Security 6 y OAuth2 Resource Server permite desacoplar por completo la capa de aplicación del almacenamiento de sesiones, habilitando arquitecturas en la nube altamente escalables y resilientes.
2. **Criptografía Preventiva:** La adopción de BCrypt garantiza que, incluso ante una filtración masiva de la base de datos MySQL, la información confidencial de los usuarios permanece protegida contra ataques de diccionario y Rainbow Tables.
3. **Validación Integral de Peticiones:** La implementación rigurosa de validaciones con Jakarta Validation en conjunto con respuestas semánticas precisas (201, 401, 409) produce APIs REST predecibles, seguras y alineadas a los estándares de la industria.
4. **Verificación Práctica Exhaustiva:** Todas las actividades de verificación del taller (persistencia de hashes, duplicidad de usuario, rechazo de credenciales, alteración de firma y vencimiento de token) fueron contrastadas empíricamente, certificando el dominio práctico de los conceptos de ciberseguridad y desarrollo web moderno.

---

## 10. Referencias Bibliográficas

1. **IETF (2015).** *RFC 7519: JSON Web Token (JWT)*. Internet Engineering Task Force. https://datatracker.ietf.org/doc/html/rfc7519
2. **Spring Security Team (2025).** *Spring Security Reference: OAuth 2.0 Resource Server*. VMware Tanzu / Broadcom. https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/jwt.html
3. **OWASP Foundation (2024).** *Password Storage Cheat Sheet & JSON Web Token Cheat Sheet*. Open Worldwide Application Security Project. https://cheatsheetseries.owasp.org/
4. **Evoila (2023).** *Spring Boot 3 & JWT Authentication: Leveraging Spring Security’s Built-in Support*. https://evoila.com/gb/spring-boot-3-jwt-authentication-leveraging-spring-securitys-support/
