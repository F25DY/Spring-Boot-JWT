package com.jwt.artifactjwt;

import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.jwt.artifactjwt.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import tools.jackson.databind.ObjectMapper;

@SpringBootTest
@AutoConfigureMockMvc
class ArtifactjwtApplicationTests {

	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private ObjectMapper objectMapper;

	@Autowired
	private UserRepository userRepository;

	@Test
	void contextLoads() {
	}

	@Test
	void registrationAuthenticationAndSecuredEndpointWork() throws Exception {
		userRepository.deleteAll();

		mockMvc.perform(post("/api/auth/register")
				.contentType(APPLICATION_JSON)
				.content("""
						{"username":"student1","password":"SecurePassword123!"}
						"""))
				.andExpect(status().isCreated())
				.andExpect(jsonPath("$.message").value("Usuario creado exitosamente"));

		MvcResult authentication = mockMvc.perform(post("/api/auth/token")
				.contentType(APPLICATION_JSON)
				.content("""
						{"username":"student1","password":"SecurePassword123!"}
						"""))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.token_type").value("Bearer"))
				.andReturn();
		String token = objectMapper.readTree(authentication.getResponse().getContentAsString())
				.get("access_token")
				.asText();

		mockMvc.perform(get("/api/secured"))
				.andExpect(status().isUnauthorized());

		mockMvc.perform(get("/api/secured")
				.header("Authorization", "Bearer " + token))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.username").value("student1"));
	}

	@Test
	void duplicateRegistrationReturnsConflict() throws Exception {
		userRepository.deleteAll();
		String request = """
				{"username":"student1","password":"SecurePassword123!"}
				""";

		mockMvc.perform(post("/api/auth/register")
				.contentType(APPLICATION_JSON)
				.content(request))
				.andExpect(status().isCreated());

		mockMvc.perform(post("/api/auth/register")
				.contentType(APPLICATION_JSON)
				.content(request))
				.andExpect(status().isConflict())
				.andExpect(jsonPath("$.error").value("Usuario Existente"));
	}
}
