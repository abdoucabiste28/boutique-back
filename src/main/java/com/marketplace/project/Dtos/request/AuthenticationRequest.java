package com.marketplace.project.Dtos.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AuthenticationRequest {

  public String getEmail() {
		return email;
	}
	public void setEmail(String email) {
		this.email = email;
	}
	public String getPassword() {
		return password;
	}
	public void setPassword(String password) {
		this.password = password;
	}

@Email(message = "L'email doit être valide")
@NotBlank(message = "L'email est obligatoire")
private String email;

@NotBlank(message = "Le mot de passe est obligatoire")
@Size(min = 6, message = "Le mot de passe doit contenir au moins 6 caractères")
    private String password;
}
