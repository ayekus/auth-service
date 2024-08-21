package com.aekus.auth_service.auth;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
public class AuthenticationRequest {

    @Email(message = "Email is not formatted properly")
    @NotEmpty(message = "Email field is empty")
    @NotBlank(message = "Email field is empty")
    private String email;

    @NotEmpty(message = "Password field is empty")
    @NotBlank(message = "Password field is empty")
    @Size(min = 8, message = "Password should be more than 8 characters long")
    private String password;

}
