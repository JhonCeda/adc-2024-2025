package pt.unl.fct.di.apdc.firstwebapp.util;

import java.util.Arrays;
import java.util.List;

public class RegisterData {
	
	// Mandatory fields
	public String email;
  public String username;
  public String name;
  public String phone;
  public String password;
  public String passwordConfirmation;
  public String accountType; // "public" or "private"

	//Optional fields
	public String citizenCardNumber;
  public String role; // "ENDUSER", "BACKOFFICE", "ADMIN", "PARTNER"
  public String nif;
  public String employer;
  public String jobTitle;
  public String address;
  public String employerNif;
  public String accountStatus; // "ACTIVATED", "SUSPENDED", "DEACTIVATED"
	
	// Allowed values for validation
	private static final List<String> ALLOWED_ROLES = 
	Arrays.asList("ENDUSER", "BACKOFFICE", "ADMIN", "PARTNER");
	private static final List<String> ALLOWED_STATUSES = 
	Arrays.asList("ACTIVATED", "SUSPENDED", "DEACTIVATED");

	public RegisterData() {
		
	}
	
	public RegisterData(String email, String username, String name, String phone,
                       String password, String accountType) {
    this.email = email;
    this.username = username;
    this.name = name;
    this.phone = phone;
    this.password = password;
    this.accountType = accountType;
    this.accountStatus = "ACTIVATED"; 
  }
	
	public String getRole() {
		return role;
}

	public void setRole(String role) {
		if (role != null && !ALLOWED_ROLES.contains(role)) {
				throw new IllegalArgumentException(
						"Invalid role. Must be one of: " + ALLOWED_ROLES);
		}
		this.role = role;
	}

	public String getAccountStatus() {
		return accountStatus;
	}

	public void setAccountStatus(String accountStatus) {
		if (accountStatus != null && !ALLOWED_STATUSES.contains(accountStatus)) {
			throw new IllegalArgumentException(
				"Invalid status. Must be one of: " + ALLOWED_STATUSES);
		}
		this.accountStatus = accountStatus;
	}

	private boolean nonEmptyOrBlankField(String field) {
		return field != null && !field.isBlank();
	}
	
	public boolean validRegistration() {
		return nonEmptyOrBlankField(username) &&
				 isValidPassword() &&
			   nonEmptyOrBlankField(email) &&
			   nonEmptyOrBlankField(name) &&
			   email.contains("@") &&
				nonEmptyOrBlankField(accountType);
	}

	private boolean isValidPassword(){
		return nonEmptyOrBlankField(password) &&
				password.matches(".*[a-z].*") &&
				password.matches(".*[A-Z].*") &&
				password.matches(".*[0-9].*") &&
				password.matches(".*[@#$%^&+=!].*");
	}
}