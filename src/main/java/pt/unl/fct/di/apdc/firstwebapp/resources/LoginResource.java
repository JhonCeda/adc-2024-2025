package pt.unl.fct.di.apdc.firstwebapp.resources;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.logging.Logger;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.NewCookie;
import jakarta.ws.rs.core.Cookie;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.Status;

import pt.unl.fct.di.apdc.firstwebapp.util.LoginData;
import pt.unl.fct.di.apdc.firstwebapp.authentication.SignatureUtils;
import pt.unl.fct.di.apdc.firstwebapp.util.AuthToken;
import pt.unl.fct.di.apdc.firstwebapp.util.UserData;

import com.google.gson.Gson;


@Path("/login")
@Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
public class LoginResource {

	public static final String ADMIN = "Admin";
	public static final String BACKOFFICE = "Backoffice";
	public static final String REGULAR = "Regular";
	private static final String key = "ljshfdjhfkjhasldjfhalkjsdfajdhflakjhdfkjahdfl";
	
	public static Map<String, UserData> users = new HashMap<String, UserData>();
	
	private static final Logger LOG = Logger.getLogger(LoginResource.class.getName());
	private final Gson g = new Gson();
	
	public LoginResource() {
		
	}
	
	@POST
	@Path("/")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response doLogin(LoginData data) {
		LOG.fine("Login attempt by user: " + data.username);
		
		if(!checkPassword(data)) {
			return Response.status(Status.FORBIDDEN).entity("Incorrect username or password.").build();
		}
		
		String id = UUID.randomUUID().toString();
		long currentTime = System.currentTimeMillis();
		String fields = data.username + "." + id + "." + REGULAR + "." + currentTime + "." + 1000*60*60*2;
		
		String signature = SignatureUtils.calculateHMac(key, fields);
		if(signature == null) {
			return Response.status(Status.INTERNAL_SERVER_ERROR).entity("Error while signing token. See logs.").build();
		}
		
		String value = fields + "." + signature;
		NewCookie cookie = new NewCookie("session::apdc", value, "/", null, "comment", 1000*60*60*2, false, true);
		
		return Response.ok().cookie(cookie).build();
	}
	
	private static int convertRole(String role) {
		int result = 0;
		
		switch(role) {
			case BACKOFFICE:
				result = 1;
				break;
			case ADMIN:
				result = 2;
				break;
			case REGULAR:
				result = 0;
				break;
			default:
				result = 0;
				break;
		}
		return result;
	}

	public static boolean checkPermissions(Cookie cookie, String role) {
		if (cookie == null || cookie.getValue() == null) {
			return false;
		}

		String value = cookie.getValue();
		String[] values = value.split("\\.");
	
		String signatureNew = SignatureUtils.calculateHMac(key, values[0]+"."+values[1]+"."+values[2]+"."+values[3]+"."+values[4]);
		String signatureOld = values[5];
					
		if(!signatureNew.equals(signatureOld)) {
			return false;
		}

		int neededRole = convertRole(role);
		int userInSessionRole = convertRole(values[2]);
		
		if(userInSessionRole < neededRole) {
			return false;
		}
		
		if(System.currentTimeMillis() > (Long.valueOf(values[3]) + Long.valueOf(values[4])*1000)) {
			
			return false;
		}
		
			
		return true;
	}

	private static boolean checkPassword(LoginData data)  {
		UserData user = users.get(data.username);
		
		if(user == null || !user.password.equals(data.password)) {
			return false;
		}
		
		return true;
	}

	
	@GET
	@Path("/{username}")
	public Response checkUsernameAvailable(@PathParam("username") String username) {
		UserData user = users.get(username);
		
		return Response.ok().entity(g.toJson(user != null)).build();
	}
	
	@POST
	@Path("/create")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response createUser(UserData data) {
		LOG.fine("Attempting to create user with username: " + data.username);
		
		UserData user = users.get(data.username);
		
		if(user != null) {
			return Response.status(Status.FORBIDDEN).entity("User with username " + data.username + " already exists.").build();
		} 
		
		users.put(data.username, data);
		
		return Response.ok().build();
	}

}
