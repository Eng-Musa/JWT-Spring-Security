package engmusa.Service;

import engmusa.DTOs.SignupRequest;
import engmusa.DTOs.UserDTO;

public interface AuthService {

    UserDTO createUser(SignupRequest signupRequest);
}
