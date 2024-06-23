using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;
using Task1_1.Services;
using Task1_1.Models;

namespace Task1_1.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly AuthService _authService;

        public AuthController(AuthService authService)
        {
            _authService = authService;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterRequest request)
        {
            var result = await _authService.RegisterUser(request.Username, request.Password);
            if (!result)
            {
                return BadRequest("User already exists.");
            }
            return Ok("User registered successfully.");
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            var (accessToken, refreshToken) = await _authService.LoginUser(request.Username, request.Password);
            if (accessToken == null)
            {
                return Unauthorized("Invalid username or password.");
            }
            return Ok(new { AccessToken = accessToken, RefreshToken = refreshToken });
        }

        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh([FromBody] TokenRequest tokenRequest)
        {
            var (newAccessToken, newRefreshToken) = await _authService.RefreshToken(tokenRequest.AccessToken, tokenRequest.RefreshToken);
            if (newAccessToken == null)
            {
                return Unauthorized("Invalid refresh token.");
            }
            return Ok(new { AccessToken = newAccessToken, RefreshToken = newRefreshToken });
        }
    }

    public record RegisterRequest(string Username, string Password);
    public record LoginRequest(string Username, string Password);
    public record TokenRequest(string AccessToken, string RefreshToken);
}
