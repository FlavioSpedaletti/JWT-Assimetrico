using JWT.Api.Services;
using Microsoft.AspNetCore.Mvc;

namespace JWT.Api.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthenticateController : ControllerBase
    {
        private readonly IJwtService _jwtService;

        public AuthenticateController(IJwtService jwtService)
        {
            _jwtService = jwtService ?? throw new ArgumentNullException(nameof(jwtService));
        }

        [HttpPost("generate-token")]
        public IActionResult GenerateToken(GenerateTokenRequestDto request, CancellationToken cancellationToken)
        {
            if (request.Login == "string" && request.Senha == "string")
            {
                return Ok(_jwtService.GenerateToken());
            }

            return BadRequest();
        }

        [HttpPost("validate-token")]
        public IActionResult ValidateToken(string token, CancellationToken cancellationToken)
        {
            return Ok(_jwtService.ValidateToken(token));
        }

    }

    public class GenerateTokenRequestDto
    {
        public string Login { get; set; }
        public string Senha { get; set; }
    }
}