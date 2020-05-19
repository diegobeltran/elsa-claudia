using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Elsa.Dashboard.Web.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Configuration;
using System.Text;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace Elsa.Dashboard.Web.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly IConfiguration configuration;

        public HomeController(ILogger<HomeController> logger, IConfiguration _configuration)
        {
            _logger = logger;
            configuration = _configuration;
        }

        //[Authorize(AuthenticationSchemes = $"{JwtBearerDefaults.AuthenticationScheme}")]
        public IActionResult Index()
        {
            return View();
        }


        //[Authorize(AuthenticationSchemes = AuthorizationConsts.BearerOrCookiesAuthenticationScheme, Policy = AuthorizationConsts.ReadPolicy)]
        public IActionResult Privacy()
        {
            return View();
        }

        [AllowAnonymous]
        [HttpGet]
        public ActionResult Token(string jsonString)
        {
            //[ "admin", "editor", "contributor" ]
            // localStorage.setItem("token", token);
            //localStorage.removeItem("token")
            //$.ajaxSetup({
            //    beforeSend: function(xhr) {
            //        if (localStorage.getItem("token") !== null)
            //        {
            //            xhr.setRequestHeader('Authorization', 'Bearer ' + localStorage.getItem("token"));
            //        }
            //    }
            //});


            try
            { 
            var a = JsonSerializer.Deserialize<string[]>(jsonString);

            var toke = GenerarTokenJWT(a);

            return Ok(toke);
            }
            catch(Exception ex)
            {
              return   NotFound(ex);

            }


        }




        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }



        private string GenerarTokenJWT(string[] usuarioInfo)
        {
            // CREAMOS EL HEADER //
            var _symmetricSecurityKey = new SymmetricSecurityKey(
                    Encoding.UTF8.GetBytes(configuration["JWT:ClaveSecreta"])
                );
            var _signingCredentials = new SigningCredentials(
                    _symmetricSecurityKey, SecurityAlgorithms.HmacSha256
                );
            var _Header = new JwtHeader(_signingCredentials);

            // CREAMOS LOS CLAIMS //
            var _Claims = new[] {
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                //new Claim(JwtRegisteredClaimNames.NameId, usuarioInfo.Id.ToString()),
                new Claim("nombre", usuarioInfo[0]),
                new Claim("apellidos", usuarioInfo[1]),
                new Claim(JwtRegisteredClaimNames.Email, usuarioInfo[2]),
                //new Claim(ClaimTypes.Role, usuarioInfo.Rol)
            };

            // CREAMOS EL PAYLOAD //
            var _Payload = new JwtPayload(
                    issuer: configuration["JWT:Issuer"],
                    audience: configuration["JWT:Audience"],
                    claims: _Claims,
                    notBefore: DateTime.UtcNow,
                    // Exipra a la 24 horas.
                    expires: DateTime.UtcNow.AddMinutes(2)
                );

            // GENERAMOS EL TOKEN //
            var _Token = new JwtSecurityToken(
                    _Header,
                    _Payload
                );

            return new JwtSecurityTokenHandler().WriteToken(_Token);
        }
    }
}
