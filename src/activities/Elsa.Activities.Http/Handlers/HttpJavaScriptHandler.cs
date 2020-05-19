using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Elsa.Activities.Http.Models;
using Elsa.Activities.Http.Services;
using Elsa.Scripting.JavaScript.Messages;
using Elsa.Services.Models;
using MediatR;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;

namespace Elsa.Activities.Http.Handlers
{
    public class HttpJavaScriptHandler : INotificationHandler<EvaluatingJavaScriptExpression>
    {
        private readonly ITokenService tokenService;
        private readonly IAbsoluteUrlProvider absoluteUrlProvider;
        private readonly IHttpContextAccessor httpContextAccessor;

        public HttpJavaScriptHandler(
            ITokenService tokenService,
            IAbsoluteUrlProvider absoluteUrlProvider,
            IHttpContextAccessor httpContextAccessor)
        {
            this.tokenService = tokenService;
            this.absoluteUrlProvider = absoluteUrlProvider;
            this.httpContextAccessor = httpContextAccessor;
        }

        public Task Handle(EvaluatingJavaScriptExpression notification, CancellationToken cancellationToken)
        {
            var engine = notification.Engine;
            var workflowExecutionContext = notification.WorkflowExecutionContext;

            engine.SetValue(
                "queryString",
                (Func<string, string>)(key => httpContextAccessor.HttpContext.Request.Query[key].ToString())
            );
            engine.SetValue(
                "absoluteUrl",
                (Func<string, string>)(url => absoluteUrlProvider.ToAbsoluteUrl(url).ToString())
            );
            engine.SetValue(
                "signalUrl",
                (Func<string, string>)(signal => GenerateUrl(signal, workflowExecutionContext))
            );

            return Task.CompletedTask;
        }

        private string GenerateUrl(string signal, WorkflowExecutionContext workflowExecutionContext)
        {
            var workflowInstanceId = workflowExecutionContext.Workflow.Id;
            var payload = new Signal(signal, workflowInstanceId);
            var token = tokenService.CreateToken(payload);
            var url = $"/workflows/signal?token={token}";

            return absoluteUrlProvider.ToAbsoluteUrl(url).ToString();
        }


        public static ClaimsPrincipal ValidateToken(string jwtToken)
        {
            IdentityModelEventSource.ShowPII = true;

            SecurityToken validatedToken;
            TokenValidationParameters validationParameters = new TokenValidationParameters();

            validationParameters.ValidateLifetime = true;

            validationParameters.ValidAudience = "www.rafaelacosta.net/api/miwebapi"; // _audience.ToLower();
            validationParameters.ValidIssuer = "www.rafaelacosta.net";//_issuer.ToLower();
            validationParameters.IssuerSigningKey = new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(Encoding.UTF8.GetBytes("OLAh6Yh5KwNFvOqgltw7"));

            ClaimsPrincipal principal = new JwtSecurityTokenHandler().ValidateToken(jwtToken, validationParameters, out validatedToken);


            return principal;
        }

    }
}