﻿using System;
using System.Configuration;
using System.IdentityModel.Claims;
using System.Threading.Tasks;
using System.Web;
using Microsoft.Identity.Client;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.Notifications;
using Microsoft.Owin.Security.OpenIdConnect;
using OAuth2_experiment.TokenStorage;
using Owin;

[assembly: OwinStartup(typeof(OAuth2_experiment.App_Start.Startup))]

namespace OAuth2_experiment.App_Start
{
    public class Startup
    {
        public static string appId = ConfigurationManager.AppSettings["ida:AppId"];
        public static string appPassword = ConfigurationManager.AppSettings["ida:AppPassword"];
        public static string redirectUri = ConfigurationManager.AppSettings["ida:RedirectUri"];
        public static string[] scopes = ConfigurationManager.AppSettings["ida:AppScopes"].Replace(' ', ',').Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);

        public void Configuration(IAppBuilder app)
        {
            // For more information on how to configure your application, visit https://go.microsoft.com/fwlink/?LinkID=316888
            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);

            app.UseCookieAuthentication(new CookieAuthenticationOptions());

            app.UseOpenIdConnectAuthentication(
                new OpenIdConnectAuthenticationOptions
                {
                    ClientId = appId,
                    Authority = "https://login.microsoftonline.com/common/v2.0",
                    Scope = "openid offline_access profile email " + string.Join(" ", scopes),
                    RedirectUri = redirectUri,
                    PostLogoutRedirectUri = "/",
                    TokenValidationParameters = new TokenValidationParameters
                    {
                        // For demo purposes only, see below
                        ValidateIssuer = false

                        // In a real multitenant app, you would add logic to determine whether the
                        // issuer was from an authorized tenant
                        //ValidateIssuer = true,
                        //IssuerValidator = (issuer, token, tvp) =>
                        //{
                        //  if (MyCustomTenantValidation(issuer))
                        //  {
                        //    return issuer;
                        //  }
                        //  else
                        //  {
                        //    throw new SecurityTokenInvalidIssuerException("Invalid issuer");
                        //  }
                        //}
                    },
                    Notifications = new OpenIdConnectAuthenticationNotifications
                    {
                        AuthenticationFailed = OnAuthenticationFailed,
                        AuthorizationCodeReceived = OnAuthorizationCodeReceived
                    }
                }
            );
        }

        private Task OnAuthenticationFailed(AuthenticationFailedNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions> notification)
        {
            notification.HandleResponse();
            string redirect = "/Home/Error?message=" + notification.Exception.Message;
            if (notification.ProtocolMessage != null && !string.IsNullOrEmpty(notification.ProtocolMessage.ErrorDescription))
            {
                redirect += "&debug=" + notification.ProtocolMessage.ErrorDescription;
            }
            notification.Response.Redirect(redirect);
            return Task.FromResult(0);
        }

        private async Task OnAuthorizationCodeReceived(AuthorizationCodeReceivedNotification notification)
        {
            string signedInUserId = notification.AuthenticationTicket.Identity.FindFirst(ClaimTypes.NameIdentifier).Value;
            SessionTokenCache tokenCache = new SessionTokenCache(
                signedInUserId,
                notification.OwinContext.Environment["System.Web.HttpContextBase"] as HttpContextBase);        
            ConfidentialClientApplication cca = new ConfidentialClientApplication(
                appId, 
                redirectUri,
                new ClientCredential(appPassword),
                tokenCache.GetMsalCacheInstance(),
                null);

            try
            {
                var result = await cca.AcquireTokenByAuthorizationCodeAsync(notification.Code, scopes);
            }
            catch (MsalException ex)
            {
                string message, debug;
                message = "AcquireTokenByAuthorizationCodeAsync threw an exception";
                debug = ex.Message;
                notification.HandleResponse();
                notification.Response.Redirect("/Home/Error?message=" + message + "&debug=" + debug);
            }            
        }
    }
}
