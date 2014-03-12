using System.Collections.Generic;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using Microsoft.Owin.Security.Cookies;
using IdentitySample.Models;
using Microsoft.Owin.Security.Facebook;
using Owin;
using System;

namespace IdentitySample
{
    public partial class Startup
    {
        // For more information on configuring authentication, please visit http://go.microsoft.com/fwlink/?LinkId=301864
        public void ConfigureAuth(IAppBuilder app)
        {
            // Configure the db context and user manager to use a single instance per request
            app.CreatePerOwinContext(ApplicationDbContext.Create);
            app.CreatePerOwinContext<ApplicationUserManager>(ApplicationUserManager.Create);

            // Enable the application to use a cookie to store information for the signed in user
            // and to use a cookie to temporarily store information about a user logging in with a third party login provider
            // Configure the sign in cookie
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie,
                LoginPath = new PathString("/Account/Login"),
                Provider = new CookieAuthenticationProvider
                {
                    // Enables the application to validate the security stamp when the user logs in.
                    // This is a security feature which is used when you change a password or add an external login to your account.  
                    OnValidateIdentity = SecurityStampValidator.OnValidateIdentity<ApplicationUserManager, ApplicationUser>(
                        validateInterval: TimeSpan.FromMinutes(30),
                        regenerateIdentity: (manager, user) => user.GenerateUserIdentityAsync(manager))
                }
            });
            app.UseExternalSignInCookie(DefaultAuthenticationTypes.ExternalCookie);

            // Enables the application to temporarily store user information when they are verifying the second factor in the two-factor authentication process.
            app.UseTwoFactorSignInCookie(DefaultAuthenticationTypes.TwoFactorCookie, TimeSpan.FromMinutes(5));

            // Enables the application to remember the second login verification factor such as phone or email.
            // Once you check this option, your second step of verification during the login process will be remembered on the device where you logged in from.
            // This is similar to the RememberMe option when you log in.
            app.UseTwoFactorRememberBrowserCookie(DefaultAuthenticationTypes.TwoFactorRememberBrowserCookie);

            // Uncomment the following lines to enable logging in with third party login providers
            //app.UseMicrosoftAccountAuthentication(
            //    clientId: "",
            //    clientSecret: "");
            //6xdCTGnA9T0wgGdmJKZSQ
            //3976paCklfia31D07I4kTkNdTTWNnKet1pVnrEbAXnA

            //Kieta
            //6xdCTGnA9T0wgGdmJKZSQ
            //3976paCklfia31D07I4kTkNdTTWNnKet1pVnrEbAXnA
            app.UseTwitterAuthentication(
               consumerKey: "6xdCTGnA9T0wgGdmJKZSQ",
               consumerSecret: "3976paCklfia31D07I4kTkNdTTWNnKet1pVnrEbAXnA");


            //app.UseFacebookAuthentication(
            //    appId: "610930642318328",
            //    appSecret: "d86b0cc758b62cc20835a54ce9bf8252");

            //List<string> scope = new List<string>() { "email", "user_about_me", "user_hometown", "friends_about_me", "friends_photos" };

            var x = new FacebookAuthenticationOptions();
            x.Scope.Add("email");
            //x.Scope.Add("friends_about_me");
            //x.Scope.Add("friends_photos");
            x.AppId = "610930642318328";
            x.AppSecret = "d86b0cc758b62cc20835a54ce9bf8252";
            x.Provider = new FacebookAuthenticationProvider()
            {
                OnAuthenticated = async context =>
                {
                    //Get the access token from FB and store it in the database and
                    //use FacebookC# SDK to get more information about the user
                    context.Identity.AddClaim(new System.Security.Claims.Claim("FacebookAccessToken", context.AccessToken));
                }
            };
            x.SignInAsAuthenticationType = DefaultAuthenticationTypes.ExternalCookie;
            app.UseFacebookAuthentication(x);

            app.UseGoogleAuthentication();
        }
    }
}