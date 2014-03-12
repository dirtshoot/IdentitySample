using System.Collections.Generic;
using System.Data.Entity;
using BidAmiModel;
using IdentitySample.Models;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;
using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;

namespace IdentitySample.Controllers
{
    [Authorize]
    public class AccountController : Controller
    {
        public AccountController()
        {
        }

        public AccountController(ApplicationUserManager userManager)
        {
            UserManager = userManager;
        }

        private ApplicationUserManager _userManager;
        public ApplicationUserManager UserManager
        {
            get
            {
                return _userManager ?? HttpContext.GetOwinContext().GetUserManager<ApplicationUserManager>();
            }
            private set
            {
                _userManager = value;
            }
        }

        //
        // GET: /Account/Login
        [AllowAnonymous]
        public ActionResult Login(string returnUrl)
        {
            ViewBag.ReturnUrl = returnUrl;
            return View();
        }

        //
        // POST: /Account/Login
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Login(LoginViewModel model, string returnUrl)
        {
            if (ModelState.IsValid)
            {
                var user = await UserManager.FindAsync(model.UserName, model.Password);
                if (user != null)
                {
                    return await LoginCommon(user, model.RememberMe, returnUrl);
                }
                ModelState.AddModelError("", "Invalid username or password.");
            }

            // If we got this far, something failed, redisplay form
            return View(model);
        }

        //
        // GET: /Account/VerifyCode
        [AllowAnonymous]
        public async Task<ActionResult> VerifyCode(string provider, string returnUrl)
        {
            // Require that the user has already logged in via username/password or external login
            string userId = await GetTwoFactorUserIdAsync();
            if (userId == null)
            {
                return View("Error");
            }

            var user = await UserManager.FindByIdAsync(userId);
            if (user != null)
            {
                // To exercise the flow without actually sending codes, uncomment the following line
                //ViewBag.Status = "For DEMO purposes the current " + provider + " code is: " + await UserManager.GenerateTwoFactorTokenAsync(user.Id, provider);
            }
            return View(new VerifyCodeViewModel { Provider = provider, ReturnUrl = returnUrl });
        }

        //
        // POST: /Account/VerifyCode
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> VerifyCode(VerifyCodeViewModel model)
        {
            if (ModelState.IsValid)
            {
                string userId = await GetTwoFactorUserIdAsync();
                if (userId == null)
                {
                    return View("Error");
                }

                var user = await UserManager.FindByIdAsync(userId);
                if (await UserManager.VerifyTwoFactorTokenAsync(user.Id, model.Provider, model.Code))
                {
                    await SignInAsync(user, model.RememberBrowser, model.RememberBrowser);
                    return RedirectToLocal(model.ReturnUrl);
                }
                ModelState.AddModelError("", "Invalid code");
            }
            // If we got this far, something failed, redisplay form
            return View(model);
        }

        //
        // GET: /Account/Register
        [AllowAnonymous]
        public ActionResult Register()
        {
            return View();
        }

        //
        // POST: /Account/Register
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Register(RegisterViewModel model)
        {
            if (!model.Terms)
            {
                ModelState.AddModelError("Terms", "You forgot to click accept");
            }

            if (ModelState.IsValid)
            {
                var user = new ApplicationUser { FirstName = model.FirstName, LastName = model.LastName, UserName = model.UserName, Email = model.Email, Reference = model.Reference, Created = System.DateTime.Now };
                IdentityResult result = await UserManager.CreateAsync(user, model.Password);
                if (result.Succeeded)
                {
                    var profile = new Profile { UserId = user.Id, Newsletter = model.NewsLetter, Seller = model.Seller, Created = System.DateTime.Now };
                    if (CreateProfile(profile))
                    {
                        string code = await UserManager.GetEmailConfirmationTokenAsync(user.Id);
                        var confirmemail = new ConfirmEmail { FirstName = model.FirstName, LastName = model.LastName, Seller = model.Seller, To = model.Email, UserName = model.UserName, Id = user.Id, Code = code };
                        try
                        {
                            confirmemail.Send();
                            ViewBag.ErrorMessage = "";
                        }
                        catch
                        {
                            ViewBag.ErrorMessage = "Unable To Send Enail";
                        }

                        return View("ConfirmEmailSent", confirmemail);
                    }

                    result = await UserManager.DeleteAsync(user);
                    if (!result.Succeeded)
                    {
                        ModelState.AddModelError("", result.Errors.First());
                    }
                }
                AddErrors(result);
            }
            var m = ModelState;
            // If we got this far, something failed, redisplay form
            return View(model);
        }

        //
        // GET: /Account/ConfirmEmail
        [AllowAnonymous]
        public async Task<ActionResult> ConfirmEmail(string userId, string code)
        {
            if (userId == null || code == null)
            {
                return View("Error");
            }

            IdentityResult result = await UserManager.ConfirmEmailAsync(userId, code);
            if (result.Succeeded)
            {
                return View("ConfirmEmail");
            }
            AddErrors(result);
            return View();
        }

        //
        // GET: /Account/ConfirmSeller
        [AllowAnonymous]
        public async Task<ActionResult> ConfirmSeller(string userId, string code)
        {
            if (userId == null || code == null)
            {
                return View("Error");
            }
            var user = await UserManager.FindByIdAsync(userId);
            if (user != null)
            {
                var id = GetProfileId(userId);
                if (id > 0)
                {
                    var paymentmethods = GetPaymentMethods();
                    var model = new ConfirmSellerViewModel { UserId = userId, Code = code, ProfileId = id, PaymentMethods = paymentmethods };
                    return View(model);
                }
            }
            return RedirectToAction("Index", "Home");
        }

        //
        // GET: /Account/ForgotPassword
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ConfirmSeller(ConfirmSellerViewModel model)
        {
            model.PaymentMethods = GetPaymentMethods();

            if (ModelState.IsValid)
            {
                using (var db = new BidAmiEntities())
                {
                    var address = new ProfileAddress { ProfileId = model.ProfileId, BusinessName = model.BusinessName, Address1 = model.Address1, Address2 = model.Address2, Country = model.Country, City = model.City, StateRegion = model.StateRegion, ZipPostal = model.ZipPostal };
                    var phone = new ProfilePhone { ProfileId = model.ProfileId, PhoneNo = model.PhoneNo };

                    db.ProfileAddresses.Add(address);
                    db.ProfilePhones.Add(phone);
                    try
                    {
                        await db.SaveChangesAsync();

                        var profile = db.Profiles.Find(model.ProfileId);
                        if (profile != null)
                        {
                            profile.AddressId = address.Id;
                            profile.PhoneId = phone.Id;
                            profile.PaymentMethod = model.PaymentMethod;

                            db.Entry(profile).State = EntityState.Modified;
                            try
                            {
                                await db.SaveChangesAsync();

                                IdentityResult result = await UserManager.ConfirmEmailAsync(model.UserId, model.Code);
                                if (result.Succeeded)
                                {
                                    return View("ConfirmSellerProfile", model);
                                }
                                AddErrors(result);
                            }
                            catch (Exception ex)
                            {
                                ModelState.AddModelError("", "Unable to create a profile " + ex.ToString());
                            }
                        }
                        else
                        {
                            ModelState.AddModelError("", "Unable to find profile " + model.ProfileId);
                        }
                    }
                    catch (Exception ex)
                    {
                        ModelState.AddModelError("", "Unable to create a profile " + ex.ToString());
                    }
                }
            }
            return View(model);
        }

        //
        // GET: /Account/SendConfirmEmail
        [AllowAnonymous]
        public ActionResult SendConfirmEmail()
        {
            ViewBag.ErrorMessage = "";
            return View();
        }

        //
        // GET: /Account/ForgotPassword
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> SendConfirmEmail(SendConfirmEmail model)
        {
            if (ModelState.IsValid)
            {
                var user = await UserManager.FindByNameAsync(model.UserName);
                if (user != null)
                {
                    if (await UserManager.IsEmailConfirmedAsync(user.Id))
                    {
                        return View("AlreadyConfirmed", model);
                    }
                    string code = await UserManager.GetEmailConfirmationTokenAsync(user.Id);
                    //var callbackUrl = Url.Action("ConfirmEmail", "Account", new { userId = user.Id, code = code }, protocol: Request.Url.Scheme);
                    //await UserManager.SendEmailAsync(user.Id, "Confirm your account", "Please confirm your account by clicking this link: <a href=\"" + callbackUrl + "\">link</a>");
                    var confirmemail = new ConfirmEmail { To = user.Email, UserName = user.UserName, Id = user.Id, Code = code };
                    try
                    {
                        confirmemail.Send();
                        ViewBag.ErrorMessage = "";
                    }
                    catch
                    {
                        ViewBag.ErrorMessage = "Unable To Send Enail";
                    }

                    return View("ConfirmEmailSent", confirmemail);
                }
                ModelState.AddModelError("", "Unable to find user " + model.UserName);
            }

            return View("SendConfirmEmail");
        }

        //
        // GET: /Account/ForgotPassword
        [AllowAnonymous]
        public ActionResult ForgotPassword()
        {
            return View();
        }

        //
        // POST: /Account/ForgotPassword
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await UserManager.FindByNameAsync(model.UserName);
                if (user == null || !(await UserManager.IsEmailConfirmedAsync(user.Id)))
                {
                    ModelState.AddModelError("", "User " + model.UserName + " either does not exist or is not confirmed.");
                    return View();
                }

                string code = await UserManager.GetPasswordResetTokenAsync(user.Id);
                //var callbackUrl = Url.Action("ResetPassword", "Account", new { userId = user.Id, code = code }, protocol: Request.Url.Scheme);
                //await UserManager.SendEmailAsync(user.Id, "Reset Password", "Please reset your password by clicking here: <a href=\"" + callbackUrl + "\">link</a>");
                //ViewBag.Link = callbackUrl;
                var forgotpasswordemail = new ForgotPasswordEmail { To = user.Email, UserName = model.UserName, Id = user.Id, Code = code };
                try
                {
                    forgotpasswordemail.Send();
                    ViewBag.ErrorMessage = "";
                }
                catch
                {
                    ViewBag.ErrorMessage = "Unable To Send Enail";
                }
                return View("ForgotPasswordEmailSent", forgotpasswordemail);
            }

            // If we got this far, something failed, redisplay form
            return View(model);
        }

        //
        // GET: /Account/ForgotPasswordConfirmation
        [AllowAnonymous]
        public ActionResult ForgotPasswordConfirmation()
        {
            return View();
        }

        //
        // GET: /Account/ResetPassword
        [AllowAnonymous]
        public ActionResult ResetPassword(string code)
        {
            if (code == null)
            {
                return View("Error");
            }
            return View();
        }

        //
        // POST: /Account/ResetPassword
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await UserManager.FindByNameAsync(model.UserName);
                if (user == null)
                {
                    ModelState.AddModelError("", "Unable to find user " + model.UserName);
                    return View();
                }
                IdentityResult result = await UserManager.ResetPasswordAsync(user.Id, model.Code, model.Password);
                if (result.Succeeded)
                {
                    return RedirectToAction("ResetPasswordConfirmation", "Account");
                }
                AddErrors(result);
                return View();
            }

            // If we got this far, something failed, redisplay form
            return View(model);
        }

        //
        // GET: /Account/ResetPasswordConfirmation
        [AllowAnonymous]
        public ActionResult ResetPasswordConfirmation()
        {
            return View();
        }

        //
        // POST: /Account/ExternalLogin
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult ExternalLogin(string provider, string returnUrl)
        {
            // Request a redirect to the external login provider
            return new ChallengeResult(provider, Url.Action("ExternalLoginCallback", "Account", new { ReturnUrl = returnUrl }));
        }

        //
        // GET: /Account/SendCode
        [AllowAnonymous]
        public async Task<ActionResult> SendCode(string returnUrl)
        {
            string userId = await GetTwoFactorUserIdAsync();
            if (userId == null)
            {
                return View("Error");
            }
            var userFactors = await UserManager.GetValidTwoFactorProvidersAsync(userId);
            var factorOptions = userFactors.Select(purpose => new SelectListItem { Text = purpose, Value = purpose }).ToList();
            return View(new SendCodeViewModel { Providers = factorOptions, ReturnUrl = returnUrl });
        }

        private async Task<string> GetTwoFactorUserIdAsync()
        {
            var result = await AuthenticationManager.AuthenticateAsync(DefaultAuthenticationTypes.TwoFactorCookie);
            if (result != null && result.Identity != null && !String.IsNullOrEmpty(result.Identity.GetUserId()))
            {
                return result.Identity.GetUserId();
            }
            return null;
        }

        //
        // POST: /Account/SendCode
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> SendCode(SendCodeViewModel model)
        {
            // Generate the token and send it
            if (ModelState.IsValid)
            {
                string userId = await GetTwoFactorUserIdAsync();
                if (userId == null)
                {
                    return View("Error");
                }

                // See IdentityConfig.cs to plug in Email/SMS services to actually send the code
                await UserManager.GenerateTwoFactorTokenAsync(userId, model.SelectedProvider);
                return RedirectToAction("VerifyCode", new { Provider = model.SelectedProvider, ReturnUrl = model.ReturnUrl });
            }
            return View();
        }

        private async Task<ActionResult> LoginCommon(ApplicationUser user, bool isPersistent, string returnUrl = "")
        {
            // Do two factor authentication if configured
            bool requireTwoFactor = await UserManager.GetTwoFactorEnabledAsync(user.Id);
            if (requireTwoFactor && !await AuthenticationManager.TwoFactorBrowserRememberedAsync(user.Id))
            {
                TwoFactorPartialSignIn(user);
                return RedirectToAction("SendCode", new { ReturnUrl = returnUrl });
            }
            await SignInAsync(user, isPersistent: isPersistent, rememberBrowser: false);

            SetUserSessionVars(user);

            return RedirectToLocal(returnUrl);
        }

        //
        // GET: /Account/ExternalLoginCallback
        [AllowAnonymous]
        public async Task<ActionResult> ExternalLoginCallback(string returnUrl)
        {
            var loginInfo = await AuthenticationManager.GetExternalLoginInfoAsync();
            if (loginInfo == null)
            {
                return RedirectToAction("Login");
            }

            // Get Email
            //var externalIdentity = HttpContext.GetOwinContext().Authentication.GetExternalIdentityAsync(DefaultAuthenticationTypes.ExternalCookie);
            //var emailClaim = externalIdentity.Result.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Email);
            //var email = emailClaim.Value;

            // Sign in the user with this external login provider if the user already has a login
            var user = await UserManager.FindAsync(loginInfo.Login);
            if (user != null)
            {
                return await LoginCommon(user, isPersistent: false, returnUrl: returnUrl);
            }
            // If the user does not have an account, then prompt the user to create an account
            ViewBag.ReturnUrl = returnUrl;
            ViewBag.LoginProvider = loginInfo.Login.LoginProvider;
            return View("ExternalLoginConfirmation", new ExternalLoginConfirmationViewModel { UserName = loginInfo.DefaultUserName, Email = loginInfo.Email });
        }

        //
        // POST: /Account/ExternalLoginConfirmation
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ExternalLoginConfirmation(ExternalLoginConfirmationViewModel model, string returnUrl)
        {
            if (User.Identity.IsAuthenticated)
            {
                return RedirectToAction("Index", "Manage");
            }
            if (!model.Terms)
            {
                ModelState.AddModelError("Terms", "You forgot to click accept");
            }

            if (ModelState.IsValid)
            {
                // Get the information about the user from the external login provider
                var info = await AuthenticationManager.GetExternalLoginInfoAsync();
                if (info == null)
                {
                    return View("ExternalLoginFailure");
                }
                var user = new ApplicationUser { FirstName = model.FirstName, LastName = model.LastName, UserName = model.UserName, Email = model.Email, Reference = model.Reference, Created = System.DateTime.Now };
                IdentityResult result = await UserManager.CreateAsync(user);
                if (result.Succeeded)
                {
                    var profile = new Profile { UserId = user.Id, Newsletter = model.NewsLetter, Seller = model.Seller, Created = System.DateTime.Now };

                    if (CreateProfile(profile))
                    {
                        result = await UserManager.AddLoginAsync(user.Id, info.Login);

                        if (result.Succeeded)
                        {
                            string code = await UserManager.GetEmailConfirmationTokenAsync(user.Id);
                            var confirmemail = new ConfirmEmail { FirstName = model.FirstName, LastName = model.LastName, Seller = model.Seller, To = model.Email, UserName = model.UserName, Id = user.Id, Code = code };
                            try
                            {
                                confirmemail.Send();
                                ViewBag.ErrorMessage = "";
                            }
                            catch
                            {
                                ViewBag.ErrorMessage = "Unable To Send Enail";
                            }

                            return View("ConfirmEmailSent", confirmemail);
                        }

                        result = await UserManager.DeleteAsync(user);
                        if (!result.Succeeded)
                        {
                            ModelState.AddModelError("", result.Errors.First());
                        }
                    }
                    //if (result.Succeeded)
                    //{
                    //    await SignInAsync(user, isPersistent: false, rememberBrowser: false);
                    //    return RedirectToLocal(returnUrl);
                    //}
                }
                AddErrors(result);
            }

            ViewBag.ReturnUrl = returnUrl;
            return View(model);
        }

        //
        // POST: /Account/LogOff
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult LogOff()
        {
            AuthenticationManager.SignOut();
            SetUserSessionVars(new ApplicationUser { Id = "", UserName = "", Email = "" });
            return RedirectToAction("Index", "Home");
        }

        //
        // GET: /Account/ExternalLoginFailure
        [AllowAnonymous]
        public ActionResult ExternalLoginFailure()
        {
            return View();
        }

        private int GetProfileId(string id)
        {
            using (var db = new BidAmiEntities())
            {
                var profile = db.Profiles.Where(c => c.UserId == id).FirstOrDefault();
                if (profile != null)
                {
                    return profile.Id;
                }
                return 0;
            }
        }

        private List<PaymnetMethod> GetPaymentMethods()
        {
            using (var db = new BidAmiEntities())
            {
                return db.PaymnetMethods.ToList();
            }
        }

        private bool CreateProfile(Profile profile)
        {
            using (var db = new BidAmiEntities())
            {
                db.Profiles.Add(profile);
                try
                {
                    db.SaveChanges();
                    return true;
                }
                catch (Exception ex)
                {
                    ModelState.AddModelError("", "Unable to create a profile " + ex.ToString());
                    return false;
                }
            }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing && _userManager != null)
            {
                _userManager.Dispose();
                _userManager = null;
            }
            base.Dispose(disposing);
        }

        #region Helpers

        private void SetUserSessionVars(ApplicationUser user)
        {
            Session["UserName"] = user.UserName;
            Session["UserId"] = user.Id;
            Session["UserEmail"] = user.Email;
        }

        // Used for XSRF protection when adding external logins
        private const string XsrfKey = "XsrfId";

        private IAuthenticationManager AuthenticationManager
        {
            get
            {
                return HttpContext.GetOwinContext().Authentication;
            }
        }

        private void TwoFactorPartialSignIn(ApplicationUser user)
        {
            ClaimsIdentity identity = new ClaimsIdentity(DefaultAuthenticationTypes.TwoFactorCookie);
            identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, user.Id));
            AuthenticationManager.SignIn(identity);
        }

        private async Task SignInAsync(ApplicationUser user, bool isPersistent, bool rememberBrowser)
        {
            // Clear any partial cookies from external or two factor partial sign ins
            AuthenticationManager.SignOut(DefaultAuthenticationTypes.ExternalCookie, DefaultAuthenticationTypes.TwoFactorCookie);
            var userIdentity = await user.GenerateUserIdentityAsync(UserManager);
            if (rememberBrowser)
            {
                var rememberBrowserIdentity = AuthenticationManager.CreateTwoFactorRememberBrowserIdentity(user.Id);
                AuthenticationManager.SignIn(new AuthenticationProperties { IsPersistent = isPersistent }, userIdentity, rememberBrowserIdentity);
            }
            else
            {
                AuthenticationManager.SignIn(new AuthenticationProperties { IsPersistent = isPersistent }, userIdentity);
            }
        }

        private void AddErrors(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError("", error);
            }
        }

        private ActionResult RedirectToLocal(string returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            return RedirectToAction("Index", "Home");
        }

        internal class ChallengeResult : HttpUnauthorizedResult
        {
            public ChallengeResult(string provider, string redirectUri)
                : this(provider, redirectUri, null)
            {
            }

            public ChallengeResult(string provider, string redirectUri, string userId)
            {
                LoginProvider = provider;
                RedirectUri = redirectUri;
                UserId = userId;
            }

            public string LoginProvider { get; set; }
            public string RedirectUri { get; set; }
            public string UserId { get; set; }

            public override void ExecuteResult(ControllerContext context)
            {
                var properties = new AuthenticationProperties { RedirectUri = RedirectUri };
                if (UserId != null)
                {
                    properties.Dictionary[XsrfKey] = UserId;
                }
                context.HttpContext.GetOwinContext().Authentication.Challenge(properties, LoginProvider);
            }
        }
        #endregion
    }
}