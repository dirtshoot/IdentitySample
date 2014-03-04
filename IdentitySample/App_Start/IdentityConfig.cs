using System.Net.Mail;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using System.Data.Entity;
using System.Threading.Tasks;

namespace IdentitySample.Models
{
    // This is useful if you do not want to tear down the database each time you run the application.
    // public class ApplicationDbInitializer : DropCreateDatabaseAlways<ApplicationDbContext>
    // This example shows you how to create a new database if the Model changes
    public class ApplicationDbInitializer : DropCreateDatabaseAlways<ApplicationDbContext>
    {
        protected override void Seed(ApplicationDbContext context)
        {
            InitializeIdentityForEF(context);
            base.Seed(context);
        }

        //Create User=Admin@Admin.com with password=123456 in the Admin role        
        public static void InitializeIdentityForEF(ApplicationDbContext db)
        {
            //var store = new UserStore<ApplicationUser>(db);
            var userManager = new ApplicationUserManager(new UserStore<ApplicationUser>(db));
            var roleManager = new RoleManager<IdentityRole>(new RoleStore<IdentityRole>(db));

            const string roleName = "Admin";

            //Create Role Admin if it does not exist
            var role = roleManager.FindByName(roleName);
            if (role == null)
            {
                role = new IdentityRole(roleName);
                var roleresult = roleManager.Create(new IdentityRole(roleName));
            }

            var user = userManager.FindByName("Admin");
            if (user == null)
            {
                //Create Admin
                user = new ApplicationUser() { UserName = "Admin", Email = "admin@bidami.com", EmailConfirmed = true, Person = new People() { FirstName = "Sam", LastName = "High" } };
                var umresult = userManager.Create(user, "ozric$9@");

                //Add User Admin to Role Admin
                if (umresult.Succeeded)
                {
                    // Add user admin to Role Admin if not already added
                    var rolesForUser = userManager.GetRoles(user.Id);
                    if (!rolesForUser.Contains(role.Name))
                    {
                        var result = userManager.AddToRole(user.Id, role.Name);
                    }
                }
            }

            user = userManager.FindByName("Kieta");
            if (user == null)
            {
                //Create Admin
                user = new ApplicationUser() { UserName = "Kieta", Email = "keita@bidami.com", EmailConfirmed = true, Person = new People() { FirstName = "Kieta", LastName = "Kieta" } };
                var umresult = userManager.Create(user, "liberty33");

                //Add User Admin to Role Admin
                if (umresult.Succeeded)
                {
                    // Add user admin to Role Admin if not already added
                    var rolesForUser = userManager.GetRoles(user.Id);
                    if (!rolesForUser.Contains(role.Name))
                    {
                        var result = userManager.AddToRole(user.Id, role.Name);
                    }
                }
            }

            user = userManager.FindByName("User");
            if (user == null)
            {
                //Create Admin
                user = new ApplicationUser() { UserName = "User", Email = "user@bidami.com", EmailConfirmed = true, Person = new People() { FirstName = "User", LastName = "Account" } };
                var umresult = userManager.Create(user, "liberty33");

            }

            user = userManager.FindByName("UserUnconfirmed");
            if (user == null)
            {
                //Create Admin
                user = new ApplicationUser() { UserName = "UserUnconfirmed", Email = "userunconfirmed@bidami.com", Person = new People() { FirstName = "User", LastName = "Account" } };
                var umresult = userManager.Create(user, "liberty33");

            }
        }
    }

    // Configure the application user manager used in this application. UserManager is defined in ASP.NET Identity and is used by the application.

    public class ApplicationUserManager : UserManager<ApplicationUser>
    {
        public ApplicationUserManager(IUserStore<ApplicationUser> store)
            : base(store)
        {
        }

        public static ApplicationUserManager Create(IdentityFactoryOptions<ApplicationUserManager> options, IOwinContext context)
        {
            var manager = new ApplicationUserManager(new UserStore<ApplicationUser>(context.Get<ApplicationDbContext>()));
            // Configure validation logic for usernames
            manager.UserValidator = new UserValidator<ApplicationUser>(manager)
            {
                AllowOnlyAlphanumericUserNames = true,
                RequireUniqueEmail = true
            };
            // Configure validation logic for passwords
            manager.PasswordValidator = new PasswordValidator
            {
                RequiredLength = 6,
                RequireNonLetterOrDigit = false,
                RequireDigit = false,
                RequireLowercase = false,
                RequireUppercase = false,
            };
            // Register two factor authentication providers. This application uses Phone and Emails as a step of receiving a code for verifying the user
            // You can write your own provider and plug in here.
            manager.RegisterTwoFactorProvider("PhoneCode", new PhoneNumberTokenProvider<ApplicationUser>
            {
                MessageFormat = "Your security code is: {0}"
            });
            manager.RegisterTwoFactorProvider("EmailCode", new EmailTokenProvider<ApplicationUser>
            {
                Subject = "SecurityCode",
                BodyFormat = "Your security code is {0}"
            });
            manager.EmailService = new EmailService();
            manager.SmsService = new SmsService();
            var dataProtectionProvider = options.DataProtectionProvider;
            if (dataProtectionProvider != null)
            {
                manager.UserTokenProvider = new DataProtectorTokenProvider<ApplicationUser>(dataProtectionProvider.Create("ASP.NET Identity"));
            }
            return manager;
        }
    }
    public class EmailService : IIdentityMessageService
    {
        public Task SendAsync(IdentityMessage message)
        {
            // Plug in your email service here to send an email.
            // Create the mail message
            var mailMessage = new MailMessage(
                "noereply@bidami.com",
                message.Destination,
                message.Subject,
                message.Body
                );

            // Send the message
            SmtpClient client = new SmtpClient();
            client.SendAsync(mailMessage, null);
            return Task.FromResult(true);
        }
    }

    public class SmsService : IIdentityMessageService
    {
        public Task SendAsync(IdentityMessage message)
        {
            // Plug in your sms service here to send a text message.
            return Task.FromResult(0);
        }
    }
}