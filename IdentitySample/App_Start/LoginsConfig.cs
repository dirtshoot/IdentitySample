using System;
using System.Collections.Generic;
using System.Data.Entity.Core;
using System.Linq;
using System.Web;
using System.Net.Mail;
using BidAmiModel;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using System.Data.Entity;
using System.Threading.Tasks;
using IdentitySample.Models;
using System.Data.Entity.Core.Objects;
using System.Data.Entity.Infrastructure;

namespace IdentitySample
{
    public class LoginsConfig
    {

        public static void CreateLogins(ApplicationDbContext db)
        {
            //var store = new UserStore<ApplicationUser>(db);
            //var ctx = new BidAmiEntities();
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

            var username = "Admin";
            var password = "ozric$9@";
            var user = userManager.FindByName(username);
            if (user == null)
            {
                //Create Admin
                user = new ApplicationUser() { UserName = username, Email = username.ToLower() + "@bidami.com", EmailConfirmed = true, FirstName = "Sam", LastName = "High", Created = System.DateTime.Now };
                var umresult = userManager.Create(user, password);

                //Add User Admin to Role Admin
                if (umresult.Succeeded)
                {
                    // Add user admin to Role Admin if not already added
                    var rolesForUser = userManager.GetRoles(user.Id);
                    if (!rolesForUser.Contains(role.Name))
                    {
                        var result = userManager.AddToRole(user.Id, role.Name);
                    }
                    CreateProfile(user.Id);
                }
            }

            username = "Kieta";
            password = "liberty33";
            user = userManager.FindByName(username);
            if (user == null)
            {
                //Create Admin
                user = new ApplicationUser() { UserName = username, Email = username.ToLower() + "@bidami.com", EmailConfirmed = true, FirstName = "Kieta", LastName = "Kieta", Created = System.DateTime.Now };
                var umresult = userManager.Create(user, password);

                //Add User Admin to Role Admin
                if (umresult.Succeeded)
                {
                    // Add user admin to Role Admin if not already added
                    var rolesForUser = userManager.GetRoles(user.Id);
                    if (!rolesForUser.Contains(role.Name))
                    {
                        var result = userManager.AddToRole(user.Id, role.Name);
                    }
                    CreateProfile(user.Id);
                }
            }

            username = "User";
            password = "liberty33";
            user = userManager.FindByName(username);
            if (user == null)
            {
                //Create Admin
                user = new ApplicationUser() { UserName = username, Email = username.ToLower() + "@bidami.com", EmailConfirmed = true, FirstName = "User", LastName = "Account", Created = System.DateTime.Now };
                var umresult = userManager.Create(user, password);
                if (umresult.Succeeded)
                {
                    CreateProfile(user.Id);
                }
            }

            username = "UserUnconfirmed";
            password = "liberty33";
            user = userManager.FindByName(username);
            if (user == null)
            {
                //Create Admin
                user = new ApplicationUser() { UserName = username, Email = username.ToLower() + "@bidami.com", FirstName = "User", LastName = "Account", Created = System.DateTime.Now };
                var umresult = userManager.Create(user, "liberty33");
                if (umresult.Succeeded)
                {
                    CreateProfile(user.Id);
                }

            }

        }
        public static void CreateProfile(string id)
        {
            using (var db = new BidAmiEntities())
            {
                //db.Configuration.ProxyCreationEnabled = false;
                //db.Configuration.AutoDetectChangesEnabled = false;
                //db.Configuration.LazyLoadingEnabled = false;
                //var aspuser = db.AspNetUsers.Find(id);
                var profile = new Profile {UserId = id, Created = System.DateTime.Now };
                db.Profiles.Add(profile);
                //try
                //{
                //    db.SaveChanges();
                //}
                //catch (Exception ex)
                //{

                //}
            }
        }
    }
}