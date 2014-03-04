using System;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using Postal;

namespace IdentitySample.Models
{
    public class ConfirmEmail : Email
    {

        [Required(ErrorMessage = "Email Address is required"), StringLength(100)]
        [EmailAddress(ErrorMessage = "Invalid Email Address")]
        public string To { get; set; }

        [Required(ErrorMessage = "User Name is required")]
        public string UserName { get; set; }

        //[Required(ErrorMessage = "Email Message is required")]
        //public string Message { get; set; }

        [Required(ErrorMessage = "Id is required")]
        public string Id { get; set; }

        [Required(ErrorMessage = "Code is required")]
        public string Code { get; set; }
    }

    public class ForgotPasswordEmail : Email
    {

        [Required(ErrorMessage = "Email Address is required"), StringLength(100)]
        [EmailAddress(ErrorMessage = "Invalid Email Address")]
        public string To { get; set; }

        [Required(ErrorMessage = "User Name is required")]
        public string UserName { get; set; }

        //[Required(ErrorMessage = "Email Message is required")]
        //public string Message { get; set; }

        [Required(ErrorMessage = "Id is required")]
        public string Id { get; set; }

        [Required(ErrorMessage = "Code is required")]
        public string Code { get; set; }
    }

    public class EmailMsg : Email
    {
        [Required(ErrorMessage = "Email Address is required"), StringLength(100)]
        [EmailAddress(ErrorMessage = "Invalid Email Address")]
        public string From { get; set; }

        [Required(ErrorMessage = "Email Address is required"), StringLength(100)]
        [EmailAddress(ErrorMessage = "Invalid Email Address")]
        public string To { get; set; }

        [StringLength(128)]
        public string UserId { get; set; }

        [Required(ErrorMessage = "First Name is required"), StringLength(50)]
        [DisplayName("First Name")]
        public string FirstName { get; set; }

        [Required(ErrorMessage = "Last Name is required"), StringLength(50)]
        public string LastName { get; set; }

        [StringLength(50)]
        public string Phone { get; set; }

        [StringLength(50)]
        public string BestTime { get; set; }

        [Required, StringLength(100)]
        public string Subject { get; set; }

        [Required(ErrorMessage = "Email Message is required")]
        public string Message { get; set; }
    }

}