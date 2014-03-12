using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using BidAmiModel;
using Infrastucture;

namespace IdentitySample.Models
{
    public class ConfirmSellerViewModel
    {
        public ConfirmSellerViewModel()
        {
            this.PaymentMethod = "Check";
        }

        [Required]
        public string UserId { get; set; }

        [Required]
        public string Code { get; set; }

        [Required]
        public int ProfileId { get; set; }

        [Display(Name = "Business Name")]
        public string BusinessName { get; set; }

        [Required]
        [Display(Name = "Address")]
        public string Address1 { get; set; }

        [Display(Name = "")]
        public string Address2 { get; set; }

        [Required]
        public string Country { get; set; }

        [Required]
        public string City { get; set; }

        [Required]
        [Display(Name = "State")]
        public string StateRegion { get; set; }

        [Required]
        [Display(Name = "Zip/Postal")]
        public string ZipPostal { get; set; }

        [Required]
        [Display(Name = "Phone")]
        public string PhoneNo { get; set; }

        [Required]
        [Display(Name = "Payment Method")]
        public string PaymentMethod { get; set; }

        [Display(Name = "Payment Methods")]
        public List<PaymnetMethod> PaymentMethods { get; set; }
    }

    public class ExternalLoginConfirmationViewModel : RegisterCommonModel
    {

    }

    public class ExternalLoginListViewModel
    {
        public string ReturnUrl { get; set; }
    }

    public class SendCodeViewModel
    {
        public string SelectedProvider { get; set; }
        public ICollection<System.Web.Mvc.SelectListItem> Providers { get; set; }
        public string ReturnUrl { get; set; }
    }

    public class VerifyCodeViewModel
    {
        [Required]
        public string Provider { get; set; }

        [Required]
        [Display(Name = "Code")]
        public string Code { get; set; }
        public string ReturnUrl { get; set; }

        [Display(Name = "Remember this browser?")]
        public bool RememberBrowser { get; set; }
    }

    public class SendConfirmEmail
    {
        [Required]
        [Display(Name = "User Name")]
        public string UserName { get; set; }
    }

    public class ForgotViewModel
    {
        [Required]
        [Display(Name = "User Name")]
        public string UserName { get; set; }
    }

    public class LoginViewModel
    {
        [Required]
        [Display(Name = "User Name")]
        public string UserName { get; set; }

        [Required]
        [DataType(DataType.Password)]
        [Display(Name = "Password")]
        public string Password { get; set; }

        [Display(Name = "Remember me?")]
        public bool RememberMe { get; set; }
    }

    public class RegisterCommonModel
    {
        [Required]
        [Display(Name = "First Name")]
        public string FirstName { get; set; }

        [Required]
        [Display(Name = "Last Name")]
        public string LastName { get; set; }

        [Required]
        [Display(Name = "User Name")]
        public string UserName { get; set; }

        [Required]
        [EmailAddress]
        [Display(Name = "Email")]
        public string Email { get; set; }

        [Display(Name = "Get Our Auction Newsletter?")]
        public bool NewsLetter { get; set; }

        [Display(Name = "Do you want to register as a Seller Account?")]
        public bool Seller { get; set; }

        [Display(Name = "What other auction sites do you purchase from? ")]
        public string Reference { get; set; }

        //[RegularExpression("^true", ErrorMessage = "You must agree to the terms to register")]
        [MustBeTrue(ErrorMessage = "You must accept the terms and conditions")]
        [Display(Name = "I Agree to the Terms?")]
        public bool Terms { get; set; }     
    }

    public class RegisterViewModel : RegisterCommonModel
    {

        [Required]
        [StringLength(100, ErrorMessage = "The {0} must be at least {2} characters long.", MinimumLength = 6)]
        [DataType(DataType.Password)]
        [Display(Name = "Password")]
        public string Password { get; set; }

        [DataType(DataType.Password)]
        [Display(Name = "Confirm password")]
        [Compare("Password", ErrorMessage = "The password and confirmation password do not match.")]
        public string ConfirmPassword { get; set; }
    }

    public class ResetPasswordViewModel
    {
        [Required]
        [Display(Name = "User Name")]
        public string UserName { get; set; }

        [Required]
        [StringLength(100, ErrorMessage = "The {0} must be at least {2} characters long.", MinimumLength = 6)]
        [DataType(DataType.Password)]
        [Display(Name = "Password")]
        public string Password { get; set; }

        [DataType(DataType.Password)]
        [Display(Name = "Confirm password")]
        [Compare("Password", ErrorMessage = "The password and confirmation password do not match.")]
        public string ConfirmPassword { get; set; }

        public string Code { get; set; }
    }

    public class ForgotPasswordViewModel
    {
        [Required]
        [Display(Name = "User Name")]
        public string UserName { get; set; }
    }
}