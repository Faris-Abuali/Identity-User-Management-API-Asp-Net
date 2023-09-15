using User.Management.Service.Models;

namespace User.Management.Service.Services.Email;

public interface IEmailService
{
    void SendEmail(Message message);
}
