using Microsoft.AspNetCore.SignalR;
using System.Security.Claims;

namespace SignaRPrivateChatApp
{
    public class CustomUserIdProvider : IUserIdProvider
    {
        public virtual string? GetUserId(HubConnectionContext connection)
        {
            return connection.User?.FindFirst(ClaimTypes.Name)?.Value;
        }
    }
}
