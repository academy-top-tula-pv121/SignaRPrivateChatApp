using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.SignalR;

namespace SignaRPrivateChatApp
{
    [Authorize]
    public class ChatHub : Hub
    {
        public async Task Send(string to, string message)
        {
            //var userName = Context.UserIdentifier;
            if(Context.UserIdentifier is String userName)
            {
                await Clients.Users(to, userName).SendAsync("Receive", userName, message);
            }
        }

        public override async Task OnConnectedAsync()
        {
            await Clients.All.SendAsync("Notify", $"Welcome to the Chat, {Context.UserIdentifier}");
            await base.OnConnectedAsync();
        }

    }
}
