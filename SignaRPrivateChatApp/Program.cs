using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.SignalR;
using Microsoft.IdentityModel.Tokens;
using SignaRPrivateChatApp;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

var users = new List<User>()
{
    new() { Login = "bob", Password = "123" },
    new() { Login = "leo", Password = "555" },
    new() { Login = "sam", Password = "111" },
};

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddSingleton<IUserIdProvider, CustomUserIdProvider>();

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(o => 
                {
                    o.TokenValidationParameters = new TokenValidationParameters()
                    {
                        ValidateIssuer = true,
                        ValidIssuer = AuthOptions.Issuer,
                        ValidateAudience = true,
                        ValidAudience = AuthOptions.Client,
                        ValidateLifetime = true,
                        IssuerSigningKey = AuthOptions.GetSymmetricSecurityKey(),
                        ValidateIssuerSigningKey = true
                    };
                    o.Events = new JwtBearerEvents()
                    {
                        OnMessageReceived = context =>
                        {
                            var token = context.Request.Query["access_token"];

                            var path = context.HttpContext.Request.Path;
                            if(!String.IsNullOrEmpty(token) && path.StartsWithSegments("/chat"))
                            {
                                context.Token = token;
                            }
                            return Task.CompletedTask;
                        }
                    };
                });
builder.Services.AddAuthorization();
builder.Services.AddSignalR();

var app = builder.Build();

app.UseDefaultFiles();
app.UseStaticFiles();

app.UseAuthentication();
app.UseAuthorization();

app.MapPost("/login", (User userModel) =>
{
    User? user = users.FirstOrDefault(u => u.Login == userModel.Login && u.Password == userModel.Password);
    if (user == null) return Results.Unauthorized();

    var claims = new List<Claim> { new Claim(ClaimTypes.Name, user.Login) };

    var jwt = new JwtSecurityToken(
        issuer: AuthOptions.Issuer,
        audience: AuthOptions.Client,
        claims: claims,
        expires: DateTime.Now.Add(TimeSpan.FromMinutes(5)),
        signingCredentials: new SigningCredentials(AuthOptions.GetSymmetricSecurityKey(), SecurityAlgorithms.HmacSha256)
        );
    var jwtToken = new JwtSecurityTokenHandler().WriteToken(jwt);

    var response = new
    {
        access_token = jwtToken,
        username = user.Login
    };

    return Results.Json(response);
});

app.MapHub<ChatHub>("/chat");

app.Run();

public class User
{
    public string? Login { set; get; }
    public string? Password { set; get; }
}

public class AuthOptions
{
    public const string Issuer = "AuthServer";
    public const string Client = "AuthClient";
    const string Key = "hkjfaoipo3412kj21ljqdfdnhkqjh!d";
    public static SymmetricSecurityKey GetSymmetricSecurityKey() =>
        new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Key));
}
