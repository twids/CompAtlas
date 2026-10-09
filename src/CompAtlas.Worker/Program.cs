using CompAtlas.Infrastructure;
using CompAtlas.Worker;

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(o => o.ServiceName = "CompAtlas Worker");
builder.Services.AddCompAtlas(builder.Configuration);
builder.Services.AddHostedService<Orchestrator>();
await builder.Build().RunAsync();
