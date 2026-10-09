using System.Diagnostics;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using CompAtlas.Collector;
using CompAtlas.Core;

return await CollectorCommand.Run(args);

namespace CompAtlas.Collector
{
    public static class CollectorCommand
    {
        public static async Task<int> Run(string[] args)
        {
            try
            {
                if (args.Length == 0) { Console.WriteLine("CompAtlas.Collector collect --path CHECKOUT --output BOM.json | submit --bom BOM.json --repository GUID --application NAME --commit SHA --branch REF [--build ID] [--release ID] | claim | complete --job GUID --lease GUID [--success true]. Secrets: COMPATLAS_TOKEN; endpoint: COMPATLAS_URL."); return 0; }
                var options = new Dictionary<string, string>(StringComparer.Ordinal);
                for (var i = 1; i < args.Length; i += 2) { if (i + 1 >= args.Length || !args[i].StartsWith("--", StringComparison.Ordinal)) throw new ArgumentException("Options require --name value pairs."); options.Add(args[i][2..], args[i + 1]); }
                string Required(string key) => options.GetValueOrDefault(key) ?? throw new ArgumentException("Missing --" + key);
                using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(20));
                if (args[0] == "collect")
                {
                    var path = Path.GetFullPath(Required("path"));
                    var output = Path.GetFullPath(Required("output"));
                    if (options.TryGetValue("scanner", out var scanner))
                    {
                        if (Environment.GetEnvironmentVariable("COMPATLAS_ISOLATED_JOB") != "1") throw new InvalidOperationException("Scanner execution requires an externally provisioned isolated job.");
                        scanner = Path.GetFullPath(scanner);
                        if (scanner.StartsWith(path.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new ArgumentException("Scanner must be provisioned outside the untrusted checkout.");
                        var entrypoint = options.GetValueOrDefault("scanner-entrypoint");
                        var hashedFile = entrypoint == null ? scanner : Path.GetFullPath(entrypoint);
                        if (hashedFile.StartsWith(path.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new ArgumentException("Scanner entrypoint must be outside the checkout.");
                        var hash = Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(hashedFile, timeout.Token)));
                        if (!string.Equals(hash, Required("scanner-sha256"), StringComparison.OrdinalIgnoreCase)) throw new ArgumentException("Scanner integrity check failed.");
                        var info = new ProcessStartInfo(scanner) { UseShellExecute = false, WorkingDirectory = path };
                        // Never give a scanner the CompAtlas upload token, even when a caller forgot to clear it.
                        var permittedEnvironment = new[] { "PATH", "SystemRoot", "WINDIR", "TEMP", "TMP", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "DOTNET_ROOT", "PROGRAMFILES", "PROGRAMFILES(X86)", "NPM_CONFIG_IGNORE_SCRIPTS", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE" };
                        var safeEnvironment = info.Environment.Where(x => permittedEnvironment.Contains(x.Key, StringComparer.OrdinalIgnoreCase)).ToArray();
                        info.Environment.Clear();
                        foreach (var variable in safeEnvironment) info.Environment[variable.Key] = variable.Value;
                        info.Environment["NPM_CONFIG_IGNORE_SCRIPTS"] = "true";
                        if (entrypoint != null) info.ArgumentList.Add(hashedFile);
                        foreach (var value in new[] { "-r", path, "-o", output, "--spec-version", "1.6" }) info.ArgumentList.Add(value);
                        using var process = Process.Start(info) ?? throw new InvalidOperationException("Scanner could not start.");
                        try { await process.WaitForExitAsync(timeout.Token); }
                        catch (OperationCanceledException) { process.Kill(entireProcessTree: true); throw; }
                        if (process.ExitCode != 0) throw new InvalidOperationException("Scanner failed.");
                    }
                    else await File.WriteAllTextAsync(output, Inventory.Create(path), timeout.Token);
                    Console.WriteLine("SBOM written. Conservative inventories are explicitly partial."); return 0;
                }
                var url = Environment.GetEnvironmentVariable("COMPATLAS_URL") ?? throw new ArgumentException("COMPATLAS_URL is required.");
                var endpoint = new Uri(url.TrimEnd('/') + "/");
                if (endpoint.Scheme != "https" || endpoint.UserInfo.Length > 0) throw new ArgumentException("An HTTPS endpoint is required.");
                using var client = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false }) { Timeout = TimeSpan.FromMinutes(2) };
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", Environment.GetEnvironmentVariable("COMPATLAS_TOKEN") ?? throw new ArgumentException("COMPATLAS_TOKEN is required."));
                HttpResponseMessage response;
                if (args[0] == "submit")
                {
                    var file = Required("bom");
                    if (new FileInfo(file).Length > 10 * 1024 * 1024) throw new ArgumentException("SBOM exceeds 10 MiB.");
                    var submission = new Submission(Guid.Parse(Required("repository")), Required("application"), options.GetValueOrDefault("relative-path", "."),
                        Required("commit"), Required("branch"), options.GetValueOrDefault("build"), options.GetValueOrDefault("release"), await File.ReadAllTextAsync(file, timeout.Token));
                    response = await client.PostAsJsonAsync(new Uri(endpoint, "api/v1/sboms"), submission, timeout.Token);
                }
                else if (args[0] == "claim") response = await client.PostAsync(new Uri(endpoint, "api/v1/collection/claim"), null, timeout.Token);
                else if (args[0] == "complete") response = await client.PostAsJsonAsync(new Uri(endpoint, "api/v1/collection/" + Guid.Parse(Required("job")) + "/complete"),
                    new Completion(Guid.Parse(Required("lease")), options.GetValueOrDefault("success") == "true"), timeout.Token);
                else throw new ArgumentException("Unknown command.");
                using (response)
                {
                    if (!response.IsSuccessStatusCode) throw new HttpRequestException("CompAtlas returned HTTP " + (int)response.StatusCode);
                    Console.WriteLine(await response.Content.ReadAsStringAsync(timeout.Token));
                }
                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("CompAtlas advisory collection failed (" + ex.GetType().Name + "). Review configuration and restricted job diagnostics.");
                return 1; // Pipeline wrapper converts failures into warnings; standalone callers retain failure evidence.
            }
        }
    }
}
