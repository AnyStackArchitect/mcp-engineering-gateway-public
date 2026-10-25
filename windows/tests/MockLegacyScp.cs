// CI-ONLY local fake ssh.exe/scp.exe. No network, credentials or Rocky host.
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

public class MockLegacyScp
{
    static readonly Regex Token = new Regex(@"^\.upload-[a-f0-9]{32}$");
    static readonly Regex Sha = new Regex(@"^[a-f0-9]{64}$");
    const string Inbox = "/home/engtest/.local/share/rocky-mcp-gateway/inbox";
    const long MaxArtifact = 8589934592L;
    static string root;

    static void Event(string name)
    {
        File.AppendAllText(Path.Combine(root, "events.txt"),
                           name + Environment.NewLine, Encoding.ASCII);
    }
    static string JsonString(string raw)
    {
        return "\"" + raw.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";
    }
    static string Hash(string path)
    {
        using (var sha = SHA256.Create())
        using (var stream = File.OpenRead(path))
            return BitConverter.ToString(sha.ComputeHash(stream)).Replace("-", "").ToLowerInvariant();
    }
    static string Arg(string[] args, int index, string key)
    {
        for (int i = index + 1; i + 1 < args.Length; i++)
            if (args[i] == key)
                return args[i + 1];
        throw new InvalidOperationException("Missing fixed argument");
    }
    static long Number(string text)
    {
        long v;
        if (!Int64.TryParse(text, out v) || v < 0 || v > MaxArtifact)
            throw new InvalidOperationException("Invalid declared size");
        return v;
    }
    static string[] Identity(string token)
    {
        if (!Token.IsMatch(token))
            throw new InvalidOperationException("Invalid upload token");
        string sidecar = Path.Combine(root, token + ".session");
        if (!File.Exists(sidecar))
            throw new InvalidOperationException("No durable session exists");
        string[] fields = File.ReadAllText(sidecar).Split('|');
        if (fields.Length != 2 || !Sha.IsMatch(fields[1]))
            throw new InvalidOperationException("Corrupt upload session");
        Number(fields[0]);
        return fields;
    }
    static void VerifyAuthFlags(string[] argv)
    {
        var flags = new List<string>(argv);
        foreach (string required in new string[] {
            "BatchMode=yes", "IdentitiesOnly=yes", "StrictHostKeyChecking=yes", "ClearAllForwardings=yes" })
            if (!flags.Contains(required))
                throw new InvalidOperationException("Required SSH policy missing");
        int key = Array.IndexOf(argv, "-i");
        if (key < 0 || key + 1 >= argv.Length || !File.Exists(argv[key + 1])
            || argv[key + 1].IndexOf("key with spaces", StringComparison.Ordinal) < 0)
            throw new InvalidOperationException("Identity path was not quoted correctly");
    }
    static int Ssh(string[] argv)
    {
        VerifyAuthFlags(argv);
        if (Array.IndexOf(argv, "engtest@rocky.example") < 0
            || Array.IndexOf(argv, "/opt/rocky-eng/transfer_bridge.py") < 0)
            throw new InvalidOperationException("Unexpected SSH target or remote helper");
        string action = null;
        int at = -1;
        for (int i = 0; i < argv.Length; i++)
            if (argv[i] == "prepare" || argv[i] == "begin" ||
                argv[i] == "finalize" || argv[i] == "abort")
            {
                action = argv[i];
                at = i;
                break;
            }
        if (at < 0)
            throw new InvalidOperationException("Unexpected remote operation");
        if (action == "prepare")
        {
            long proposed = Number(Arg(argv, at, "--size"));
            long available = 104857600L;
            string configured = Environment.GetEnvironmentVariable("ROCKY_LEGACY_SAFE_BYTES");
            if (!String.IsNullOrEmpty(configured))
                available = Number(configured);
            Event("PREPARE");
            if (proposed > available)
                throw new InvalidOperationException("Insufficient prepared capacity");
            Console.WriteLine("{\"status\":\"READY\",\"inbox\":" + JsonString(Inbox) +
                ",\"max_artifact_bytes\":8589934592,\"safe_available_bytes\":" + available + "}");
            return 0;
        }
        string token = Arg(argv, at, "--temp");
        if (!Token.IsMatch(token))
            throw new InvalidOperationException("Invalid upload token");
        string partial = Path.Combine(root, token);
        string metadata = partial + ".session";
        if (action == "begin")
        {
            Event("BEGIN");
            if (Environment.GetEnvironmentVariable("ROCKY_LEGACY_DENY_BEGIN") == "1")
                throw new InvalidOperationException("Injected reservation refusal");
            long length = Number(Arg(argv, at, "--size"));
            string digest = Arg(argv, at, "--sha256");
            if (!Sha.IsMatch(digest))
                throw new InvalidOperationException("Invalid digest");
            using (var stream = new FileStream(partial, FileMode.CreateNew, FileAccess.Write))
                stream.Flush(true);
            File.WriteAllText(metadata, length + "|" + digest, Encoding.UTF8);
            Console.WriteLine("{\"status\":\"SESSION_CREATED\",\"bytes_staged\":0," +
                "\"declared_size\":" + length + ",\"expected_sha256\":" +
                JsonString(digest) + "}");
            return 0;
        }
        if (action == "abort")
        {
            Event("ABORT");
            if (File.Exists(partial)) File.Delete(partial);
            if (File.Exists(metadata)) File.Delete(metadata);
            Console.WriteLine("{\"status\":\"TEMPORARY_FILE_REMOVED\"}");
            return 0;
        }
        if (action == "finalize")
        {
            Event("FINALIZE");
            string[] identity = Identity(token);
            long length = Number(identity[0]);
            string digest = identity[1];
            if (length != Number(Arg(argv, at, "--size"))
                || digest != Arg(argv, at, "--sha256"))
                throw new InvalidOperationException("Finalization identity changed");
            string name = Arg(argv, at, "--filename");
            if (!Regex.IsMatch(name, "^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"))
                throw new InvalidOperationException("Invalid destination name");
            if (new FileInfo(partial).Length != length || Hash(partial) != digest)
                throw new InvalidOperationException("Staged file size/digest invalid");
            string destination = Path.Combine(root, name);
            if (File.Exists(destination))
                throw new InvalidOperationException("Destination already exists");
            File.Move(partial, destination);
            File.Delete(metadata);
            Console.WriteLine("{\"status\":\"STAGED\",\"filename\":" +
                JsonString(name) + ",\"bytes\":" + length + ",\"sha256\":" +
                JsonString(digest) + "}");
            return 0;
        }
        throw new InvalidOperationException("Unknown fixed SSH operation");
    }
    static int Scp(string[] argv)
    {
        VerifyAuthFlags(argv);
        int separator = Array.IndexOf(argv, "--");
        if (separator < 0 || separator + 2 != argv.Length - 1)
            throw new InvalidOperationException("SCP must use exact source/target after --");
        string local = argv[separator + 1];
        string remote = argv[separator + 2];
        string prefix = "engtest@rocky.example:" + Inbox + "/";
        if (!remote.StartsWith(prefix, StringComparison.Ordinal))
            throw new InvalidOperationException("Unexpected SCP destination");
        string token = remote.Substring(prefix.Length);
        string[] identity = Identity(token);
        string destination = Path.Combine(root, token);
        if (!File.Exists(local) || !File.Exists(destination))
            throw new InvalidOperationException("SCP must target a reserved placeholder");
        Event("SCP");
        using (var src = File.OpenRead(local))
        using (var dst = new FileStream(destination, FileMode.Truncate,
                                      FileAccess.Write, FileShare.None))
        {
            if (Environment.GetEnvironmentVariable("ROCKY_LEGACY_DROP_SCP") == "1")
            {
                byte[] first = new byte[37];
                int n = src.Read(first, 0, first.Length);
                dst.Write(first, 0, n);
                dst.Flush(true);
                Event("SCP_INTERRUPTED");
                return 73;
            }
            src.CopyTo(dst);
            dst.Flush(true);
        }
        if (new FileInfo(destination).Length > Number(identity[0]))
            throw new InvalidOperationException("Exceeded reserved size");
        return 0;
    }
    public static int Main(string[] argv)
    {
        try
        {
            root = Environment.GetEnvironmentVariable("ROCKY_LEGACY_CI_ROOT");
            if (String.IsNullOrEmpty(root) || !Directory.Exists(root))
                throw new InvalidOperationException("Synthetic test root unavailable");
            string executable = Path.GetFileName(Environment.GetCommandLineArgs()[0]).ToLowerInvariant();
            if (executable == "scp.exe")
                return Scp(argv);
            if (executable == "ssh.exe")
                return Ssh(argv);
            throw new InvalidOperationException("Unsupported mock executable");
        }
        catch (Exception)
        {
            Console.Error.WriteLine("synthetic transfer action refused");
            return 19;
        }
    }
}
