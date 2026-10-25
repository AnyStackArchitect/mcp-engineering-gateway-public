// CI ONLY fake ssh.exe. It is NOT a network transport or Rocky service.
// Tests that the real Windows client sends opaque bytes through an executable
// stdin, validates remote SHA prefixes, and never overwrites existing files.
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

public class MockSsh
{
    private const long MaxArtifact = 8589934592L;

    private static string Hash(byte[] data)
    {
        using (var sha = SHA256.Create())
            return BitConverter.ToString(sha.ComputeHash(data)).Replace("-", "").ToLowerInvariant();
    }

    private static string HashFile(string path)
    {
        using (var sha = SHA256.Create())
        using (var file = File.OpenRead(path))
            return BitConverter.ToString(sha.ComputeHash(file)).Replace("-", "").ToLowerInvariant();
    }

    private static string[] Normalize(string[] source)
    {
        var parts = new List<string>();
        foreach (string item in source)
        {
            // PowerShell's text ssh invocation passes separate argv, whereas
            // ProcessStartInfo passes the fixed remote command as one argv.
            if (item.StartsWith("python3 -u ", StringComparison.Ordinal))
                parts.AddRange(item.Split(new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries));
            else
                parts.Add(item);
        }
        return parts.ToArray();
    }

    private static string Option(string[] args, int action, string name)
    {
        for (int i = action + 1; i + 1 < args.Length; i++)
            if (args[i] == name)
                return args[i + 1];
        throw new InvalidOperationException("Missing fixture argument");
    }

    private static long Number(string raw)
    {
        long value;
        if (!Int64.TryParse(raw, out value) || value < 0 || value > MaxArtifact)
            throw new InvalidOperationException("Invalid fixture size");
        return value;
    }

    private static string JsonString(string data)
    {
        return "\"" + data.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";
    }

    private static string[] Session(string path)
    {
        var s = File.ReadAllText(path, Encoding.UTF8).Split('|');
        if (s.Length != 2) throw new InvalidOperationException("Invalid fixture session");
        return s;
    }

    public static int Main(string[] native)
    {
        try
        {
            string[] args = Normalize(native);
            var flags = new List<string>(args);
            foreach (string required in new string[] {
                "-T", "BatchMode=yes", "IdentitiesOnly=yes",
                "StrictHostKeyChecking=yes", "ClearAllForwardings=yes" })
                if (!flags.Contains(required))
                    throw new InvalidOperationException("Required fixed SSH flag missing");
            if (!flags.Contains("engtest@rocky.example"))
                throw new InvalidOperationException("Unexpected synthetic SSH target");
            int keyIndex = Array.IndexOf(args, "-i");
            if (keyIndex < 0 || keyIndex + 1 >= args.Length ||
                !File.Exists(args[keyIndex + 1]) ||
                args[keyIndex + 1].IndexOf("keys with spaces", StringComparison.Ordinal) < 0)
                throw new InvalidOperationException("SSH identity path was split or misquoted");
            int pythonIndex = Array.IndexOf(args, "python3");
            if (pythonIndex < 0 || pythonIndex + 2 >= args.Length ||
                args[pythonIndex + 1] != "-u" ||
                args[pythonIndex + 2] != "/opt/rocky-eng/transfer_bridge.py")
                throw new InvalidOperationException("Unexpected remote helper argv");
            string root = Environment.GetEnvironmentVariable("ROCKY_TEST_UPLOAD_ROOT");
            if (String.IsNullOrEmpty(root) || !Directory.Exists(root))
                throw new InvalidOperationException("Synthetic upload root missing");
            int pos = -1;
            string action = null;
            for (int i = 0; i < args.Length; i++)
                if (args[i] == "prepare" || args[i] == "begin" || args[i] == "status" ||
                    args[i] == "append" || args[i] == "finalize" || args[i] == "abort")
                {
                    action = args[i]; pos = i; break;
                }
            if (pos < 0) throw new InvalidOperationException("Unsupported synthetic action");
            if (action == "prepare")
            {
                long size = Number(Option(args, pos, "--size"));
                if (size > MaxArtifact) throw new InvalidOperationException("Size rejected");
                Console.WriteLine("{\"status\":\"READY\",\"max_artifact_bytes\":8589934592," +
                                  "\"safe_available_bytes\":12884901888}");
                return 0;
            }
            string token = Option(args, pos, "--temp");
            if (!System.Text.RegularExpressions.Regex.IsMatch(token,
                    @"^\.upload-[a-f0-9]{32}$"))
                throw new InvalidOperationException("Token invalid");
            string partial = Path.Combine(root, token);
            string metadata = partial + ".session";
            if (action == "begin")
            {
                long length = Number(Option(args, pos, "--size"));
                string expected = Option(args, pos, "--sha256");
                if (!System.Text.RegularExpressions.Regex.IsMatch(expected, "^[a-f0-9]{64}$"))
                    throw new InvalidOperationException("SHA invalid");
                using (var fd = new FileStream(partial, FileMode.CreateNew, FileAccess.Write))
                    fd.Flush(true);
                File.WriteAllText(metadata, length + "|" + expected, Encoding.UTF8);
                Console.WriteLine("{\"status\":\"SESSION_CREATED\",\"bytes_staged\":0," +
                                  "\"expected_sha256\":" + JsonString(expected) + "}");
                return 0;
            }
            string[] session = Session(metadata);
            long declared = Number(session[0]);
            string digest = session[1];
            if (action == "status")
            {
                long current = new FileInfo(partial).Length;
                if (current > declared) throw new InvalidOperationException("Partial overflow");
                string status = current == declared ? "COMPLETE_UNVERIFIED" : "PARTIAL";
                Console.WriteLine("{\"status\":" + JsonString(status) +
                    ",\"bytes_staged\":" + current +
                    ",\"remaining_bytes\":" + (declared - current) +
                    ",\"declared_size\":" + declared +
                    ",\"expected_sha256\":" + JsonString(digest) +
                    ",\"prefix_sha256\":" + JsonString(HashFile(partial)) +
                    ",\"ready_for_case_import\":false}");
                return 0;
            }
            if (action == "append")
            {
                long offset = Number(Option(args, pos, "--offset"));
                using (var fd = new FileStream(partial, FileMode.Open, FileAccess.Write, FileShare.None))
                {
                    if (offset != fd.Length)
                        throw new InvalidOperationException("Stale upload offset");
                    fd.Position = offset;
                    bool shouldDrop = Environment.GetEnvironmentVariable("ROCKY_TEST_DROP_ONCE") == "1";
                    string sentinel = Path.Combine(root, "dropped.flag");
                    if (shouldDrop && !File.Exists(sentinel))
                    {
                        byte[] first = new byte[37];
                        int read = Console.OpenStandardInput().Read(first, 0, first.Length);
                        fd.Write(first, 0, read);
                        fd.Flush(true);
                        File.WriteAllText(sentinel, "simulated", Encoding.ASCII);
                        Console.Error.WriteLine("synthetic interrupted SSH transport");
                        return 73;
                    }
                    byte[] buffer = new byte[65536];
                    int n;
                    Stream input = Console.OpenStandardInput();
                    while ((n = input.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        if (fd.Position + n > declared)
                            throw new InvalidOperationException("Excess evidence bytes");
                        fd.Write(buffer, 0, n);
                    }
                    fd.Flush(true);
                }
                long bytes = new FileInfo(partial).Length;
                Console.WriteLine("{\"status\":" +
                    JsonString(bytes == declared ? "COMPLETE_UNVERIFIED" : "PARTIAL") +
                    ",\"bytes_staged\":" + bytes + "}");
                return 0;
            }
            if (action == "finalize")
            {
                long expectedLength = Number(Option(args, pos, "--size"));
                string expected = Option(args, pos, "--sha256");
                string name = Option(args, pos, "--filename");
                if (!System.Text.RegularExpressions.Regex.IsMatch(name, "^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"))
                    throw new InvalidOperationException("Invalid filename");
                if (expectedLength != declared || expected != digest ||
                    new FileInfo(partial).Length != declared || HashFile(partial) != expected)
                    throw new InvalidOperationException("Final full SHA mismatch");
                File.Move(partial, Path.Combine(root, name));
                File.Delete(metadata);
                Console.WriteLine("{\"status\":\"STAGED\",\"filename\":" +
                    JsonString(name) + ",\"bytes\":" + expectedLength +
                    ",\"sha256\":" + JsonString(digest) + ",\"ready_for_case_import\":true}");
                return 0;
            }
            throw new InvalidOperationException("Unsupported synthetic action");
        }
        catch (Exception)
        {
            Console.Error.WriteLine("synthetic remote refused request");
            return 12;
        }
    }
}
