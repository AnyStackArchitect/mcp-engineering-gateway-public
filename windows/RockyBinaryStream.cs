// Compiled locally by Send-RockyEvidenceResume.ps1 under Windows PowerShell 5.1+.
// No credentials or evidence are written to this helper's output.
// It sends raw file bytes to ssh.exe stdin; PowerShell's text pipeline is not used.
using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading.Tasks;

public static class RockyBinaryStream
{
    private static string ReadBounded(StreamReader reader, int limit)
    {
        var builder = new StringBuilder();
        var buffer = new char[512];
        int count;
        while ((count = reader.Read(buffer, 0, buffer.Length)) > 0)
        {
            if (builder.Length + count > limit)
                throw new InvalidOperationException("Remote command output exceeded the limit");
            builder.Append(buffer, 0, count);
        }
        return builder.ToString();
    }

    private static int Remaining(Stopwatch clock, int maxMilliseconds)
    {
        long remaining = (long)maxMilliseconds - clock.ElapsedMilliseconds;
        if (remaining <= 0)
            throw new TimeoutException("SSH binary transfer exceeded its deadline");
        return (int)Math.Min(remaining, int.MaxValue);
    }

    private static void Stop(Process process)
    {
        try
        {
            if (!process.HasExited)
                process.Kill();
        }
        catch (InvalidOperationException) { }
        catch (System.ComponentModel.Win32Exception) { }
        try { process.WaitForExit(5000); }
        catch (InvalidOperationException) { }
    }

    public static string Append(string executable, string arguments, Stream source,
                                long offset, int timeoutMilliseconds)
    {
        if (String.IsNullOrEmpty(executable) || String.IsNullOrEmpty(arguments) ||
            source == null || !source.CanRead || !source.CanSeek ||
            offset < 0 || offset > source.Length || timeoutMilliseconds < 1000)
            throw new ArgumentException("Invalid binary append request");
        var start = new ProcessStartInfo(executable, arguments);
        start.UseShellExecute = false;
        start.CreateNoWindow = true;
        start.RedirectStandardInput = true;
        start.RedirectStandardOutput = true;
        start.RedirectStandardError = true;
        start.StandardOutputEncoding = Encoding.UTF8;
        start.StandardErrorEncoding = Encoding.UTF8;
        using (var process = new Process())
        {
            process.StartInfo = start;
            var stopwatch = Stopwatch.StartNew();
            try
            {
                // .NET Framework Process.StandardInput initializes an auto-
                // flushed StreamWriter using Console.InputEncoding. On Windows
                // this may be a UTF-8 encoder WITH preamble: its three BOM
                // bytes are emitted into BaseStream before our first Write.
                // Temporarily choose a BOM-free input encoder while Start()
                // allocates that writer, then restore the operator console.
                Encoding priorInput = Console.InputEncoding;
                try
                {
                    Console.InputEncoding = new UTF8Encoding(false);
                    if (!process.Start())
                        throw new IOException("SSH binary transfer did not start");
                }
                finally
                {
                    Console.InputEncoding = priorInput;
                }
                // Drain both outputs concurrently to prevent an SSH child blocking
                // on a full stderr/stdout pipe. Only bounded UTF-8 metadata exists.
                Task<string> output = Task.Run(() => ReadBounded(process.StandardOutput, 8192));
                Task<string> errors = Task.Run(() => ReadBounded(process.StandardError, 8192));
                source.Seek(offset, SeekOrigin.Begin);
                using (var remoteInput = process.StandardInput.BaseStream)
                {
                    byte[] buffer = new byte[1024 * 1024];
                    int read;
                    while ((read = source.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        var write = remoteInput.WriteAsync(buffer, 0, read);
                        if (!write.Wait(Remaining(stopwatch, timeoutMilliseconds)))
                            throw new TimeoutException("SSH binary stdin stalled");
                    }
                    var flush = remoteInput.FlushAsync();
                    if (!flush.Wait(Remaining(stopwatch, timeoutMilliseconds)))
                        throw new TimeoutException("SSH binary stdin flush stalled");
                }
                if (!process.WaitForExit(Remaining(stopwatch, timeoutMilliseconds)))
                    throw new TimeoutException("SSH binary transfer did not finish");
                if (!Task.WaitAll(new Task[] { output, errors },
                                  Remaining(stopwatch, timeoutMilliseconds)))
                    throw new TimeoutException("SSH output collection did not finish");
                if (process.ExitCode != 0)
                    throw new IOException("Remote append rejected or SSH transport disconnected");
                string result = output.Result.Trim();
                if (result.Length == 0 || result.Length > 8192)
                    throw new IOException("Remote append metadata missing or oversized");
                return result;
            }
            catch
            {
                Stop(process);
                throw;
            }
        }
    }
}
