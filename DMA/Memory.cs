global using LoneEftDumper.DMA;
global using static LoneEftDumper.DMA.Memory;
using System.Text;
using VmmSharpEx;

namespace LoneEftDumper.DMA
{
    internal static class Memory
    {
        private const string MMAP_FILE = "mmap.txt";
        /// <summary>
        /// Backing VMM instance.
        /// </summary>
        public static Vmm Vmm { get; private set; }
        /// <summary>
        /// PID for EscapeFromTarkov.exe
        /// </summary>
        public static uint PID { get; private set; }

        internal static void InitializeMemoryModule()
        {
            Console.WriteLine("Initializing DMA...");
            List<string> args = [
                "-device",
                "FPGA",
                "-norefresh", // Maybe remove this if it causes issues
                "-waitinitialize",
                "-printf",
                "-v"
            ];
            if (File.Exists(MMAP_FILE))
            {
                args.Add("-memmap");
                args.Add(MMAP_FILE);
                Vmm = new Vmm(args: args.ToArray())
                {
                    EnableMemoryWriting = false
                };
            }
            else
            {
                Vmm = new Vmm(args: args.ToArray())
                {
                    EnableMemoryWriting = false
                };
                _ = Vmm.GetMemoryMap(
                    applyMap: true,
                    outputFile: MMAP_FILE);
            }
            if (!Vmm.PidGetFromName("EscapeFromTarkov.exe", out uint pid))
                throw new InvalidOperationException("Could not find EscapeFromTarkov.exe process.");
            PID = pid;
            Console.WriteLine($"DMA Initialized. EscapeFromTarkov.exe running @ PID {pid}.");
        }

        public static T Read<T>(ulong address)
            where T : unmanaged
        {
            return Vmm.MemReadValue<T>(PID, address);
        }

        public static bool Read<T>(ulong address, Span<T> span)
            where T : unmanaged
        {
            return Vmm.MemReadSpan(PID, address, span);
        }

        public static string ReadString(ulong address, int length = 128) => Vmm.MemReadString(PID, address, length, Encoding.ASCII);
    }
}
