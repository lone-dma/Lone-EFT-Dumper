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
            if (Cache<T>.Dict.TryGetValue(address, out T cached))
            {
                return cached;
            }
            return Cache<T>.Dict[address] = Vmm.MemReadValue<T>(PID, address);
        }

        public static T[] Read<T>(ulong address, int cb)
            where T : unmanaged
        {
            if (Cache<T[]>.Dict.TryGetValue(address, out T[] cached))
            {
                return cached;
            }
            return Cache<T[]>.Dict[address] = Vmm.MemReadArray<T>(PID, address, cb);
        }

        public static string ReadString(ulong address, int length = 128)
        {
            if (Cache<string>.Dict.TryGetValue(address, out string cached))
            {
                return cached;
            }
            return Cache<string>.Dict[address] = Vmm.MemReadString(PID, address, length, Encoding.ASCII);
        }
    }
}
