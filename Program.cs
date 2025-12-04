using LoneEftDumper.SDK;

namespace LoneEftDumper
{
    internal class Program
    {
        static void Main()
        {
            try
            {
                InitializeMemoryModule();
                IL2CPP.Init();
                Dumper.Dump();
                Console.WriteLine("Done.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"ERROR - Unhandled Exception: {ex}");
            }
            finally
            {
                Vmm?.Dispose();
                Console.WriteLine("Press any key to exit...");
                Console.ReadKey(intercept: true);
            }
        }
    }
}
