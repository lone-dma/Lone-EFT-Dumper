namespace LoneEftDumper.DMA
{
    internal static class Cache<T>
    {
        public static readonly Dictionary<ulong, T> Dict = new();
    }
}
