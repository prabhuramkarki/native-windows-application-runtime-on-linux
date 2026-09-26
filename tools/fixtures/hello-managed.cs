// A managed (.NET) console program for the Wine Mono e2e test (crates/cli/tests/e2e_dotnet.rs), built by
// tools/build-managed-fixture.sh with Wine Mono's own C# compiler.
//
//   hello-managed [args...]   prints "hello from .NET <Environment.Version> args=<n>", then each argument on its
//                             own line; exit 7
//   hello-managed threads     4 threads add 100000 each to a shared counter under a lock; prints
//                             "threads total=400000"; exit 0 (JIT + threads)
//   hello-managed alloc       allocates and touches 64 MiB in 1 MiB arrays, forces a collection; prints
//                             "alloc ok 64 MiB"; exit 0 (GC)
using System;
using System.Threading;

static class HelloManaged
{
    static int Main(string[] args)
    {
        if (args.Length == 1 && args[0] == "threads")
        {
            object gate = new object();
            long total = 0;
            Thread[] threads = new Thread[4];
            for (int t = 0; t < threads.Length; t++)
            {
                threads[t] = new Thread(() =>
                {
                    for (int i = 0; i < 100000; i++)
                    {
                        lock (gate) { total++; }
                    }
                });
                threads[t].Start();
            }
            foreach (Thread t in threads) t.Join();
            Console.WriteLine("threads total=" + total);
            return 0;
        }
        if (args.Length == 1 && args[0] == "alloc")
        {
            byte[][] blocks = new byte[64][];
            long sum = 0;
            for (int i = 0; i < blocks.Length; i++)
            {
                blocks[i] = new byte[1 << 20];
                for (int j = 0; j < blocks[i].Length; j += 4096) blocks[i][j] = (byte)(i + 1);
            }
            GC.Collect();
            foreach (byte[] b in blocks) sum += b[0];
            // 1 + 2 + ... + 64: every block is still there after the collection.
            Console.WriteLine(sum == 64 * 65 / 2 ? "alloc ok 64 MiB" : "alloc BAD sum=" + sum);
            return sum == 64 * 65 / 2 ? 0 : 1;
        }
        Console.WriteLine("hello from .NET " + Environment.Version + " args=" + args.Length);
        foreach (string a in args) Console.WriteLine(a);
        return 7;
    }
}
