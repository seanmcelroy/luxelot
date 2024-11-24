using System.Collections.Concurrent;
using System.Diagnostics;
using Microsoft.Extensions.Logging;

namespace Luxelot;

public class LoopbackStream : Stream
{
    private ILogger? Logger { get; init; }
    private ConcurrentQueue<MemoryStream> _inner = new();
    private readonly Mutex _innerMutex = new();
    private int _readTimeout { get; set; } = int.MaxValue;
    private int _writeTimeout { get; set; } = int.MaxValue;

    public override bool CanRead => true;

    public override bool CanSeek => false;

    public override bool CanTimeout => true;

    public override bool CanWrite => true;

    public override long Length => throw new NotSupportedException();

    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

    public override int ReadTimeout { get => _readTimeout; set => _readTimeout = value; }

    public override int WriteTimeout { get => _writeTimeout; set => _writeTimeout = value; }

    public LoopbackStream(ILogger? logger)
    {
        Logger = logger;
    }

    public override void Flush() { }

    public override int Read(byte[] buffer, int offset, int count)
    {
        if (_inner.IsEmpty)
            return 0;
    beginning:
        var sw = new Stopwatch();
        sw.Start();
        var okay = _innerMutex.WaitOne(ReadTimeout);
        if (!okay)
            throw new IOException("Read timeout");
        else
            Logger?.LogTrace("Read took {ElapsedMilliseconds} to acquire mutex", sw.ElapsedMilliseconds);

        var peeked = _inner.TryPeek(out MemoryStream? peek);
        if (!peeked || peek == null)
        {
            // Nothing in queue, wait for data available
            _innerMutex.ReleaseMutex();
            Thread.Yield();
            goto beginning;
            //return 0;
        }

        var bytesAvailable = peek.Length;

        if (bytesAvailable <= count)
        {
            // There are bytes, and we want less than the next inner stream has, so give it all
            var bytes = peek.ToArray();
            _inner.TryDequeue(out MemoryStream? _);
            _innerMutex.ReleaseMutex();
            Array.Copy(bytes, buffer, peek.Length);
            return (int)peek.Length;
        }

        // There are bytes, and we want more than the next inner stream has, so give it all
        {
            var bytes = peek.ToArray();
            var bytesToPreserve = new byte[bytesAvailable - count];
            Array.Copy(bytes, buffer, count);
            Array.Copy(bytes, count, bytesToPreserve, 0, bytesToPreserve.Length);

            _inner.TryDequeue(out MemoryStream? _);
            var remainder = _inner.ToList();
            remainder.Insert(0, new MemoryStream(bytesToPreserve));
            _inner = new ConcurrentQueue<MemoryStream>(remainder); ;
            _innerMutex.ReleaseMutex();
            return count;
        }
    }

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count)
    {
        var sw = new Stopwatch();
        sw.Start();
        var okay = _innerMutex.WaitOne(WriteTimeout);
        if (!okay)
            throw new IOException("Write timeout");
        else
            Logger?.LogTrace("Write took {ElapsedMilliseconds} to acquire mutex", sw.ElapsedMilliseconds);

        var bytes = new byte[count];
        Array.Copy(buffer, offset, bytes, 0, count);
        _inner.Enqueue(new MemoryStream([.. bytes]));
        _innerMutex.ReleaseMutex();
    }

    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        var sw = new Stopwatch();
        sw.Start();
        var okay = _innerMutex.WaitOne(WriteTimeout);
        if (!okay)
            throw new IOException("Write timeout");
        else
            Logger?.LogTrace("WriteAsync took {ElapsedMilliseconds} to acquire mutex", sw.ElapsedMilliseconds);

        _inner.Enqueue(new MemoryStream([.. buffer.ToArray()]));
        _innerMutex.ReleaseMutex();
        return ValueTask.CompletedTask;
    }
}