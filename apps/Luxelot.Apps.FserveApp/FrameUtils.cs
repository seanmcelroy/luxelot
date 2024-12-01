using System.Collections.Immutable;
using Google.Protobuf;
using Luxelot.Apps.Common;
using Luxelot.Apps.FserveApp.Messages;
using Microsoft.Extensions.Logging;

namespace Luxelot.Apps.FserveApp;

internal static class FrameUtils
{
    internal static ServerFrame WrapServerFrame(IAppContext appContext, IMessage message, ImmutableArray<byte> sessionKey)
    {
        var message_bytes = message.ToByteArray();
        var envelope = appContext.EncryptEnvelope(message_bytes, sessionKey, appContext.Logger);

        ServerFrameType frameType;
        if (message is AuthUserChallenge)
            frameType = ServerFrameType.AuthUserChallenge;
        else if (message is Status)
            frameType = ServerFrameType.Status;
        else if (message is ListResponse)
            frameType = ServerFrameType.ListResponse;
        else if (message is DownloadReady)
            frameType = ServerFrameType.DownloadReady;
        else if (message is ChunkResponse)
            frameType = ServerFrameType.ChunkResponse;
        else
        {
            appContext?.Logger?.LogError("Unknown frame type: {TypeName}", message.GetType().FullName);
            throw new NotImplementedException($"Unknown frame type: {message.GetType().FullName}");
        }

        return new ServerFrame
        {
            Nonce = ByteString.CopyFrom(envelope.Nonce),
            Ciphertext = ByteString.CopyFrom(envelope.Ciphertext),
            Tag = ByteString.CopyFrom(envelope.Tag),
            AssociatedData = ByteString.CopyFrom(envelope.AssociatedData),
            FrameType = frameType
        };
    }

    internal static ClientFrame WrapClientFrame(IAppContext appContext, IMessage message, ImmutableArray<byte> sessionKey)
    {
        var message_bytes = message.ToByteArray();
        var envelope = appContext.EncryptEnvelope(message_bytes, sessionKey, appContext.Logger);

        ClientFrameType frameType;
        if (message is AuthUserBegin)
            frameType = ClientFrameType.AuthUserBegin;
        else if (message is AuthUserResponse)
            frameType = ClientFrameType.AuthUserResponse;
        else if (message is ListRequest)
            frameType = ClientFrameType.ListRequest;
        else if (message is ChangeDirectory)
            frameType = ClientFrameType.ChangeDirectory;
        else if (message is PrepareDownload)
            frameType = ClientFrameType.PrepareDownload;
        else if (message is ChunkRequest)
            frameType = ClientFrameType.ChunkRequest;
        else
            throw new NotImplementedException($"Unknown frame type: {message.GetType().FullName}");

        return new ClientFrame
        {
            Nonce = ByteString.CopyFrom(envelope.Nonce),
            Ciphertext = ByteString.CopyFrom(envelope.Ciphertext),
            Tag = ByteString.CopyFrom(envelope.Tag),
            AssociatedData = ByteString.CopyFrom(envelope.AssociatedData),
            FrameType = frameType
        };
    }

    internal static IMessage UnwrapFrame(IAppContext appContext, ClientFrame frame, ReadOnlySpan<byte> sessionKey)
    {
        // Marshal into an envelope to use shared method in IAppContext
        var envelope = new Envelope
        {
            Nonce = frame.Nonce.Span,
            Ciphertext = frame.Ciphertext.Span,
            Tag = frame.Tag.Span,
            AssociatedData = frame.AssociatedData.Span
        };

        var decrypted = appContext.DecryptEnvelope(envelope, sessionKey, appContext.Logger);

        return frame.FrameType switch
        {
            ClientFrameType.AuthUserBegin => AuthUserBegin.Parser.ParseFrom(decrypted),
            ClientFrameType.AuthUserResponse => AuthUserResponse.Parser.ParseFrom(decrypted),
            ClientFrameType.ListRequest => ListRequest.Parser.ParseFrom(decrypted),
            ClientFrameType.ChangeDirectory => ChangeDirectory.Parser.ParseFrom(decrypted),
            ClientFrameType.PrepareDownload => PrepareDownload.Parser.ParseFrom(decrypted),
            ClientFrameType.ChunkRequest => ChunkRequest.Parser.ParseFrom(decrypted),
            _ => throw new NotImplementedException($"Unknown frame type: {frame.FrameType}"),
        };
    }

    internal static IMessage UnwrapFrame(IAppContext appContext, ServerFrame frame, ReadOnlySpan<byte> sessionKey)
    {
        // Marshal into an envelope to use shared method in IAppContext
        var envelope = new Envelope
        {
            Nonce = frame.Nonce.Span,
            Ciphertext = frame.Ciphertext.Span,
            Tag = frame.Tag.Span,
            AssociatedData = frame.AssociatedData.Span
        };

        var decrypted = appContext.DecryptEnvelope(envelope, sessionKey, appContext.Logger);

        return frame.FrameType switch
        {
            ServerFrameType.AuthUserChallenge => AuthUserChallenge.Parser.ParseFrom(decrypted),
            ServerFrameType.Status => Status.Parser.ParseFrom(decrypted),
            ServerFrameType.ListResponse => ListResponse.Parser.ParseFrom(decrypted),
            ServerFrameType.DownloadReady => DownloadReady.Parser.ParseFrom(decrypted),
            ServerFrameType.ChunkResponse => ChunkResponse.Parser.ParseFrom(decrypted),
            _ => throw new NotImplementedException($"Unknown frame type: {frame.FrameType}"),
        };
    }
}