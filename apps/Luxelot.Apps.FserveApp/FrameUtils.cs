using System.Collections.Immutable;
using Google.Protobuf;
using Luxelot.App.Common.Messages;
using Luxelot.Apps.Common;
using Luxelot.Apps.FserveApp.Messages;
using Microsoft.Extensions.Logging;

namespace Luxelot.Apps.FserveApp;

public static class FrameUtils
{
    public static ServerFrame WrapServerFrame(IAppContext appContext, IMessage message, ImmutableArray<byte> sessionKey)
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
        else
        {
            appContext?.Logger?.LogError("Unknown frame type: {TypeName}", message.GetType().FullName);
            throw new NotImplementedException($"Unknown frame type: {message.GetType().FullName}");
        }

        return new ServerFrame
        {
            Nonce = envelope.Nonce,
            Ciphertext = envelope.Ciphertext,
            Tag = envelope.Tag,
            AssociatedData = envelope.AssociatedData,
            FrameType = frameType
        };
    }

    public static ClientFrame WrapClientFrame(IAppContext appContext, IMessage message, ImmutableArray<byte> sessionKey)
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
        else if (message is ChangeDirectoryRequest)
            frameType = ClientFrameType.ChangeDirectoryRequest;
        else
            throw new NotImplementedException($"Unknown frame type: {message.GetType().FullName}");

        return new ClientFrame
        {
            Nonce = envelope.Nonce,
            Ciphertext = envelope.Ciphertext,
            Tag = envelope.Tag,
            AssociatedData = envelope.AssociatedData,
            FrameType = frameType
        };
    }

    public static IMessage UnwrapFrame(IAppContext appContext, ClientFrame frame, ImmutableArray<byte> sessionKey)
    {
        // Marshal into an envelope to use shared method in IAppContext
        var envelope = new Envelope
        {
            Nonce = frame.Nonce,
            Ciphertext = frame.Ciphertext,
            Tag = frame.Tag,
            AssociatedData = frame.AssociatedData
        };

        var decrypted = appContext.DecryptEnvelope(envelope, sessionKey, appContext.Logger);

        return frame.FrameType switch
        {
            ClientFrameType.AuthUserBegin => AuthUserBegin.Parser.ParseFrom(decrypted),
            ClientFrameType.AuthUserResponse => AuthUserResponse.Parser.ParseFrom(decrypted),
            ClientFrameType.ListRequest => ListRequest.Parser.ParseFrom(decrypted),
            ClientFrameType.ChangeDirectoryRequest => ChangeDirectoryRequest.Parser.ParseFrom(decrypted),
            _ => throw new NotImplementedException($"Unknown frame type: {frame.FrameType}"),
        };
    }

    public static IMessage UnwrapFrame(IAppContext appContext, ServerFrame frame, ImmutableArray<byte> sessionKey)
    {
        // Marshal into an envelope to use shared method in IAppContext
        var envelope = new Envelope
        {
            Nonce = frame.Nonce,
            Ciphertext = frame.Ciphertext,
            Tag = frame.Tag,
            AssociatedData = frame.AssociatedData
        };

        var decrypted = appContext.DecryptEnvelope(envelope, sessionKey, appContext.Logger);

        return frame.FrameType switch
        {
            ServerFrameType.AuthUserChallenge => AuthUserChallenge.Parser.ParseFrom(decrypted),
            ServerFrameType.Status => Status.Parser.ParseFrom(decrypted),
            ServerFrameType.ListResponse => ListResponse.Parser.ParseFrom(decrypted),
            _ => throw new NotImplementedException($"Unknown frame type: {frame.FrameType}"),
        };
    }
}