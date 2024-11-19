// <auto-generated>
//     Generated by the protocol buffer compiler.  DO NOT EDIT!
//     source: forwarded_message.proto
// </auto-generated>
#pragma warning disable 1591, 0612, 3021, 8981
#region Designer generated code

using pb = global::Google.Protobuf;
using pbc = global::Google.Protobuf.Collections;
using pbr = global::Google.Protobuf.Reflection;
using scg = global::System.Collections.Generic;
namespace Luxelot.Messages {

  /// <summary>Holder for reflection information generated from forwarded_message.proto</summary>
  public static partial class ForwardedMessageReflection {

    #region Descriptor
    /// <summary>File descriptor for forwarded_message.proto</summary>
    public static pbr::FileDescriptor Descriptor {
      get { return descriptor; }
    }
    private static pbr::FileDescriptor descriptor;

    static ForwardedMessageReflection() {
      byte[] descriptorData = global::System.Convert.FromBase64String(
          string.Concat(
            "Chdmb3J3YXJkZWRfbWVzc2FnZS5wcm90bxoZZ29vZ2xlL3Byb3RvYnVmL2Fu",
            "eS5wcm90byKvAQoQRm9yd2FyZGVkTWVzc2FnZRISCgpmb3J3YXJkX2lkGAEg",
            "ASgGEgsKA3R0bBgCIAEoBRIfChdzcmNfaWRlbnRpdHlfdGh1bWJwcmludBgD",
            "IAEoDBIfChdkc3RfaWRlbnRpdHlfdGh1bWJwcmludBgEIAEoDBIlCgdwYXls",
            "b2FkGAUgASgLMhQuZ29vZ2xlLnByb3RvYnVmLkFueRIRCglzaWduYXR1cmUY",
            "BiABKAxCE6oCEEx1eGVsb3QuTWVzc2FnZXNiBnByb3RvMw=="));
      descriptor = pbr::FileDescriptor.FromGeneratedCode(descriptorData,
          new pbr::FileDescriptor[] { global::Google.Protobuf.WellKnownTypes.AnyReflection.Descriptor, },
          new pbr::GeneratedClrTypeInfo(null, null, new pbr::GeneratedClrTypeInfo[] {
            new pbr::GeneratedClrTypeInfo(typeof(global::Luxelot.Messages.ForwardedMessage), global::Luxelot.Messages.ForwardedMessage.Parser, new[]{ "ForwardId", "Ttl", "SrcIdentityThumbprint", "DstIdentityThumbprint", "Payload", "Signature" }, null, null, null, null)
          }));
    }
    #endregion

  }
  #region Messages
  public sealed partial class ForwardedMessage : pb::IMessage<ForwardedMessage>
  #if !GOOGLE_PROTOBUF_REFSTRUCT_COMPATIBILITY_MODE
      , pb::IBufferMessage
  #endif
  {
    private static readonly pb::MessageParser<ForwardedMessage> _parser = new pb::MessageParser<ForwardedMessage>(() => new ForwardedMessage());
    private pb::UnknownFieldSet _unknownFields;
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public static pb::MessageParser<ForwardedMessage> Parser { get { return _parser; } }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public static pbr::MessageDescriptor Descriptor {
      get { return global::Luxelot.Messages.ForwardedMessageReflection.Descriptor.MessageTypes[0]; }
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    pbr::MessageDescriptor pb::IMessage.Descriptor {
      get { return Descriptor; }
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public ForwardedMessage() {
      OnConstruction();
    }

    partial void OnConstruction();

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public ForwardedMessage(ForwardedMessage other) : this() {
      forwardId_ = other.forwardId_;
      ttl_ = other.ttl_;
      srcIdentityThumbprint_ = other.srcIdentityThumbprint_;
      dstIdentityThumbprint_ = other.dstIdentityThumbprint_;
      payload_ = other.payload_ != null ? other.payload_.Clone() : null;
      signature_ = other.signature_;
      _unknownFields = pb::UnknownFieldSet.Clone(other._unknownFields);
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public ForwardedMessage Clone() {
      return new ForwardedMessage(this);
    }

    /// <summary>Field number for the "forward_id" field.</summary>
    public const int ForwardIdFieldNumber = 1;
    private ulong forwardId_;
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public ulong ForwardId {
      get { return forwardId_; }
      set {
        forwardId_ = value;
      }
    }

    /// <summary>Field number for the "ttl" field.</summary>
    public const int TtlFieldNumber = 2;
    private int ttl_;
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public int Ttl {
      get { return ttl_; }
      set {
        ttl_ = value;
      }
    }

    /// <summary>Field number for the "src_identity_thumbprint" field.</summary>
    public const int SrcIdentityThumbprintFieldNumber = 3;
    private pb::ByteString srcIdentityThumbprint_ = pb::ByteString.Empty;
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public pb::ByteString SrcIdentityThumbprint {
      get { return srcIdentityThumbprint_; }
      set {
        srcIdentityThumbprint_ = pb::ProtoPreconditions.CheckNotNull(value, "value");
      }
    }

    /// <summary>Field number for the "dst_identity_thumbprint" field.</summary>
    public const int DstIdentityThumbprintFieldNumber = 4;
    private pb::ByteString dstIdentityThumbprint_ = pb::ByteString.Empty;
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public pb::ByteString DstIdentityThumbprint {
      get { return dstIdentityThumbprint_; }
      set {
        dstIdentityThumbprint_ = pb::ProtoPreconditions.CheckNotNull(value, "value");
      }
    }

    /// <summary>Field number for the "payload" field.</summary>
    public const int PayloadFieldNumber = 5;
    private global::Google.Protobuf.WellKnownTypes.Any payload_;
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public global::Google.Protobuf.WellKnownTypes.Any Payload {
      get { return payload_; }
      set {
        payload_ = value;
      }
    }

    /// <summary>Field number for the "signature" field.</summary>
    public const int SignatureFieldNumber = 6;
    private pb::ByteString signature_ = pb::ByteString.Empty;
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public pb::ByteString Signature {
      get { return signature_; }
      set {
        signature_ = pb::ProtoPreconditions.CheckNotNull(value, "value");
      }
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public override bool Equals(object other) {
      return Equals(other as ForwardedMessage);
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public bool Equals(ForwardedMessage other) {
      if (ReferenceEquals(other, null)) {
        return false;
      }
      if (ReferenceEquals(other, this)) {
        return true;
      }
      if (ForwardId != other.ForwardId) return false;
      if (Ttl != other.Ttl) return false;
      if (SrcIdentityThumbprint != other.SrcIdentityThumbprint) return false;
      if (DstIdentityThumbprint != other.DstIdentityThumbprint) return false;
      if (!object.Equals(Payload, other.Payload)) return false;
      if (Signature != other.Signature) return false;
      return Equals(_unknownFields, other._unknownFields);
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public override int GetHashCode() {
      int hash = 1;
      if (ForwardId != 0UL) hash ^= ForwardId.GetHashCode();
      if (Ttl != 0) hash ^= Ttl.GetHashCode();
      if (SrcIdentityThumbprint.Length != 0) hash ^= SrcIdentityThumbprint.GetHashCode();
      if (DstIdentityThumbprint.Length != 0) hash ^= DstIdentityThumbprint.GetHashCode();
      if (payload_ != null) hash ^= Payload.GetHashCode();
      if (Signature.Length != 0) hash ^= Signature.GetHashCode();
      if (_unknownFields != null) {
        hash ^= _unknownFields.GetHashCode();
      }
      return hash;
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public override string ToString() {
      return pb::JsonFormatter.ToDiagnosticString(this);
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public void WriteTo(pb::CodedOutputStream output) {
    #if !GOOGLE_PROTOBUF_REFSTRUCT_COMPATIBILITY_MODE
      output.WriteRawMessage(this);
    #else
      if (ForwardId != 0UL) {
        output.WriteRawTag(9);
        output.WriteFixed64(ForwardId);
      }
      if (Ttl != 0) {
        output.WriteRawTag(16);
        output.WriteInt32(Ttl);
      }
      if (SrcIdentityThumbprint.Length != 0) {
        output.WriteRawTag(26);
        output.WriteBytes(SrcIdentityThumbprint);
      }
      if (DstIdentityThumbprint.Length != 0) {
        output.WriteRawTag(34);
        output.WriteBytes(DstIdentityThumbprint);
      }
      if (payload_ != null) {
        output.WriteRawTag(42);
        output.WriteMessage(Payload);
      }
      if (Signature.Length != 0) {
        output.WriteRawTag(50);
        output.WriteBytes(Signature);
      }
      if (_unknownFields != null) {
        _unknownFields.WriteTo(output);
      }
    #endif
    }

    #if !GOOGLE_PROTOBUF_REFSTRUCT_COMPATIBILITY_MODE
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    void pb::IBufferMessage.InternalWriteTo(ref pb::WriteContext output) {
      if (ForwardId != 0UL) {
        output.WriteRawTag(9);
        output.WriteFixed64(ForwardId);
      }
      if (Ttl != 0) {
        output.WriteRawTag(16);
        output.WriteInt32(Ttl);
      }
      if (SrcIdentityThumbprint.Length != 0) {
        output.WriteRawTag(26);
        output.WriteBytes(SrcIdentityThumbprint);
      }
      if (DstIdentityThumbprint.Length != 0) {
        output.WriteRawTag(34);
        output.WriteBytes(DstIdentityThumbprint);
      }
      if (payload_ != null) {
        output.WriteRawTag(42);
        output.WriteMessage(Payload);
      }
      if (Signature.Length != 0) {
        output.WriteRawTag(50);
        output.WriteBytes(Signature);
      }
      if (_unknownFields != null) {
        _unknownFields.WriteTo(ref output);
      }
    }
    #endif

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public int CalculateSize() {
      int size = 0;
      if (ForwardId != 0UL) {
        size += 1 + 8;
      }
      if (Ttl != 0) {
        size += 1 + pb::CodedOutputStream.ComputeInt32Size(Ttl);
      }
      if (SrcIdentityThumbprint.Length != 0) {
        size += 1 + pb::CodedOutputStream.ComputeBytesSize(SrcIdentityThumbprint);
      }
      if (DstIdentityThumbprint.Length != 0) {
        size += 1 + pb::CodedOutputStream.ComputeBytesSize(DstIdentityThumbprint);
      }
      if (payload_ != null) {
        size += 1 + pb::CodedOutputStream.ComputeMessageSize(Payload);
      }
      if (Signature.Length != 0) {
        size += 1 + pb::CodedOutputStream.ComputeBytesSize(Signature);
      }
      if (_unknownFields != null) {
        size += _unknownFields.CalculateSize();
      }
      return size;
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public void MergeFrom(ForwardedMessage other) {
      if (other == null) {
        return;
      }
      if (other.ForwardId != 0UL) {
        ForwardId = other.ForwardId;
      }
      if (other.Ttl != 0) {
        Ttl = other.Ttl;
      }
      if (other.SrcIdentityThumbprint.Length != 0) {
        SrcIdentityThumbprint = other.SrcIdentityThumbprint;
      }
      if (other.DstIdentityThumbprint.Length != 0) {
        DstIdentityThumbprint = other.DstIdentityThumbprint;
      }
      if (other.payload_ != null) {
        if (payload_ == null) {
          Payload = new global::Google.Protobuf.WellKnownTypes.Any();
        }
        Payload.MergeFrom(other.Payload);
      }
      if (other.Signature.Length != 0) {
        Signature = other.Signature;
      }
      _unknownFields = pb::UnknownFieldSet.MergeFrom(_unknownFields, other._unknownFields);
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public void MergeFrom(pb::CodedInputStream input) {
    #if !GOOGLE_PROTOBUF_REFSTRUCT_COMPATIBILITY_MODE
      input.ReadRawMessage(this);
    #else
      uint tag;
      while ((tag = input.ReadTag()) != 0) {
        switch(tag) {
          default:
            _unknownFields = pb::UnknownFieldSet.MergeFieldFrom(_unknownFields, input);
            break;
          case 9: {
            ForwardId = input.ReadFixed64();
            break;
          }
          case 16: {
            Ttl = input.ReadInt32();
            break;
          }
          case 26: {
            SrcIdentityThumbprint = input.ReadBytes();
            break;
          }
          case 34: {
            DstIdentityThumbprint = input.ReadBytes();
            break;
          }
          case 42: {
            if (payload_ == null) {
              Payload = new global::Google.Protobuf.WellKnownTypes.Any();
            }
            input.ReadMessage(Payload);
            break;
          }
          case 50: {
            Signature = input.ReadBytes();
            break;
          }
        }
      }
    #endif
    }

    #if !GOOGLE_PROTOBUF_REFSTRUCT_COMPATIBILITY_MODE
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    void pb::IBufferMessage.InternalMergeFrom(ref pb::ParseContext input) {
      uint tag;
      while ((tag = input.ReadTag()) != 0) {
        switch(tag) {
          default:
            _unknownFields = pb::UnknownFieldSet.MergeFieldFrom(_unknownFields, ref input);
            break;
          case 9: {
            ForwardId = input.ReadFixed64();
            break;
          }
          case 16: {
            Ttl = input.ReadInt32();
            break;
          }
          case 26: {
            SrcIdentityThumbprint = input.ReadBytes();
            break;
          }
          case 34: {
            DstIdentityThumbprint = input.ReadBytes();
            break;
          }
          case 42: {
            if (payload_ == null) {
              Payload = new global::Google.Protobuf.WellKnownTypes.Any();
            }
            input.ReadMessage(Payload);
            break;
          }
          case 50: {
            Signature = input.ReadBytes();
            break;
          }
        }
      }
    }
    #endif

  }

  #endregion

}

#endregion Designer generated code