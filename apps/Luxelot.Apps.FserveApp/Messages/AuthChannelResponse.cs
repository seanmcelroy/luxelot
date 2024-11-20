// <auto-generated>
//     Generated by the protocol buffer compiler.  DO NOT EDIT!
//     source: auth_channel_response.proto
// </auto-generated>
#pragma warning disable 1591, 0612, 3021, 8981
#region Designer generated code

using pb = global::Google.Protobuf;
using pbc = global::Google.Protobuf.Collections;
using pbr = global::Google.Protobuf.Reflection;
using scg = global::System.Collections.Generic;
namespace Luxelot.Messages {

  /// <summary>Holder for reflection information generated from auth_channel_response.proto</summary>
  public static partial class AuthChannelResponseReflection {

    #region Descriptor
    /// <summary>File descriptor for auth_channel_response.proto</summary>
    public static pbr::FileDescriptor Descriptor {
      get { return descriptor; }
    }
    private static pbr::FileDescriptor descriptor;

    static AuthChannelResponseReflection() {
      byte[] descriptorData = global::System.Convert.FromBase64String(
          string.Concat(
            "ChthdXRoX2NoYW5uZWxfcmVzcG9uc2UucHJvdG8ieAoTQXV0aENoYW5uZWxS",
            "ZXNwb25zZRIQCghwcm90X3ZlchgBIAEoDRIOCgZzdGF0dXMYAiABKAUSFgoO",
            "c3RhdHVzX21lc3NhZ2UYAyABKAkSEwoLY2lwaGVyX3RleHQYBCABKAwSEgoK",
            "aWRfcHViX2tleRgFIAEoDEITqgIQTHV4ZWxvdC5NZXNzYWdlc2IGcHJvdG8z"));
      descriptor = pbr::FileDescriptor.FromGeneratedCode(descriptorData,
          new pbr::FileDescriptor[] { },
          new pbr::GeneratedClrTypeInfo(null, null, new pbr::GeneratedClrTypeInfo[] {
            new pbr::GeneratedClrTypeInfo(typeof(global::Luxelot.Messages.AuthChannelResponse), global::Luxelot.Messages.AuthChannelResponse.Parser, new[]{ "ProtVer", "Status", "StatusMessage", "CipherText", "IdPubKey" }, null, null, null, null)
          }));
    }
    #endregion

  }
  #region Messages
  public sealed partial class AuthChannelResponse : pb::IMessage<AuthChannelResponse>
  #if !GOOGLE_PROTOBUF_REFSTRUCT_COMPATIBILITY_MODE
      , pb::IBufferMessage
  #endif
  {
    private static readonly pb::MessageParser<AuthChannelResponse> _parser = new pb::MessageParser<AuthChannelResponse>(() => new AuthChannelResponse());
    private pb::UnknownFieldSet _unknownFields;
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public static pb::MessageParser<AuthChannelResponse> Parser { get { return _parser; } }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public static pbr::MessageDescriptor Descriptor {
      get { return global::Luxelot.Messages.AuthChannelResponseReflection.Descriptor.MessageTypes[0]; }
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    pbr::MessageDescriptor pb::IMessage.Descriptor {
      get { return Descriptor; }
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public AuthChannelResponse() {
      OnConstruction();
    }

    partial void OnConstruction();

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public AuthChannelResponse(AuthChannelResponse other) : this() {
      protVer_ = other.protVer_;
      status_ = other.status_;
      statusMessage_ = other.statusMessage_;
      cipherText_ = other.cipherText_;
      idPubKey_ = other.idPubKey_;
      _unknownFields = pb::UnknownFieldSet.Clone(other._unknownFields);
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public AuthChannelResponse Clone() {
      return new AuthChannelResponse(this);
    }

    /// <summary>Field number for the "prot_ver" field.</summary>
    public const int ProtVerFieldNumber = 1;
    private uint protVer_;
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public uint ProtVer {
      get { return protVer_; }
      set {
        protVer_ = value;
      }
    }

    /// <summary>Field number for the "status" field.</summary>
    public const int StatusFieldNumber = 2;
    private int status_;
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public int Status {
      get { return status_; }
      set {
        status_ = value;
      }
    }

    /// <summary>Field number for the "status_message" field.</summary>
    public const int StatusMessageFieldNumber = 3;
    private string statusMessage_ = "";
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public string StatusMessage {
      get { return statusMessage_; }
      set {
        statusMessage_ = pb::ProtoPreconditions.CheckNotNull(value, "value");
      }
    }

    /// <summary>Field number for the "cipher_text" field.</summary>
    public const int CipherTextFieldNumber = 4;
    private pb::ByteString cipherText_ = pb::ByteString.Empty;
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public pb::ByteString CipherText {
      get { return cipherText_; }
      set {
        cipherText_ = pb::ProtoPreconditions.CheckNotNull(value, "value");
      }
    }

    /// <summary>Field number for the "id_pub_key" field.</summary>
    public const int IdPubKeyFieldNumber = 5;
    private pb::ByteString idPubKey_ = pb::ByteString.Empty;
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public pb::ByteString IdPubKey {
      get { return idPubKey_; }
      set {
        idPubKey_ = pb::ProtoPreconditions.CheckNotNull(value, "value");
      }
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public override bool Equals(object other) {
      return Equals(other as AuthChannelResponse);
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public bool Equals(AuthChannelResponse other) {
      if (ReferenceEquals(other, null)) {
        return false;
      }
      if (ReferenceEquals(other, this)) {
        return true;
      }
      if (ProtVer != other.ProtVer) return false;
      if (Status != other.Status) return false;
      if (StatusMessage != other.StatusMessage) return false;
      if (CipherText != other.CipherText) return false;
      if (IdPubKey != other.IdPubKey) return false;
      return Equals(_unknownFields, other._unknownFields);
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public override int GetHashCode() {
      int hash = 1;
      if (ProtVer != 0) hash ^= ProtVer.GetHashCode();
      if (Status != 0) hash ^= Status.GetHashCode();
      if (StatusMessage.Length != 0) hash ^= StatusMessage.GetHashCode();
      if (CipherText.Length != 0) hash ^= CipherText.GetHashCode();
      if (IdPubKey.Length != 0) hash ^= IdPubKey.GetHashCode();
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
      if (ProtVer != 0) {
        output.WriteRawTag(8);
        output.WriteUInt32(ProtVer);
      }
      if (Status != 0) {
        output.WriteRawTag(16);
        output.WriteInt32(Status);
      }
      if (StatusMessage.Length != 0) {
        output.WriteRawTag(26);
        output.WriteString(StatusMessage);
      }
      if (CipherText.Length != 0) {
        output.WriteRawTag(34);
        output.WriteBytes(CipherText);
      }
      if (IdPubKey.Length != 0) {
        output.WriteRawTag(42);
        output.WriteBytes(IdPubKey);
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
      if (ProtVer != 0) {
        output.WriteRawTag(8);
        output.WriteUInt32(ProtVer);
      }
      if (Status != 0) {
        output.WriteRawTag(16);
        output.WriteInt32(Status);
      }
      if (StatusMessage.Length != 0) {
        output.WriteRawTag(26);
        output.WriteString(StatusMessage);
      }
      if (CipherText.Length != 0) {
        output.WriteRawTag(34);
        output.WriteBytes(CipherText);
      }
      if (IdPubKey.Length != 0) {
        output.WriteRawTag(42);
        output.WriteBytes(IdPubKey);
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
      if (ProtVer != 0) {
        size += 1 + pb::CodedOutputStream.ComputeUInt32Size(ProtVer);
      }
      if (Status != 0) {
        size += 1 + pb::CodedOutputStream.ComputeInt32Size(Status);
      }
      if (StatusMessage.Length != 0) {
        size += 1 + pb::CodedOutputStream.ComputeStringSize(StatusMessage);
      }
      if (CipherText.Length != 0) {
        size += 1 + pb::CodedOutputStream.ComputeBytesSize(CipherText);
      }
      if (IdPubKey.Length != 0) {
        size += 1 + pb::CodedOutputStream.ComputeBytesSize(IdPubKey);
      }
      if (_unknownFields != null) {
        size += _unknownFields.CalculateSize();
      }
      return size;
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public void MergeFrom(AuthChannelResponse other) {
      if (other == null) {
        return;
      }
      if (other.ProtVer != 0) {
        ProtVer = other.ProtVer;
      }
      if (other.Status != 0) {
        Status = other.Status;
      }
      if (other.StatusMessage.Length != 0) {
        StatusMessage = other.StatusMessage;
      }
      if (other.CipherText.Length != 0) {
        CipherText = other.CipherText;
      }
      if (other.IdPubKey.Length != 0) {
        IdPubKey = other.IdPubKey;
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
          case 8: {
            ProtVer = input.ReadUInt32();
            break;
          }
          case 16: {
            Status = input.ReadInt32();
            break;
          }
          case 26: {
            StatusMessage = input.ReadString();
            break;
          }
          case 34: {
            CipherText = input.ReadBytes();
            break;
          }
          case 42: {
            IdPubKey = input.ReadBytes();
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
          case 8: {
            ProtVer = input.ReadUInt32();
            break;
          }
          case 16: {
            Status = input.ReadInt32();
            break;
          }
          case 26: {
            StatusMessage = input.ReadString();
            break;
          }
          case 34: {
            CipherText = input.ReadBytes();
            break;
          }
          case 42: {
            IdPubKey = input.ReadBytes();
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