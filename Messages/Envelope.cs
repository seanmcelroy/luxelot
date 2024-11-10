// <auto-generated>
//     Generated by the protocol buffer compiler.  DO NOT EDIT!
//     source: envelope.proto
// </auto-generated>
#pragma warning disable 1591, 0612, 3021, 8981
#region Designer generated code

using pb = global::Google.Protobuf;
using pbc = global::Google.Protobuf.Collections;
using pbr = global::Google.Protobuf.Reflection;
using scg = global::System.Collections.Generic;
namespace Luxelot.Messages {

  /// <summary>Holder for reflection information generated from envelope.proto</summary>
  public static partial class EnvelopeReflection {

    #region Descriptor
    /// <summary>File descriptor for envelope.proto</summary>
    public static pbr::FileDescriptor Descriptor {
      get { return descriptor; }
    }
    private static pbr::FileDescriptor descriptor;

    static EnvelopeReflection() {
      byte[] descriptorData = global::System.Convert.FromBase64String(
          string.Concat(
            "Cg5lbnZlbG9wZS5wcm90byJTCghFbnZlbG9wZRINCgVub25jZRgBIAEoDBIS",
            "CgpjaXBoZXJ0ZXh0GAIgASgMEgsKA3RhZxgDIAEoDBIXCg9hc3NvY2lhdGVk",
            "X2RhdGEYBCABKAxCE6oCEEx1eGVsb3QuTWVzc2FnZXNiBnByb3RvMw=="));
      descriptor = pbr::FileDescriptor.FromGeneratedCode(descriptorData,
          new pbr::FileDescriptor[] { },
          new pbr::GeneratedClrTypeInfo(null, null, new pbr::GeneratedClrTypeInfo[] {
            new pbr::GeneratedClrTypeInfo(typeof(global::Luxelot.Messages.Envelope), global::Luxelot.Messages.Envelope.Parser, new[]{ "Nonce", "Ciphertext", "Tag", "AssociatedData" }, null, null, null, null)
          }));
    }
    #endregion

  }
  #region Messages
  public sealed partial class Envelope : pb::IMessage<Envelope>
  #if !GOOGLE_PROTOBUF_REFSTRUCT_COMPATIBILITY_MODE
      , pb::IBufferMessage
  #endif
  {
    private static readonly pb::MessageParser<Envelope> _parser = new pb::MessageParser<Envelope>(() => new Envelope());
    private pb::UnknownFieldSet _unknownFields;
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public static pb::MessageParser<Envelope> Parser { get { return _parser; } }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public static pbr::MessageDescriptor Descriptor {
      get { return global::Luxelot.Messages.EnvelopeReflection.Descriptor.MessageTypes[0]; }
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    pbr::MessageDescriptor pb::IMessage.Descriptor {
      get { return Descriptor; }
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public Envelope() {
      OnConstruction();
    }

    partial void OnConstruction();

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public Envelope(Envelope other) : this() {
      nonce_ = other.nonce_;
      ciphertext_ = other.ciphertext_;
      tag_ = other.tag_;
      associatedData_ = other.associatedData_;
      _unknownFields = pb::UnknownFieldSet.Clone(other._unknownFields);
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public Envelope Clone() {
      return new Envelope(this);
    }

    /// <summary>Field number for the "nonce" field.</summary>
    public const int NonceFieldNumber = 1;
    private pb::ByteString nonce_ = pb::ByteString.Empty;
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public pb::ByteString Nonce {
      get { return nonce_; }
      set {
        nonce_ = pb::ProtoPreconditions.CheckNotNull(value, "value");
      }
    }

    /// <summary>Field number for the "ciphertext" field.</summary>
    public const int CiphertextFieldNumber = 2;
    private pb::ByteString ciphertext_ = pb::ByteString.Empty;
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public pb::ByteString Ciphertext {
      get { return ciphertext_; }
      set {
        ciphertext_ = pb::ProtoPreconditions.CheckNotNull(value, "value");
      }
    }

    /// <summary>Field number for the "tag" field.</summary>
    public const int TagFieldNumber = 3;
    private pb::ByteString tag_ = pb::ByteString.Empty;
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public pb::ByteString Tag {
      get { return tag_; }
      set {
        tag_ = pb::ProtoPreconditions.CheckNotNull(value, "value");
      }
    }

    /// <summary>Field number for the "associated_data" field.</summary>
    public const int AssociatedDataFieldNumber = 4;
    private pb::ByteString associatedData_ = pb::ByteString.Empty;
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public pb::ByteString AssociatedData {
      get { return associatedData_; }
      set {
        associatedData_ = pb::ProtoPreconditions.CheckNotNull(value, "value");
      }
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public override bool Equals(object other) {
      return Equals(other as Envelope);
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public bool Equals(Envelope other) {
      if (ReferenceEquals(other, null)) {
        return false;
      }
      if (ReferenceEquals(other, this)) {
        return true;
      }
      if (Nonce != other.Nonce) return false;
      if (Ciphertext != other.Ciphertext) return false;
      if (Tag != other.Tag) return false;
      if (AssociatedData != other.AssociatedData) return false;
      return Equals(_unknownFields, other._unknownFields);
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public override int GetHashCode() {
      int hash = 1;
      if (Nonce.Length != 0) hash ^= Nonce.GetHashCode();
      if (Ciphertext.Length != 0) hash ^= Ciphertext.GetHashCode();
      if (Tag.Length != 0) hash ^= Tag.GetHashCode();
      if (AssociatedData.Length != 0) hash ^= AssociatedData.GetHashCode();
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
      if (Nonce.Length != 0) {
        output.WriteRawTag(10);
        output.WriteBytes(Nonce);
      }
      if (Ciphertext.Length != 0) {
        output.WriteRawTag(18);
        output.WriteBytes(Ciphertext);
      }
      if (Tag.Length != 0) {
        output.WriteRawTag(26);
        output.WriteBytes(Tag);
      }
      if (AssociatedData.Length != 0) {
        output.WriteRawTag(34);
        output.WriteBytes(AssociatedData);
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
      if (Nonce.Length != 0) {
        output.WriteRawTag(10);
        output.WriteBytes(Nonce);
      }
      if (Ciphertext.Length != 0) {
        output.WriteRawTag(18);
        output.WriteBytes(Ciphertext);
      }
      if (Tag.Length != 0) {
        output.WriteRawTag(26);
        output.WriteBytes(Tag);
      }
      if (AssociatedData.Length != 0) {
        output.WriteRawTag(34);
        output.WriteBytes(AssociatedData);
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
      if (Nonce.Length != 0) {
        size += 1 + pb::CodedOutputStream.ComputeBytesSize(Nonce);
      }
      if (Ciphertext.Length != 0) {
        size += 1 + pb::CodedOutputStream.ComputeBytesSize(Ciphertext);
      }
      if (Tag.Length != 0) {
        size += 1 + pb::CodedOutputStream.ComputeBytesSize(Tag);
      }
      if (AssociatedData.Length != 0) {
        size += 1 + pb::CodedOutputStream.ComputeBytesSize(AssociatedData);
      }
      if (_unknownFields != null) {
        size += _unknownFields.CalculateSize();
      }
      return size;
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public void MergeFrom(Envelope other) {
      if (other == null) {
        return;
      }
      if (other.Nonce.Length != 0) {
        Nonce = other.Nonce;
      }
      if (other.Ciphertext.Length != 0) {
        Ciphertext = other.Ciphertext;
      }
      if (other.Tag.Length != 0) {
        Tag = other.Tag;
      }
      if (other.AssociatedData.Length != 0) {
        AssociatedData = other.AssociatedData;
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
          case 10: {
            Nonce = input.ReadBytes();
            break;
          }
          case 18: {
            Ciphertext = input.ReadBytes();
            break;
          }
          case 26: {
            Tag = input.ReadBytes();
            break;
          }
          case 34: {
            AssociatedData = input.ReadBytes();
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
          case 10: {
            Nonce = input.ReadBytes();
            break;
          }
          case 18: {
            Ciphertext = input.ReadBytes();
            break;
          }
          case 26: {
            Tag = input.ReadBytes();
            break;
          }
          case 34: {
            AssociatedData = input.ReadBytes();
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
