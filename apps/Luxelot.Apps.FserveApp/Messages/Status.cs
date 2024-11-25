// <auto-generated>
//     Generated by the protocol buffer compiler.  DO NOT EDIT!
//     source: status.proto
// </auto-generated>
#pragma warning disable 1591, 0612, 3021, 8981
#region Designer generated code

using pb = global::Google.Protobuf;
using pbc = global::Google.Protobuf.Collections;
using pbr = global::Google.Protobuf.Reflection;
using scg = global::System.Collections.Generic;
namespace Luxelot.Apps.FserveApp.Messages {

  /// <summary>Holder for reflection information generated from status.proto</summary>
  public static partial class StatusReflection {

    #region Descriptor
    /// <summary>File descriptor for status.proto</summary>
    public static pbr::FileDescriptor Descriptor {
      get { return descriptor; }
    }
    private static pbr::FileDescriptor descriptor;

    static StatusReflection() {
      byte[] descriptorData = global::System.Convert.FromBase64String(
          string.Concat(
            "CgxzdGF0dXMucHJvdG8ibAoGU3RhdHVzEh0KCW9wZXJhdGlvbhgBIAEoDjIK",
            "Lk9wZXJhdGlvbhITCgtzdGF0dXNfY29kZRgCIAEoBRIWCg5zdGF0dXNfbWVz",
            "c2FnZRgDIAEoCRIWCg5yZXN1bHRfcGF5bG9hZBgEIAEoDCpHCglPcGVyYXRp",
            "b24SCAoETk9ORRAAEhIKDkFVVEhFTlRJQ0FUSU9OEAESBgoCQ0QQAhIUChBQ",
            "UkVQQVJFX0RPV05MT0FEEANCIqoCH0x1eGVsb3QuQXBwcy5Gc2VydmVBcHAu",
            "TWVzc2FnZXNiBnByb3RvMw=="));
      descriptor = pbr::FileDescriptor.FromGeneratedCode(descriptorData,
          new pbr::FileDescriptor[] { },
          new pbr::GeneratedClrTypeInfo(new[] {typeof(global::Luxelot.Apps.FserveApp.Messages.Operation), }, null, new pbr::GeneratedClrTypeInfo[] {
            new pbr::GeneratedClrTypeInfo(typeof(global::Luxelot.Apps.FserveApp.Messages.Status), global::Luxelot.Apps.FserveApp.Messages.Status.Parser, new[]{ "Operation", "StatusCode", "StatusMessage", "ResultPayload" }, null, null, null, null)
          }));
    }
    #endregion

  }
  #region Enums
  public enum Operation {
    [pbr::OriginalName("NONE")] None = 0,
    [pbr::OriginalName("AUTHENTICATION")] Authentication = 1,
    [pbr::OriginalName("CD")] Cd = 2,
    [pbr::OriginalName("PREPARE_DOWNLOAD")] PrepareDownload = 3,
  }

  #endregion

  #region Messages
  public sealed partial class Status : pb::IMessage<Status>
  #if !GOOGLE_PROTOBUF_REFSTRUCT_COMPATIBILITY_MODE
      , pb::IBufferMessage
  #endif
  {
    private static readonly pb::MessageParser<Status> _parser = new pb::MessageParser<Status>(() => new Status());
    private pb::UnknownFieldSet _unknownFields;
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public static pb::MessageParser<Status> Parser { get { return _parser; } }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public static pbr::MessageDescriptor Descriptor {
      get { return global::Luxelot.Apps.FserveApp.Messages.StatusReflection.Descriptor.MessageTypes[0]; }
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    pbr::MessageDescriptor pb::IMessage.Descriptor {
      get { return Descriptor; }
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public Status() {
      OnConstruction();
    }

    partial void OnConstruction();

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public Status(Status other) : this() {
      operation_ = other.operation_;
      statusCode_ = other.statusCode_;
      statusMessage_ = other.statusMessage_;
      resultPayload_ = other.resultPayload_;
      _unknownFields = pb::UnknownFieldSet.Clone(other._unknownFields);
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public Status Clone() {
      return new Status(this);
    }

    /// <summary>Field number for the "operation" field.</summary>
    public const int OperationFieldNumber = 1;
    private global::Luxelot.Apps.FserveApp.Messages.Operation operation_ = global::Luxelot.Apps.FserveApp.Messages.Operation.None;
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public global::Luxelot.Apps.FserveApp.Messages.Operation Operation {
      get { return operation_; }
      set {
        operation_ = value;
      }
    }

    /// <summary>Field number for the "status_code" field.</summary>
    public const int StatusCodeFieldNumber = 2;
    private int statusCode_;
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public int StatusCode {
      get { return statusCode_; }
      set {
        statusCode_ = value;
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

    /// <summary>Field number for the "result_payload" field.</summary>
    public const int ResultPayloadFieldNumber = 4;
    private pb::ByteString resultPayload_ = pb::ByteString.Empty;
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public pb::ByteString ResultPayload {
      get { return resultPayload_; }
      set {
        resultPayload_ = pb::ProtoPreconditions.CheckNotNull(value, "value");
      }
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public override bool Equals(object other) {
      return Equals(other as Status);
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public bool Equals(Status other) {
      if (ReferenceEquals(other, null)) {
        return false;
      }
      if (ReferenceEquals(other, this)) {
        return true;
      }
      if (Operation != other.Operation) return false;
      if (StatusCode != other.StatusCode) return false;
      if (StatusMessage != other.StatusMessage) return false;
      if (ResultPayload != other.ResultPayload) return false;
      return Equals(_unknownFields, other._unknownFields);
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public override int GetHashCode() {
      int hash = 1;
      if (Operation != global::Luxelot.Apps.FserveApp.Messages.Operation.None) hash ^= Operation.GetHashCode();
      if (StatusCode != 0) hash ^= StatusCode.GetHashCode();
      if (StatusMessage.Length != 0) hash ^= StatusMessage.GetHashCode();
      if (ResultPayload.Length != 0) hash ^= ResultPayload.GetHashCode();
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
      if (Operation != global::Luxelot.Apps.FserveApp.Messages.Operation.None) {
        output.WriteRawTag(8);
        output.WriteEnum((int) Operation);
      }
      if (StatusCode != 0) {
        output.WriteRawTag(16);
        output.WriteInt32(StatusCode);
      }
      if (StatusMessage.Length != 0) {
        output.WriteRawTag(26);
        output.WriteString(StatusMessage);
      }
      if (ResultPayload.Length != 0) {
        output.WriteRawTag(34);
        output.WriteBytes(ResultPayload);
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
      if (Operation != global::Luxelot.Apps.FserveApp.Messages.Operation.None) {
        output.WriteRawTag(8);
        output.WriteEnum((int) Operation);
      }
      if (StatusCode != 0) {
        output.WriteRawTag(16);
        output.WriteInt32(StatusCode);
      }
      if (StatusMessage.Length != 0) {
        output.WriteRawTag(26);
        output.WriteString(StatusMessage);
      }
      if (ResultPayload.Length != 0) {
        output.WriteRawTag(34);
        output.WriteBytes(ResultPayload);
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
      if (Operation != global::Luxelot.Apps.FserveApp.Messages.Operation.None) {
        size += 1 + pb::CodedOutputStream.ComputeEnumSize((int) Operation);
      }
      if (StatusCode != 0) {
        size += 1 + pb::CodedOutputStream.ComputeInt32Size(StatusCode);
      }
      if (StatusMessage.Length != 0) {
        size += 1 + pb::CodedOutputStream.ComputeStringSize(StatusMessage);
      }
      if (ResultPayload.Length != 0) {
        size += 1 + pb::CodedOutputStream.ComputeBytesSize(ResultPayload);
      }
      if (_unknownFields != null) {
        size += _unknownFields.CalculateSize();
      }
      return size;
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public void MergeFrom(Status other) {
      if (other == null) {
        return;
      }
      if (other.Operation != global::Luxelot.Apps.FserveApp.Messages.Operation.None) {
        Operation = other.Operation;
      }
      if (other.StatusCode != 0) {
        StatusCode = other.StatusCode;
      }
      if (other.StatusMessage.Length != 0) {
        StatusMessage = other.StatusMessage;
      }
      if (other.ResultPayload.Length != 0) {
        ResultPayload = other.ResultPayload;
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
            Operation = (global::Luxelot.Apps.FserveApp.Messages.Operation) input.ReadEnum();
            break;
          }
          case 16: {
            StatusCode = input.ReadInt32();
            break;
          }
          case 26: {
            StatusMessage = input.ReadString();
            break;
          }
          case 34: {
            ResultPayload = input.ReadBytes();
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
            Operation = (global::Luxelot.Apps.FserveApp.Messages.Operation) input.ReadEnum();
            break;
          }
          case 16: {
            StatusCode = input.ReadInt32();
            break;
          }
          case 26: {
            StatusMessage = input.ReadString();
            break;
          }
          case 34: {
            ResultPayload = input.ReadBytes();
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
