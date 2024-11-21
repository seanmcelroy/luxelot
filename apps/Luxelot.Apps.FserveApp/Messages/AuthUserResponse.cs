// <auto-generated>
//     Generated by the protocol buffer compiler.  DO NOT EDIT!
//     source: auth_user_response.proto
// </auto-generated>
#pragma warning disable 1591, 0612, 3021, 8981
#region Designer generated code

using pb = global::Google.Protobuf;
using pbc = global::Google.Protobuf.Collections;
using pbr = global::Google.Protobuf.Reflection;
using scg = global::System.Collections.Generic;
namespace Luxelot.Apps.FserveApp.Messages {

  /// <summary>Holder for reflection information generated from auth_user_response.proto</summary>
  public static partial class AuthUserResponseReflection {

    #region Descriptor
    /// <summary>File descriptor for auth_user_response.proto</summary>
    public static pbr::FileDescriptor Descriptor {
      get { return descriptor; }
    }
    private static pbr::FileDescriptor descriptor;

    static AuthUserResponseReflection() {
      byte[] descriptorData = global::System.Convert.FromBase64String(
          string.Concat(
            "ChhhdXRoX3VzZXJfcmVzcG9uc2UucHJvdG8irQEKEEF1dGhVc2VyUmVzcG9u",
            "c2USEwoLc3RhdHVzX2NvZGUYASABKAUSFgoOc3RhdHVzX21lc3NhZ2UYAiAB",
            "KAkSRAoeYWRkaXRpb25hbF91c2VyX2NoYWxsZW5nZV90eXBlGAMgASgOMhwu",
            "QWRkaXRpb25hbFVzZXJDaGFsbGVuZ2VUeXBlEiYKHmFkZGl0aW9uYWxfdXNl",
            "cl9jaGFsbGVuZ2VfZGF0YRgEIAEoDCo+ChtBZGRpdGlvbmFsVXNlckNoYWxs",
            "ZW5nZVR5cGUSCAoETk9ORRAAEgwKCFBBU1NXT1JEEAESBwoDT1RQEAJCIqoC",
            "H0x1eGVsb3QuQXBwcy5Gc2VydmVBcHAuTWVzc2FnZXNiBnByb3RvMw=="));
      descriptor = pbr::FileDescriptor.FromGeneratedCode(descriptorData,
          new pbr::FileDescriptor[] { },
          new pbr::GeneratedClrTypeInfo(new[] {typeof(global::Luxelot.Apps.FserveApp.Messages.AdditionalUserChallengeType), }, null, new pbr::GeneratedClrTypeInfo[] {
            new pbr::GeneratedClrTypeInfo(typeof(global::Luxelot.Apps.FserveApp.Messages.AuthUserResponse), global::Luxelot.Apps.FserveApp.Messages.AuthUserResponse.Parser, new[]{ "StatusCode", "StatusMessage", "AdditionalUserChallengeType", "AdditionalUserChallengeData" }, null, null, null, null)
          }));
    }
    #endregion

  }
  #region Enums
  public enum AdditionalUserChallengeType {
    [pbr::OriginalName("NONE")] None = 0,
    [pbr::OriginalName("PASSWORD")] Password = 1,
    [pbr::OriginalName("OTP")] Otp = 2,
  }

  #endregion

  #region Messages
  public sealed partial class AuthUserResponse : pb::IMessage<AuthUserResponse>
  #if !GOOGLE_PROTOBUF_REFSTRUCT_COMPATIBILITY_MODE
      , pb::IBufferMessage
  #endif
  {
    private static readonly pb::MessageParser<AuthUserResponse> _parser = new pb::MessageParser<AuthUserResponse>(() => new AuthUserResponse());
    private pb::UnknownFieldSet _unknownFields;
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public static pb::MessageParser<AuthUserResponse> Parser { get { return _parser; } }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public static pbr::MessageDescriptor Descriptor {
      get { return global::Luxelot.Apps.FserveApp.Messages.AuthUserResponseReflection.Descriptor.MessageTypes[0]; }
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    pbr::MessageDescriptor pb::IMessage.Descriptor {
      get { return Descriptor; }
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public AuthUserResponse() {
      OnConstruction();
    }

    partial void OnConstruction();

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public AuthUserResponse(AuthUserResponse other) : this() {
      statusCode_ = other.statusCode_;
      statusMessage_ = other.statusMessage_;
      additionalUserChallengeType_ = other.additionalUserChallengeType_;
      additionalUserChallengeData_ = other.additionalUserChallengeData_;
      _unknownFields = pb::UnknownFieldSet.Clone(other._unknownFields);
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public AuthUserResponse Clone() {
      return new AuthUserResponse(this);
    }

    /// <summary>Field number for the "status_code" field.</summary>
    public const int StatusCodeFieldNumber = 1;
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
    public const int StatusMessageFieldNumber = 2;
    private string statusMessage_ = "";
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public string StatusMessage {
      get { return statusMessage_; }
      set {
        statusMessage_ = pb::ProtoPreconditions.CheckNotNull(value, "value");
      }
    }

    /// <summary>Field number for the "additional_user_challenge_type" field.</summary>
    public const int AdditionalUserChallengeTypeFieldNumber = 3;
    private global::Luxelot.Apps.FserveApp.Messages.AdditionalUserChallengeType additionalUserChallengeType_ = global::Luxelot.Apps.FserveApp.Messages.AdditionalUserChallengeType.None;
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public global::Luxelot.Apps.FserveApp.Messages.AdditionalUserChallengeType AdditionalUserChallengeType {
      get { return additionalUserChallengeType_; }
      set {
        additionalUserChallengeType_ = value;
      }
    }

    /// <summary>Field number for the "additional_user_challenge_data" field.</summary>
    public const int AdditionalUserChallengeDataFieldNumber = 4;
    private pb::ByteString additionalUserChallengeData_ = pb::ByteString.Empty;
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public pb::ByteString AdditionalUserChallengeData {
      get { return additionalUserChallengeData_; }
      set {
        additionalUserChallengeData_ = pb::ProtoPreconditions.CheckNotNull(value, "value");
      }
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public override bool Equals(object other) {
      return Equals(other as AuthUserResponse);
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public bool Equals(AuthUserResponse other) {
      if (ReferenceEquals(other, null)) {
        return false;
      }
      if (ReferenceEquals(other, this)) {
        return true;
      }
      if (StatusCode != other.StatusCode) return false;
      if (StatusMessage != other.StatusMessage) return false;
      if (AdditionalUserChallengeType != other.AdditionalUserChallengeType) return false;
      if (AdditionalUserChallengeData != other.AdditionalUserChallengeData) return false;
      return Equals(_unknownFields, other._unknownFields);
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public override int GetHashCode() {
      int hash = 1;
      if (StatusCode != 0) hash ^= StatusCode.GetHashCode();
      if (StatusMessage.Length != 0) hash ^= StatusMessage.GetHashCode();
      if (AdditionalUserChallengeType != global::Luxelot.Apps.FserveApp.Messages.AdditionalUserChallengeType.None) hash ^= AdditionalUserChallengeType.GetHashCode();
      if (AdditionalUserChallengeData.Length != 0) hash ^= AdditionalUserChallengeData.GetHashCode();
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
      if (StatusCode != 0) {
        output.WriteRawTag(8);
        output.WriteInt32(StatusCode);
      }
      if (StatusMessage.Length != 0) {
        output.WriteRawTag(18);
        output.WriteString(StatusMessage);
      }
      if (AdditionalUserChallengeType != global::Luxelot.Apps.FserveApp.Messages.AdditionalUserChallengeType.None) {
        output.WriteRawTag(24);
        output.WriteEnum((int) AdditionalUserChallengeType);
      }
      if (AdditionalUserChallengeData.Length != 0) {
        output.WriteRawTag(34);
        output.WriteBytes(AdditionalUserChallengeData);
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
      if (StatusCode != 0) {
        output.WriteRawTag(8);
        output.WriteInt32(StatusCode);
      }
      if (StatusMessage.Length != 0) {
        output.WriteRawTag(18);
        output.WriteString(StatusMessage);
      }
      if (AdditionalUserChallengeType != global::Luxelot.Apps.FserveApp.Messages.AdditionalUserChallengeType.None) {
        output.WriteRawTag(24);
        output.WriteEnum((int) AdditionalUserChallengeType);
      }
      if (AdditionalUserChallengeData.Length != 0) {
        output.WriteRawTag(34);
        output.WriteBytes(AdditionalUserChallengeData);
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
      if (StatusCode != 0) {
        size += 1 + pb::CodedOutputStream.ComputeInt32Size(StatusCode);
      }
      if (StatusMessage.Length != 0) {
        size += 1 + pb::CodedOutputStream.ComputeStringSize(StatusMessage);
      }
      if (AdditionalUserChallengeType != global::Luxelot.Apps.FserveApp.Messages.AdditionalUserChallengeType.None) {
        size += 1 + pb::CodedOutputStream.ComputeEnumSize((int) AdditionalUserChallengeType);
      }
      if (AdditionalUserChallengeData.Length != 0) {
        size += 1 + pb::CodedOutputStream.ComputeBytesSize(AdditionalUserChallengeData);
      }
      if (_unknownFields != null) {
        size += _unknownFields.CalculateSize();
      }
      return size;
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public void MergeFrom(AuthUserResponse other) {
      if (other == null) {
        return;
      }
      if (other.StatusCode != 0) {
        StatusCode = other.StatusCode;
      }
      if (other.StatusMessage.Length != 0) {
        StatusMessage = other.StatusMessage;
      }
      if (other.AdditionalUserChallengeType != global::Luxelot.Apps.FserveApp.Messages.AdditionalUserChallengeType.None) {
        AdditionalUserChallengeType = other.AdditionalUserChallengeType;
      }
      if (other.AdditionalUserChallengeData.Length != 0) {
        AdditionalUserChallengeData = other.AdditionalUserChallengeData;
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
            StatusCode = input.ReadInt32();
            break;
          }
          case 18: {
            StatusMessage = input.ReadString();
            break;
          }
          case 24: {
            AdditionalUserChallengeType = (global::Luxelot.Apps.FserveApp.Messages.AdditionalUserChallengeType) input.ReadEnum();
            break;
          }
          case 34: {
            AdditionalUserChallengeData = input.ReadBytes();
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
            StatusCode = input.ReadInt32();
            break;
          }
          case 18: {
            StatusMessage = input.ReadString();
            break;
          }
          case 24: {
            AdditionalUserChallengeType = (global::Luxelot.Apps.FserveApp.Messages.AdditionalUserChallengeType) input.ReadEnum();
            break;
          }
          case 34: {
            AdditionalUserChallengeData = input.ReadBytes();
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
