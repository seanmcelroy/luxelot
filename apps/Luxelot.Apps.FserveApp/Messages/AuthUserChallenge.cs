// <auto-generated>
//     Generated by the protocol buffer compiler.  DO NOT EDIT!
//     source: auth_user_challenge.proto
// </auto-generated>
#pragma warning disable 1591, 0612, 3021, 8981
#region Designer generated code

using pb = global::Google.Protobuf;
using pbc = global::Google.Protobuf.Collections;
using pbr = global::Google.Protobuf.Reflection;
using scg = global::System.Collections.Generic;
namespace Luxelot.Apps.FserveApp.Messages {

  /// <summary>Holder for reflection information generated from auth_user_challenge.proto</summary>
  public static partial class AuthUserChallengeReflection {

    #region Descriptor
    /// <summary>File descriptor for auth_user_challenge.proto</summary>
    public static pbr::FileDescriptor Descriptor {
      get { return descriptor; }
    }
    private static pbr::FileDescriptor descriptor;

    static AuthUserChallengeReflection() {
      byte[] descriptorData = global::System.Convert.FromBase64String(
          string.Concat(
            "ChlhdXRoX3VzZXJfY2hhbGxlbmdlLnByb3RvIlcKEUF1dGhVc2VyQ2hhbGxl",
            "bmdlEhEKCXByaW5jaXBhbBgBIAEoDBIvChN1c2VyX2NoYWxsZW5nZV90eXBl",
            "GAIgASgOMhIuVXNlckNoYWxsZW5nZVR5cGUqNAoRVXNlckNoYWxsZW5nZVR5",
            "cGUSCAoETk9ORRAAEgwKCFBBU1NXT1JEEAESBwoDT1RQEAJCIqoCH0x1eGVs",
            "b3QuQXBwcy5Gc2VydmVBcHAuTWVzc2FnZXNiBnByb3RvMw=="));
      descriptor = pbr::FileDescriptor.FromGeneratedCode(descriptorData,
          new pbr::FileDescriptor[] { },
          new pbr::GeneratedClrTypeInfo(new[] {typeof(global::Luxelot.Apps.FserveApp.Messages.UserChallengeType), }, null, new pbr::GeneratedClrTypeInfo[] {
            new pbr::GeneratedClrTypeInfo(typeof(global::Luxelot.Apps.FserveApp.Messages.AuthUserChallenge), global::Luxelot.Apps.FserveApp.Messages.AuthUserChallenge.Parser, new[]{ "Principal", "UserChallengeType" }, null, null, null, null)
          }));
    }
    #endregion

  }
  #region Enums
  public enum UserChallengeType {
    [pbr::OriginalName("NONE")] None = 0,
    [pbr::OriginalName("PASSWORD")] Password = 1,
    [pbr::OriginalName("OTP")] Otp = 2,
  }

  #endregion

  #region Messages
  public sealed partial class AuthUserChallenge : pb::IMessage<AuthUserChallenge>
  #if !GOOGLE_PROTOBUF_REFSTRUCT_COMPATIBILITY_MODE
      , pb::IBufferMessage
  #endif
  {
    private static readonly pb::MessageParser<AuthUserChallenge> _parser = new pb::MessageParser<AuthUserChallenge>(() => new AuthUserChallenge());
    private pb::UnknownFieldSet _unknownFields;
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public static pb::MessageParser<AuthUserChallenge> Parser { get { return _parser; } }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public static pbr::MessageDescriptor Descriptor {
      get { return global::Luxelot.Apps.FserveApp.Messages.AuthUserChallengeReflection.Descriptor.MessageTypes[0]; }
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    pbr::MessageDescriptor pb::IMessage.Descriptor {
      get { return Descriptor; }
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public AuthUserChallenge() {
      OnConstruction();
    }

    partial void OnConstruction();

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public AuthUserChallenge(AuthUserChallenge other) : this() {
      principal_ = other.principal_;
      userChallengeType_ = other.userChallengeType_;
      _unknownFields = pb::UnknownFieldSet.Clone(other._unknownFields);
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public AuthUserChallenge Clone() {
      return new AuthUserChallenge(this);
    }

    /// <summary>Field number for the "principal" field.</summary>
    public const int PrincipalFieldNumber = 1;
    private pb::ByteString principal_ = pb::ByteString.Empty;
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public pb::ByteString Principal {
      get { return principal_; }
      set {
        principal_ = pb::ProtoPreconditions.CheckNotNull(value, "value");
      }
    }

    /// <summary>Field number for the "user_challenge_type" field.</summary>
    public const int UserChallengeTypeFieldNumber = 2;
    private global::Luxelot.Apps.FserveApp.Messages.UserChallengeType userChallengeType_ = global::Luxelot.Apps.FserveApp.Messages.UserChallengeType.None;
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public global::Luxelot.Apps.FserveApp.Messages.UserChallengeType UserChallengeType {
      get { return userChallengeType_; }
      set {
        userChallengeType_ = value;
      }
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public override bool Equals(object other) {
      return Equals(other as AuthUserChallenge);
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public bool Equals(AuthUserChallenge other) {
      if (ReferenceEquals(other, null)) {
        return false;
      }
      if (ReferenceEquals(other, this)) {
        return true;
      }
      if (Principal != other.Principal) return false;
      if (UserChallengeType != other.UserChallengeType) return false;
      return Equals(_unknownFields, other._unknownFields);
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public override int GetHashCode() {
      int hash = 1;
      if (Principal.Length != 0) hash ^= Principal.GetHashCode();
      if (UserChallengeType != global::Luxelot.Apps.FserveApp.Messages.UserChallengeType.None) hash ^= UserChallengeType.GetHashCode();
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
      if (Principal.Length != 0) {
        output.WriteRawTag(10);
        output.WriteBytes(Principal);
      }
      if (UserChallengeType != global::Luxelot.Apps.FserveApp.Messages.UserChallengeType.None) {
        output.WriteRawTag(16);
        output.WriteEnum((int) UserChallengeType);
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
      if (Principal.Length != 0) {
        output.WriteRawTag(10);
        output.WriteBytes(Principal);
      }
      if (UserChallengeType != global::Luxelot.Apps.FserveApp.Messages.UserChallengeType.None) {
        output.WriteRawTag(16);
        output.WriteEnum((int) UserChallengeType);
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
      if (Principal.Length != 0) {
        size += 1 + pb::CodedOutputStream.ComputeBytesSize(Principal);
      }
      if (UserChallengeType != global::Luxelot.Apps.FserveApp.Messages.UserChallengeType.None) {
        size += 1 + pb::CodedOutputStream.ComputeEnumSize((int) UserChallengeType);
      }
      if (_unknownFields != null) {
        size += _unknownFields.CalculateSize();
      }
      return size;
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public void MergeFrom(AuthUserChallenge other) {
      if (other == null) {
        return;
      }
      if (other.Principal.Length != 0) {
        Principal = other.Principal;
      }
      if (other.UserChallengeType != global::Luxelot.Apps.FserveApp.Messages.UserChallengeType.None) {
        UserChallengeType = other.UserChallengeType;
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
            Principal = input.ReadBytes();
            break;
          }
          case 16: {
            UserChallengeType = (global::Luxelot.Apps.FserveApp.Messages.UserChallengeType) input.ReadEnum();
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
            Principal = input.ReadBytes();
            break;
          }
          case 16: {
            UserChallengeType = (global::Luxelot.Apps.FserveApp.Messages.UserChallengeType) input.ReadEnum();
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
