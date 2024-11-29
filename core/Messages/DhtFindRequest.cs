// <auto-generated>
//     Generated by the protocol buffer compiler.  DO NOT EDIT!
//     source: dht_find_request.proto
// </auto-generated>
#pragma warning disable 1591, 0612, 3021, 8981
#region Designer generated code

using pb = global::Google.Protobuf;
using pbc = global::Google.Protobuf.Collections;
using pbr = global::Google.Protobuf.Reflection;
using scg = global::System.Collections.Generic;
namespace Luxelot.Messages {

  /// <summary>Holder for reflection information generated from dht_find_request.proto</summary>
  public static partial class DhtFindRequestReflection {

    #region Descriptor
    /// <summary>File descriptor for dht_find_request.proto</summary>
    public static pbr::FileDescriptor Descriptor {
      get { return descriptor; }
    }
    private static pbr::FileDescriptor descriptor;

    static DhtFindRequestReflection() {
      byte[] descriptorData = global::System.Convert.FromBase64String(
          string.Concat(
            "ChZkaHRfZmluZF9yZXF1ZXN0LnByb3RvInMKDkRodEZpbmRSZXF1ZXN0Eg4K",
            "BnZhbHVlMRgBIAEoBhIOCgZ2YWx1ZTIYAiABKAYSDgoGdmFsdWUzGAMgASgG",
            "Eg4KBnZhbHVlNBgEIAEoBhIhCgp0YWJsZV90eXBlGAUgASgOMg0uRGh0VGFi",
            "bGVUeXBlKiQKDERodFRhYmxlVHlwZRIICgROb2RlEAASCgoGQmluYXJ5EAFC",
            "E6oCEEx1eGVsb3QuTWVzc2FnZXNiBnByb3RvMw=="));
      descriptor = pbr::FileDescriptor.FromGeneratedCode(descriptorData,
          new pbr::FileDescriptor[] { },
          new pbr::GeneratedClrTypeInfo(new[] {typeof(global::Luxelot.Messages.DhtTableType), }, null, new pbr::GeneratedClrTypeInfo[] {
            new pbr::GeneratedClrTypeInfo(typeof(global::Luxelot.Messages.DhtFindRequest), global::Luxelot.Messages.DhtFindRequest.Parser, new[]{ "Value1", "Value2", "Value3", "Value4", "TableType" }, null, null, null, null)
          }));
    }
    #endregion

  }
  #region Enums
  public enum DhtTableType {
    [pbr::OriginalName("Node")] Node = 0,
    [pbr::OriginalName("Binary")] Binary = 1,
  }

  #endregion

  #region Messages
  public sealed partial class DhtFindRequest : pb::IMessage<DhtFindRequest>
  #if !GOOGLE_PROTOBUF_REFSTRUCT_COMPATIBILITY_MODE
      , pb::IBufferMessage
  #endif
  {
    private static readonly pb::MessageParser<DhtFindRequest> _parser = new pb::MessageParser<DhtFindRequest>(() => new DhtFindRequest());
    private pb::UnknownFieldSet _unknownFields;
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public static pb::MessageParser<DhtFindRequest> Parser { get { return _parser; } }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public static pbr::MessageDescriptor Descriptor {
      get { return global::Luxelot.Messages.DhtFindRequestReflection.Descriptor.MessageTypes[0]; }
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    pbr::MessageDescriptor pb::IMessage.Descriptor {
      get { return Descriptor; }
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public DhtFindRequest() {
      OnConstruction();
    }

    partial void OnConstruction();

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public DhtFindRequest(DhtFindRequest other) : this() {
      value1_ = other.value1_;
      value2_ = other.value2_;
      value3_ = other.value3_;
      value4_ = other.value4_;
      tableType_ = other.tableType_;
      _unknownFields = pb::UnknownFieldSet.Clone(other._unknownFields);
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public DhtFindRequest Clone() {
      return new DhtFindRequest(this);
    }

    /// <summary>Field number for the "value1" field.</summary>
    public const int Value1FieldNumber = 1;
    private ulong value1_;
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public ulong Value1 {
      get { return value1_; }
      set {
        value1_ = value;
      }
    }

    /// <summary>Field number for the "value2" field.</summary>
    public const int Value2FieldNumber = 2;
    private ulong value2_;
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public ulong Value2 {
      get { return value2_; }
      set {
        value2_ = value;
      }
    }

    /// <summary>Field number for the "value3" field.</summary>
    public const int Value3FieldNumber = 3;
    private ulong value3_;
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public ulong Value3 {
      get { return value3_; }
      set {
        value3_ = value;
      }
    }

    /// <summary>Field number for the "value4" field.</summary>
    public const int Value4FieldNumber = 4;
    private ulong value4_;
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public ulong Value4 {
      get { return value4_; }
      set {
        value4_ = value;
      }
    }

    /// <summary>Field number for the "table_type" field.</summary>
    public const int TableTypeFieldNumber = 5;
    private global::Luxelot.Messages.DhtTableType tableType_ = global::Luxelot.Messages.DhtTableType.Node;
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public global::Luxelot.Messages.DhtTableType TableType {
      get { return tableType_; }
      set {
        tableType_ = value;
      }
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public override bool Equals(object other) {
      return Equals(other as DhtFindRequest);
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public bool Equals(DhtFindRequest other) {
      if (ReferenceEquals(other, null)) {
        return false;
      }
      if (ReferenceEquals(other, this)) {
        return true;
      }
      if (Value1 != other.Value1) return false;
      if (Value2 != other.Value2) return false;
      if (Value3 != other.Value3) return false;
      if (Value4 != other.Value4) return false;
      if (TableType != other.TableType) return false;
      return Equals(_unknownFields, other._unknownFields);
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public override int GetHashCode() {
      int hash = 1;
      if (Value1 != 0UL) hash ^= Value1.GetHashCode();
      if (Value2 != 0UL) hash ^= Value2.GetHashCode();
      if (Value3 != 0UL) hash ^= Value3.GetHashCode();
      if (Value4 != 0UL) hash ^= Value4.GetHashCode();
      if (TableType != global::Luxelot.Messages.DhtTableType.Node) hash ^= TableType.GetHashCode();
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
      if (Value1 != 0UL) {
        output.WriteRawTag(9);
        output.WriteFixed64(Value1);
      }
      if (Value2 != 0UL) {
        output.WriteRawTag(17);
        output.WriteFixed64(Value2);
      }
      if (Value3 != 0UL) {
        output.WriteRawTag(25);
        output.WriteFixed64(Value3);
      }
      if (Value4 != 0UL) {
        output.WriteRawTag(33);
        output.WriteFixed64(Value4);
      }
      if (TableType != global::Luxelot.Messages.DhtTableType.Node) {
        output.WriteRawTag(40);
        output.WriteEnum((int) TableType);
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
      if (Value1 != 0UL) {
        output.WriteRawTag(9);
        output.WriteFixed64(Value1);
      }
      if (Value2 != 0UL) {
        output.WriteRawTag(17);
        output.WriteFixed64(Value2);
      }
      if (Value3 != 0UL) {
        output.WriteRawTag(25);
        output.WriteFixed64(Value3);
      }
      if (Value4 != 0UL) {
        output.WriteRawTag(33);
        output.WriteFixed64(Value4);
      }
      if (TableType != global::Luxelot.Messages.DhtTableType.Node) {
        output.WriteRawTag(40);
        output.WriteEnum((int) TableType);
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
      if (Value1 != 0UL) {
        size += 1 + 8;
      }
      if (Value2 != 0UL) {
        size += 1 + 8;
      }
      if (Value3 != 0UL) {
        size += 1 + 8;
      }
      if (Value4 != 0UL) {
        size += 1 + 8;
      }
      if (TableType != global::Luxelot.Messages.DhtTableType.Node) {
        size += 1 + pb::CodedOutputStream.ComputeEnumSize((int) TableType);
      }
      if (_unknownFields != null) {
        size += _unknownFields.CalculateSize();
      }
      return size;
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public void MergeFrom(DhtFindRequest other) {
      if (other == null) {
        return;
      }
      if (other.Value1 != 0UL) {
        Value1 = other.Value1;
      }
      if (other.Value2 != 0UL) {
        Value2 = other.Value2;
      }
      if (other.Value3 != 0UL) {
        Value3 = other.Value3;
      }
      if (other.Value4 != 0UL) {
        Value4 = other.Value4;
      }
      if (other.TableType != global::Luxelot.Messages.DhtTableType.Node) {
        TableType = other.TableType;
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
            Value1 = input.ReadFixed64();
            break;
          }
          case 17: {
            Value2 = input.ReadFixed64();
            break;
          }
          case 25: {
            Value3 = input.ReadFixed64();
            break;
          }
          case 33: {
            Value4 = input.ReadFixed64();
            break;
          }
          case 40: {
            TableType = (global::Luxelot.Messages.DhtTableType) input.ReadEnum();
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
            Value1 = input.ReadFixed64();
            break;
          }
          case 17: {
            Value2 = input.ReadFixed64();
            break;
          }
          case 25: {
            Value3 = input.ReadFixed64();
            break;
          }
          case 33: {
            Value4 = input.ReadFixed64();
            break;
          }
          case 40: {
            TableType = (global::Luxelot.Messages.DhtTableType) input.ReadEnum();
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
