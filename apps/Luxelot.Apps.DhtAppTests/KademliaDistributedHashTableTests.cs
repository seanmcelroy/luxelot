﻿using Luxelot.Apps.Common;
using Luxelot.Apps.DhtApp;

namespace Luxelot.Apps.DhtAppTests;

[TestClass]
public sealed class KademliaDistributedHashTableTests

{
    [TestMethod]
    public void MapDistanceToBucketNumber()
    {
        Assert.AreEqual(0, ByteUtils.MapDistanceToBucketNumber([0x00], 8));
        Assert.AreEqual(8, ByteUtils.MapDistanceToBucketNumber([0xFF], 8));
        
        Assert.AreEqual(0, ByteUtils.MapDistanceToBucketNumber([
            // 32 bytes * 8 bits/byte = 256 bits/tree height
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            ,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            ,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            ,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            ], 256));
        Assert.AreEqual(256, ByteUtils.MapDistanceToBucketNumber([
             0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
            ,0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
            ,0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
            ,0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
            ], 256));
        Assert.AreEqual(128, ByteUtils.MapDistanceToBucketNumber([
             0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
            ,0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
            ,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            ,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            ], 256));
    }


}
