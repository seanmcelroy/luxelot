using Microsoft.VisualBasic;

namespace Luxelot.Apps.Common.Tests;

[TestClass]
public sealed class ByteUtilsTests
{
    [TestMethod]
    public void GetDistanceMetric()
    {
        var distance = ByteUtils.GetDistanceMetric(
            Convert.FromHexString("703e860c26f25cf33bbef40bfb818da03d7a522d24ff3b07bd4c2ab68c76384c"),
            Convert.FromHexString("593eefc175710c9831ac67c2684508bd9a1627cd14207c696e0949d24c2f2d22")
        );
        Assert.IsTrue(
            Enumerable.SequenceEqual(
                distance,
                Convert.FromHexString("290069cd5383506b0a1293c993c4851da76c75e030df476ed3456364c059156e")
            ));
    }

    [TestMethod]
    public void LongestCommonPrefixLengthByte0()
    {
        Assert.AreEqual(0, ByteUtils.LongestCommonPrefixLength(0b_1111_1111, 0b_0000_0000));
    }

    [TestMethod]
    public void LongestCommonPrefixLengthByte1()
    {
        Assert.AreEqual(1, ByteUtils.LongestCommonPrefixLength(0b_1111_1111, 0b_1000_0000));
    }

    [TestMethod]
    public void LongestCommonPrefixLengthByte8Zeros()
    {
        Assert.AreEqual(8, ByteUtils.LongestCommonPrefixLength(0b_0000_0000, 0b_0000_0000));
    }

    [TestMethod]
    public void LongestCommonPrefixLengthByte8Ones()
    {
        Assert.AreEqual(8, ByteUtils.LongestCommonPrefixLength(0b_1111_1111, 0b_1111_1111));
        Assert.AreEqual(7, ByteUtils.LongestCommonPrefixLength(0b_1111_1110, 0b_1111_1111));
        Assert.AreEqual(0, ByteUtils.LongestCommonPrefixLength(0b_0111_1111, 0b_1111_1111));
    }

    [TestMethod]
    public void LongestCommonPrefixLengthUShortOnes()
    {
        Assert.AreEqual(16, ByteUtils.LongestCommonPrefixLength(0b_1111_1111_1111_1111, 0b_1111_1111_1111_1111));
        Assert.AreEqual(15, ByteUtils.LongestCommonPrefixLength(0b_1111_1111_1111_1110, 0b_1111_1111_1111_1111));
        Assert.AreEqual(0, ByteUtils.LongestCommonPrefixLength(0b_0111_1111_1111_1111, 0b_1111_1111_1111_1111));
    }

    [TestMethod]
    public void LongestCommonPrefixLengthUIntOnes()
    {
        Assert.AreEqual(32, ByteUtils.LongestCommonPrefixLength(0b_1111_1111_1111_1111_1111_1111_1111_1111, 0b_1111_1111_1111_1111_1111_1111_1111_1111));
        Assert.AreEqual(31, ByteUtils.LongestCommonPrefixLength(0b_1111_1111_1111_1111_1111_1111_1111_1110, 0b_1111_1111_1111_1111_1111_1111_1111_1111));
        Assert.AreEqual(0, ByteUtils.LongestCommonPrefixLength(0b_0111_1111_1111_1111_1111_1111_1111_1110, 0b_1111_1111_1111_1111_1111_1111_1111_1111));
    }

    [TestMethod]
    public void LongestCommonPrefixLengthULongOnes()
    {
        Assert.AreEqual(64, ByteUtils.LongestCommonPrefixLength(0b_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111, 0b_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111));
        Assert.AreEqual(63, ByteUtils.LongestCommonPrefixLength(0b_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1110, 0b_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111));
        Assert.AreEqual(0, ByteUtils.LongestCommonPrefixLength(0b_0111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1110, 0b_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111));
    }

    [TestMethod]
    public void LongestCommonPrefixLengthArray()
    {
        Assert.AreEqual(8, ByteUtils.LongestCommonPrefixLength([0b_1111_1111], [0b_1111_1111]));
        Assert.AreEqual(0, ByteUtils.LongestCommonPrefixLength([0b_0111_1111], [0b_1111_1111]));

        Assert.AreEqual(16, ByteUtils.LongestCommonPrefixLength([0b_1111_1111, 0b_1111_1111], [0b_1111_1111, 0b_1111_1111]));
        Assert.AreEqual(15, ByteUtils.LongestCommonPrefixLength([0b_1111_1111, 0b_1111_1110], [0b_1111_1111, 0b_1111_1111]));
        Assert.AreEqual(0, ByteUtils.LongestCommonPrefixLength([0b_0111_1111, 0b_1111_1111], [0b_1111_1111, 0b_1111_1111]));

        Assert.AreEqual(32, ByteUtils.LongestCommonPrefixLength([0b_1111_1111, 0b_1111_1111, 0b_1111_1111, 0b_1111_1111], [0b_1111_1111, 0b_1111_1111, 0b_1111_1111, 0b_1111_1111]));
        Assert.AreEqual(31, ByteUtils.LongestCommonPrefixLength([0b_1111_1111, 0b_1111_1111, 0b_1111_1111, 0b_1111_1110], [0b_1111_1111, 0b_1111_1111, 0b_1111_1111, 0b_1111_1111]));
        Assert.AreEqual(0, ByteUtils.LongestCommonPrefixLength([0b_0111_1111, 0b_1111_1111, 0b_1111_1111, 0b_1111_1111], [0b_1111_1111, 0b_1111_1111, 0b_1111_1111, 0b_1111_1111]));

        Assert.AreEqual(64, ByteUtils.LongestCommonPrefixLength([0b_1111_1111, 0b_1111_1111, 0b_1111_1111, 0b_1111_1111, 0b_1111_1111, 0b_1111_1111, 0b_1111_1111, 0b_1111_1111], [0b_1111_1111, 0b_1111_1111, 0b_1111_1111, 0b_1111_1111, 0b_1111_1111, 0b_1111_1111, 0b_1111_1111, 0b_1111_1111]));
        Assert.AreEqual(63, ByteUtils.LongestCommonPrefixLength([0b_1111_1111, 0b_1111_1111, 0b_1111_1111, 0b_1111_1111, 0b_1111_1111, 0b_1111_1111, 0b_1111_1111, 0b_1111_1110], [0b_1111_1111, 0b_1111_1111, 0b_1111_1111, 0b_1111_1111, 0b_1111_1111, 0b_1111_1111, 0b_1111_1111, 0b_1111_1111]));
        Assert.AreEqual(0, ByteUtils.LongestCommonPrefixLength([0b_0111_1111, 0b_1111_1111, 0b_1111_1111, 0b_1111_1111, 0b_1111_1111, 0b_1111_1111, 0b_1111_1111, 0b_1111_1111], [0b_1111_1111, 0b_1111_1111, 0b_1111_1111, 0b_1111_1111, 0b_1111_1111, 0b_1111_1111, 0b_1111_1111, 0b_1111_1111]));

        Assert.AreEqual(256, ByteUtils.LongestCommonPrefixLength(
            [0b_1111_1111, 0b_1111_1111, 0b_1111_1111, 0b_1111_1111, 0b_1111_1111, 0b_1111_1111, 0b_1111_1111, 0b_0111_1111
            ,0b_1111_1111, 0b_1111_1111, 0b_1111_1111, 0b_1111_1111, 0b_1111_1111, 0b_1111_1111, 0b_1111_1111, 0b_0111_1111
            ,0b_1111_1111, 0b_1111_1111, 0b_1111_1111, 0b_1111_1111, 0b_1111_1111, 0b_1111_1111, 0b_1111_1111, 0b_0111_1111
            ,0b_1111_1111, 0b_1111_1111, 0b_1111_1111, 0b_1111_1111, 0b_1111_1111, 0b_1111_1111, 0b_1111_1111, 0b_0111_1111
            ],
            [0b_1111_1111, 0b_1111_1111, 0b_1111_1111, 0b_1111_1111, 0b_1111_1111, 0b_1111_1111, 0b_1111_1111, 0b_0111_1111
            ,0b_1111_1111, 0b_1111_1111, 0b_1111_1111, 0b_1111_1111, 0b_1111_1111, 0b_1111_1111, 0b_1111_1111, 0b_0111_1111
            ,0b_1111_1111, 0b_1111_1111, 0b_1111_1111, 0b_1111_1111, 0b_1111_1111, 0b_1111_1111, 0b_1111_1111, 0b_0111_1111
            ,0b_1111_1111, 0b_1111_1111, 0b_1111_1111, 0b_1111_1111, 0b_1111_1111, 0b_1111_1111, 0b_1111_1111, 0b_0111_1111
            ]));
    }
}