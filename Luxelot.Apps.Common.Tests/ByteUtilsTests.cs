namespace Luxelot.Apps.Common.Tests;

[TestClass]
public sealed class ByteUtilsTests
{
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
        Assert.AreEqual(0, ByteUtils.LongestCommonPrefixLength([ 0b_0111_1111, 0b_1111_1111], [0b_1111_1111, 0b_1111_1111]));

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