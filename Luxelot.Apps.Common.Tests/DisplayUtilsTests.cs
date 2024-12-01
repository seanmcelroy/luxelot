namespace Luxelot.Apps.Common.Tests;

[TestClass]
public sealed class DisplayUtilsTests
{
    [TestMethod]
    public void UnixFileModeToString_0000()
    {
        var result = DisplayUtils.UnixFileModeToString(UnixFileMode.None, false);
        Assert.AreEqual("----------", result);
    }

    [TestMethod]
    public void UnixFileModeToString_0001()
    {
        var result = DisplayUtils.UnixFileModeToString(UnixFileMode.OtherExecute, false);
        Assert.AreEqual("---------x", result);
    }

    [TestMethod]
    public void UnixFileModeToString_0002()
    {
        var result = DisplayUtils.UnixFileModeToString(UnixFileMode.OtherWrite, false);
        Assert.AreEqual("--------w-", result);
    }

    [TestMethod]
    public void UnixFileModeToString_0003()
    {
        var result = DisplayUtils.UnixFileModeToString(UnixFileMode.OtherWrite | UnixFileMode.OtherExecute, false);
        Assert.AreEqual("--------wx", result);
    }

    [TestMethod]
    public void UnixFileModeToString_0004()
    {
        var result = DisplayUtils.UnixFileModeToString(0004, false);
        Assert.AreEqual("-------r--", result);
    }

    [TestMethod]
    public void UnixFileModeToString_0005()
    {
        var result = DisplayUtils.UnixFileModeToString(0005, false);
        Assert.AreEqual("-------r-x", result);
    }

    [TestMethod]
    public void UnixFileModeToString_0006()
    {
        var result = DisplayUtils.UnixFileModeToString(0006, false);
        Assert.AreEqual("-------rw-", result);
    }

    [TestMethod]
    public void UnixFileModeToString_0007()
    {
        var result = DisplayUtils.UnixFileModeToString(0007, false);
        Assert.AreEqual("-------rwx", result);
    }

    [TestMethod]
    public void UnixFileModeToString_0777()
    {
        var result = DisplayUtils.UnixFileModeToString(
            UnixFileMode.None
            | UnixFileMode.OtherExecute
            | UnixFileMode.OtherRead
            | UnixFileMode.OtherWrite
            | UnixFileMode.GroupExecute
            | UnixFileMode.GroupRead
            | UnixFileMode.GroupWrite
            | UnixFileMode.UserExecute
            | UnixFileMode.UserRead
            | UnixFileMode.UserWrite
            , false);
        Assert.AreEqual("-rwxrwxrwx", result);
    }

    [TestMethod]
    public void UnixFileModeToString_0777_Directory()
    {
        var result = DisplayUtils.UnixFileModeToString(
            UnixFileMode.None
            | UnixFileMode.OtherExecute
            | UnixFileMode.OtherRead
            | UnixFileMode.OtherWrite
            | UnixFileMode.GroupExecute
            | UnixFileMode.GroupRead
            | UnixFileMode.GroupWrite
            | UnixFileMode.UserExecute
            | UnixFileMode.UserRead
            | UnixFileMode.UserWrite
            , true);
        Assert.AreEqual("drwxrwxrwx", result);
    }
}
