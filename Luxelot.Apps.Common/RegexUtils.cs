using System.Text.RegularExpressions;

namespace Luxelot.Apps.Common;

public static partial class RegexUtils
{
    [GeneratedRegex("(?:^|\\s)(\\\"(?:[^\\\"])*\\\"|[^\\s]*)")]
    public static partial Regex QuotedWordArrayRegex();
}