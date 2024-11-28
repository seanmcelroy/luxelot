namespace Luxelot.Apps.Common;

public readonly record struct HandleUserInputResult
{
    /// <summary>
    /// Whether the input was handled by a command, and, if so, whether so it was done so successfully by a command
    /// </summary>
    public required bool Success { get; init; }

    /// <summary>
    /// If unsuccessful, an error message
    /// </summary>
    public required string? ErrorMessage { get; init; }

    /// <summary>
    /// If the input matched a command, this is the command that was executed
    /// </summary>
    public required IConsoleCommand? Command { get; init; }
}