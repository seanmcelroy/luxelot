internal record TaskEntry
{
    public Guid TaskId { get; init; } = Guid.NewGuid();
    public required TaskEventType EventType { get; init; }
    public DateTimeOffset? NotBefore { get; init; }
    public DateTimeOffset Created { get; init; } = DateTimeOffset.Now;
}

internal enum TaskEventType
{
    PersistentBackgroundWorker,
    FireOnce,
}