namespace Luxelot.Apps.DhtApp;

public record class Bucket
{
    public BucketEntry[] Entries { get; init; } = new BucketEntry[Constants.K];
}