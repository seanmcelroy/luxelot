namespace Luxelot.DHT;

public record class Bucket
{
    public BucketEntry[] Entries { get; init; } = new BucketEntry[Constants.K];
}