namespace Luxelot.Apps.Common;

public static class DateUtils
{
    public static string GetRelativeTimeString(TimeSpan duration)
    {
        const int MINUTE = 60;
        const int HOUR = 60 * MINUTE;
        const int DAY = 24 * HOUR;
        const int MONTH = 30 * DAY;

        double delta = Math.Abs(duration.TotalSeconds);

        if (delta < 1 * MINUTE)
            return duration.Seconds == 1 ? "one second ago" : duration.Seconds + " seconds ago";

        if (delta < 2 * MINUTE)
            return "a minute ago";

        if (delta < 45 * MINUTE)
            return duration.Minutes + " minutes ago";

        if (delta < 90 * MINUTE)
            return "an hour ago";

        if (delta < 24 * HOUR)
            return duration.Hours + " hours ago";

        if (delta < 48 * HOUR)
            return "yesterday";

        if (delta < 30 * DAY)
            return duration.Days + " days ago";

        if (delta < 12 * MONTH)
        {
            int months = Convert.ToInt32(Math.Floor((double)duration.Days / 30));
            return months <= 1 ? "one month ago" : months + " months ago";
        }
        else
        {
            int years = Convert.ToInt32(Math.Floor((double)duration.Days / 365));
            return years <= 1 ? "one year ago" : years + " years ago";
        }
    }
}