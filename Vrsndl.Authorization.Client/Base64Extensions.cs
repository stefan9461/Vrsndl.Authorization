namespace Vrsndl.Authorization.Client;

public static class Base64Extensions
{
    public static bool IsBas64UrlEncoded(this string base64)
    {
        if (string.IsNullOrEmpty(base64))
            return false;

        return !base64.Contains('=') && !base64.Contains('+') && !base64.Contains('/');
    }

    public static bool IsBas64Strict(this string base64)
    {
        if (string.IsNullOrEmpty(base64))
            return false;

        var mod = base64.Length % 4;
        return !base64.Contains('-') && !base64.Contains('_') && mod == 0;
    }

    public static byte[]? DecodeBase64ToBytes(this string base64)
    {
        if (string.IsNullOrEmpty(base64))
            return null;

        return base64.IsBas64UrlEncoded()
            ? Base64UrlEncoder.DecodeBytes(base64)
            : Convert.FromBase64String(base64);
    }

    public static string? DecodeBase64(this string base64)
    {
        if (string.IsNullOrEmpty(base64))
            return null;

        var bytes = base64.DecodeBase64ToBytes();
        if (bytes == null)
            return null;

        return Encoding.UTF8.GetString(bytes);
    }

    public static string? EncodeAsBase64UrlEncoded(this string input)
    {
        if (string.IsNullOrEmpty(input))
            return null;

        return Base64UrlEncoder.Encode(input);
    }

    public static string? EncodeAsBase64UrlEncoded(this byte[] input)
    {
        if (input == null)
            return null;

        return Base64UrlEncoder.Encode(input);
    }

    public static string? EncodeAsBase64Strict(this string? input)
    {
        if (string.IsNullOrEmpty(input))
            return null;

        var bytes = Encoding.UTF8.GetBytes(input);
        return bytes.EncodeAsBase64Strict();
    }

    public static string? EncodeAsBase64Strict(this byte[] input)
    {
        if (input == null)
            return null;

        return Convert.ToBase64String(input);
    }
}
