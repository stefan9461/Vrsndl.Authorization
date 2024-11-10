namespace Vrsndl.Authorization.Client;

public static class RsaExtensions
{
    private static readonly string FILLER = "-----";
    private static readonly string BEGIN = "BEGIN";
    private static readonly string END = "END";
    private static readonly string RSA_PRIVATE_KEY = "RSA PRIVATE KEY";
    private static readonly string RSA_PRIVATE_KEY_BEGIN = $"{FILLER}{BEGIN} {RSA_PRIVATE_KEY}{FILLER}";
    private static readonly string RSA_PRIVATE_KEY_END = $"{FILLER}{END} {RSA_PRIVATE_KEY}{FILLER}";
    private static readonly string PRIVATE_KEY = "PRIVATE KEY";
    private static readonly string PRIVATE_KEY_BEGIN = $"{FILLER}{BEGIN} {PRIVATE_KEY}{FILLER}";
    private static readonly string PRIVATE_KEY_END = $"{FILLER}{END} {PRIVATE_KEY}{FILLER}";
    private static readonly string RSA_PUBLIC_KEY = "RSA PUBLIC KEY";
    private static readonly string RSA_PUBLIC_KEY_BEGIN = $"{FILLER}{BEGIN} {RSA_PUBLIC_KEY}{FILLER}";
    private static readonly string RSA_PUBLIC_KEY_END = $"{FILLER}{END} {RSA_PUBLIC_KEY}{FILLER}";
    private static readonly string PUBLIC_KEY = "PUBLIC KEY";
    private static readonly string PUBLIC_KEY_BEGIN = $"{FILLER}{BEGIN} {PUBLIC_KEY}{FILLER}";
    private static readonly string PUBLIC_KEY_END = $"{FILLER}{END} {PUBLIC_KEY}{FILLER}";

    public static string ExportPrivateKeyAsPem(this RSA rsa)
    {
        if (rsa == null)
            return string.Empty;

        var privKey = rsa.ExportRSAPrivateKey();
        var privKeyString = Convert.ToBase64String(privKey);
        return exportKeyAsPem(privKeyString, RSA_PRIVATE_KEY_BEGIN, RSA_PRIVATE_KEY_END);
    }

    public static string ExportPublicKeyAsPem(this RSA rsa)
    {
        if (rsa == null)
            return string.Empty;

        var privKey = rsa.ExportRSAPublicKey();
        var privKeyString = Convert.ToBase64String(privKey);
        return exportKeyAsPem(privKeyString, RSA_PUBLIC_KEY_BEGIN, RSA_PUBLIC_KEY_END);
    }

    private static string exportKeyAsPem(string keyString, string begin, string end)
    {
        var result = new StringBuilder();
        result.AppendLine(begin);
        const int LINE_LENGTH = 64;
        int offset = 0;
        while (offset < keyString.Length)
        {
            var lineEnd = Math.Min(offset + LINE_LENGTH, keyString.Length);
            result.AppendLine(keyString.Substring(offset, lineEnd - offset));
            offset = lineEnd;
        }
        result.AppendLine(end);
        return result.ToString();
    }

    public static RSA? ImportPublicKeyFromPem(this string pem)
    {
        string[] lines = pem.Split(new string[] { Environment.NewLine }, StringSplitOptions.None);

        string base64 = GetBase64FromLines(lines, RSA_PUBLIC_KEY_BEGIN, RSA_PUBLIC_KEY_END);

        if (string.IsNullOrEmpty(base64))
            base64 = GetBase64FromLines(lines, PUBLIC_KEY_BEGIN, PUBLIC_KEY_END);

        if (!string.IsNullOrEmpty(base64))
        {
            var bytes = Convert.FromBase64String(base64);
            RSA rsa = RSA.Create();
            rsa.ImportRSAPublicKey(bytes, out _);
            return rsa;
        }

        return null;
    }

    public static RSA? ImportPrivateKeyFromPem(this string pem)
    {
        string[] lines = pem.Split(new string[] { Environment.NewLine }, StringSplitOptions.None);

        string base64 = GetBase64FromLines(lines, RSA_PRIVATE_KEY_BEGIN, RSA_PRIVATE_KEY_END);

        if (string.IsNullOrEmpty(base64))
            base64 = GetBase64FromLines(lines, PRIVATE_KEY_BEGIN, PRIVATE_KEY_END);

        if (!string.IsNullOrEmpty(base64))
        {
            var bytes = Convert.FromBase64String(base64);
            RSA rsa = RSA.Create();
            rsa.ImportRSAPrivateKey(bytes, out _);
            return rsa;
        }

        return null;
    }

    private static string GetBase64FromLines(string[] lines, string beginTag, string endTag)
    {
        string base64 = string.Empty;
        int beginFound = lines.Length;
        int endFound = -1;
        for (int i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            beginFound = string.Equals(line, beginTag, StringComparison.OrdinalIgnoreCase) ? i : beginFound;
            endFound = string.Equals(line, endTag, StringComparison.OrdinalIgnoreCase) ? i : endFound;
            if (i > beginFound && endFound == -1)
                base64 += line;
        }

        if (beginFound < endFound)
            return base64;
        return string.Empty;
    }
}