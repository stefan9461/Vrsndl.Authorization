namespace Vrsndl.Authorization.Client;

public static class FileExtensions
{
    public static string? FindFullFilePath(string? fileName)
    {
        if (fileName == null)
            return null;

        var baseDir = AppDomain.CurrentDomain.BaseDirectory;

        return FindFullFilePath(baseDir, Path.GetFileNameWithoutExtension(fileName), Path.GetExtension(fileName));
    }

    public static string? FindFullFilePath(string path, string name, string extension)
    {
        var files = Directory.GetFiles(path, $"*{extension}");
        var fileName = $"{name}{extension}";
        var foundFiles = files.Where(f => f.EndsWith(fileName, StringComparison.CurrentCultureIgnoreCase));
        if (foundFiles.Any())
        {
            var foundFile = files.FirstOrDefault(f => f.EndsWith(fileName, StringComparison.CurrentCulture));
            return foundFile;
        }

        var directories = Directory.GetDirectories(path);
        foreach (var directory in directories)
        {
            var foundFile = FindFullFilePath(directory, name, extension);
            if (foundFile != null)
                return foundFile;
        }

        return null;
    }
}
