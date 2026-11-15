using System.Diagnostics.CodeAnalysis;
using System.IO;

namespace NomDePlume;

public readonly record struct FilePath : ISpanParsable<FilePath>
{
    public string Value { get; }

    public FilePath(string path)
    {
        if (!TryNormalize(path, out string? result))
        {
            throw new ArgumentException($"Invalid file path: {path}");
        }

        Value = result;
    }

    private FilePath(string normalizedPath, bool skipValidation) => Value = normalizedPath;

    public string FileName => Path.GetFileName(Value);
    public string Extension => Path.GetExtension(Value);
    public string FileNameWithoutExtension => Path.GetFileNameWithoutExtension(Value);
    public bool Exists => File.Exists(Value);

    public override string ToString() => Value;
    public static implicit operator string(FilePath filePath) => filePath.Value;

    public static FilePath Parse(string s, IFormatProvider? provider)
    {
        ArgumentNullException.ThrowIfNull(s, nameof(s));

        return TryParse(s, provider, out var result) ? result : throw new FormatException($"Invalid file path: {s}");
    }

    public static bool TryParse([NotNullWhen(true)] string? s, IFormatProvider? provider, out FilePath result)
    {
        if (TryNormalize(s, out string? normalizedPath))
        {
            result = new FilePath(normalizedPath, skipValidation: true);
        }

        result = default;
        return false;
    }

    public static FilePath Parse(ReadOnlySpan<char> s, IFormatProvider? provider) => Parse(s.ToString(), provider);

    public static bool TryParse(ReadOnlySpan<char> s, IFormatProvider? provider, out FilePath result)
        => TryParse(s.ToString(), provider, out result);

    public static bool TryNormalize([NotNullWhen(true)] string? path, [NotNullWhen(true)] out string? normalizedPath)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            normalizedPath = null;
            return false;
        }

        try
        {
            normalizedPath = Path.GetFullPath(path);
            return true;
        }
        catch (Exception e) when (e is ArgumentException or NotSupportedException or PathTooLongException)
        {
            normalizedPath = null;
            return false;
        }
    }
}
