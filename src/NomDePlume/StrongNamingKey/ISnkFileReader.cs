namespace NomDePlume.StrongNamingKey;

public interface ISnkFileReader
{
    Task<SnkFile> ReadSnkFile(string filePath);
    Task<SnkFile> ReadSnkFile(ReadOnlySpan<byte> fileData);
}
