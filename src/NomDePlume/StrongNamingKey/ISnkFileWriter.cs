namespace NomDePlume.StrongNamingKey;

public interface ISnkFileWriter
{
    Task WriteSnkFile(SnkFile snkFile, FilePath filePath);
}
