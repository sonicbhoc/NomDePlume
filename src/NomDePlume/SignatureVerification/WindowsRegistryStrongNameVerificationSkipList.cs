using Microsoft.Win32;

namespace NomDePlume.SignatureVerification;

public sealed class WindowsRegistryStrongNameVerificationSkipList : IStrongNameVerificationSkipList
{
    private const string RegistryPath = @"SOFTWARE\Microsoft\StrongName\Verification";

    public bool IsVerificationSkipped(string assemblyPath, string assemblyName, string publicKeyToken)
    {
        if (!OperatingSystem.IsWindows())
        {
            return false;
        }

        RegistryView[] registryViews = Environment.Is64BitOperatingSystem
            ? [RegistryView.Registry64, RegistryView.Registry32]
            : [RegistryView.Registry32];

        foreach (RegistryView registryView in registryViews)
        {
            using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, registryView);
            using RegistryKey? verificationKey = baseKey.OpenSubKey(RegistryPath);
            if (verificationKey is null)
            {
                continue;
            }

            if (verificationKey.GetSubKeyNames().Any(entry =>
                    StrongNameVerificationSkipEntry.Matches(entry, assemblyPath, assemblyName, publicKeyToken))
                || verificationKey.GetValueNames().Any(entry =>
                    StrongNameVerificationSkipEntry.Matches(entry, assemblyPath, assemblyName, publicKeyToken)))
            {
                return true;
            }
        }

        return false;
    }
}

internal static class StrongNameVerificationSkipEntry
{
    internal static bool Matches(
        string entry,
        string assemblyPath,
        string assemblyName,
        string publicKeyToken)
    {
        int separator = entry.LastIndexOf(',');
        if (separator < 0)
        {
            return false;
        }

        string registeredToken = entry[(separator + 1)..].Trim();
        const string tokenPrefix = "PublicKeyToken=";
        if (registeredToken.StartsWith(tokenPrefix, StringComparison.OrdinalIgnoreCase))
        {
            registeredToken = registeredToken[tokenPrefix.Length..];
        }

        if (!registeredToken.Equals(publicKeyToken, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        string registeredAssembly = entry[..separator].Trim().Trim('"');
        if (registeredAssembly == "*")
        {
            return true;
        }

        string simpleName = registeredAssembly.Split(',', 2)[0].Trim();
        return simpleName.Equals(assemblyName, StringComparison.OrdinalIgnoreCase)
            || registeredAssembly.Equals(assemblyPath, StringComparison.OrdinalIgnoreCase);
    }
}
