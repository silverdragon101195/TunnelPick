using System.IO;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace TunnelPick.App.Native;

/// <summary>
/// The root CA that issued TunnelPick's code-signing certificate, embedded so a signed build can make
/// Windows trust its own signature.
/// </summary>
internal static class SigningRoot
{
    private const string ResourceName = "HoshizoraRootCA.crt";

    /// <summary>
    /// Adds the embedded root CA to the local machine's Trusted Root Certification Authorities store
    /// when the store lacks it and this executable is signed by a certificate the root issued.
    /// Unsigned builds never change the store. Requires elevation.
    /// </summary>
    /// <exception cref="CryptographicException">The store could not be read or written.</exception>
    public static void EnsureTrusted()
    {
        using var root = LoadRoot();
        if (IsInstalled(root))
            return;

        using var signer = ReadSigner(Environment.ProcessPath!);
        if (signer is null || !ChainsTo(signer, root))
            return;

        using var store = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadWrite);
        store.Add(root);
    }

    private static X509Certificate2 LoadRoot()
    {
        using var stream = typeof(SigningRoot).Assembly.GetManifestResourceStream(ResourceName)!;
        using var reader = new StreamReader(stream);
        return X509Certificate2.CreateFromPem(reader.ReadToEnd());
    }

    private static bool IsInstalled(X509Certificate2 root)
    {
        using var store = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadOnly);
        return store.Certificates.Find(X509FindType.FindByThumbprint, root.Thumbprint, validOnly: false).Count > 0;
    }

    /// <summary>Returns the signer certificate of the file's Authenticode signature, or null when the file is unsigned.</summary>
    private static X509Certificate2? ReadSigner(string path)
    {
        using var file = File.OpenRead(path);
        var table = new PEHeaders(file).PEHeader!.CertificateTableDirectory;
        if (table.Size == 0)
            return null;

        // This directory entry holds a file offset, not an RVA. The first WIN_CERTIFICATE in it is an
        // 8-byte header followed by the PKCS #7 SignedData of the signature.
        var entry = new byte[table.Size];
        file.Position = table.RelativeVirtualAddress;
        file.ReadExactly(entry);

        var signedData = new SignedCms();
        signedData.Decode(entry.AsSpan(8));
        return signedData.SignerInfos[0].Certificate;
    }

    private static bool ChainsTo(X509Certificate2 certificate, X509Certificate2 root)
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(root);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        // Timestamped signatures stay valid after the signing certificate expires.
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.IgnoreNotTimeValid;
        return chain.Build(certificate);
    }
}
