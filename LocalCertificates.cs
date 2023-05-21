using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Nj.LocalCertificate;

public static class LocalCertificates
{
    private const string EncryptionCertFilePath = "encryption-cert.pfx";
    private const string SigningCertFilePath = "signing-cert.pfx";
    private const string EncryptionCertFriendlyName = "OpenIddict Server Development Encryption Certificate";
    private const string SigningCertFriendlyName = "OpenIddict Server Development Signing Certificate";

    public static async Task CreateEncryptionCertificate(string certificatePassword)
    {
        using var algorithm = RSA.Create(keySizeInBits: 2048);

        var request = new CertificateRequest(
            subjectName: "CN=Encryption Certificate",
            key: algorithm,
            hashAlgorithm: HashAlgorithmName.SHA256,
            padding: RSASignaturePadding.Pkcs1);

        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.KeyEncipherment, critical: true));

        var certificate = request.CreateSelfSigned(
            notBefore: DateTimeOffset.UtcNow,
            notAfter: DateTimeOffset.UtcNow.AddYears(2));

        SetFriendlyName(certificate, EncryptionCertFriendlyName);

        var data = certificate.Export(X509ContentType.Pfx, certificatePassword);
        var finalFile = $"{Directory.GetCurrentDirectory()}\\{EncryptionCertFilePath}";
        await File.WriteAllBytesAsync(finalFile, data);
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Black;
        Console.BackgroundColor = ConsoleColor.Green;
        Console.WriteLine($"Written {finalFile}");
        Console.ResetColor();
        Console.WriteLine();
    }

    public static async Task CreateSigningCertificate(string certificatePassword)
    {
        using var algorithm = RSA.Create(keySizeInBits: 2048);

        var request = new CertificateRequest(
            subjectName: "CN=Signing Certificate",
            key: algorithm,
            hashAlgorithm: HashAlgorithmName.SHA256,
            padding: RSASignaturePadding.Pkcs1);

        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: true));

        var certificate = request.CreateSelfSigned(
            notBefore: DateTimeOffset.UtcNow,
            notAfter: DateTimeOffset.UtcNow.AddYears(2));

        SetFriendlyName(certificate, SigningCertFriendlyName);

        // Note: CertificateRequest.CreateSelfSigned() doesn't mark the key set associated with the certificate 
        // as "persisted", which eventually prevents X509Store.Add() from correctly storing the private key. 
        // To work around this issue, the certificate payload is manually exported and imported back 
        // into a new X509Certificate2 instance specifying the X509KeyStorageFlags.PersistKeySet flag. 
        var data = certificate.Export(X509ContentType.Pfx, certificatePassword);
        var finalFile = $"{Directory.GetCurrentDirectory()}\\{SigningCertFilePath}";
        await File.WriteAllBytesAsync(finalFile, data);
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Black;
        Console.BackgroundColor = ConsoleColor.Green;
        Console.WriteLine($"Written {finalFile}");
        Console.ResetColor();
        Console.WriteLine();
    }

    private static void SetFriendlyName(X509Certificate2 certificate, string friendlyName)
    {
        // Note: setting the friendly name is not supported on Unix machines (including Linux and macOS). 
        // To ensure an exception is not thrown by the property setter, an OS runtime check is used here. 
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            certificate.FriendlyName = friendlyName;
        }
    }
}