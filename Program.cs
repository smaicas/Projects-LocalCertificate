using Nj.LocalCertificate;

bool exit = false;
do
{
    Console.WriteLine("Create local certificates:");
    Console.WriteLine("Enter 'encryption' or 'e' to create Encryption Certificate");
    Console.WriteLine("Enter 'signing' or 's' to create Signing Certificate");
    Console.WriteLine("Enter 'tls' or 't' to create TLS Certificate");
    string? line = Console.ReadLine();
    string? p;
    switch (line)
    {
        case "encryption" or "e":
            p = ReadPassword();
            if (p == null)
            {
                break;
            }
            await LocalCertificates.CreateEncryptionCertificate(p);
            break;
        case "signing" or "s":
            p = ReadPassword();
            if (p == null)
            {
                break;
            }
            await LocalCertificates.CreateSigningCertificate(p);
            break;
        case "tls" or "t":
            p = ReadPassword();
            if (p == null)
            {
                break;
            }
            await LocalCertificates.CreateTLSCertificate(p);
            break;
        case "exit":
            exit = true;
            break;
    }
} while (!exit);

static string? ReadPassword()
{
    Console.WriteLine("Insert password (min. 8 characters)");
    string? p = Console.ReadLine();
    if (p is { Length: >= 8 }) return p;
    Console.WriteLine("Invalid password");
    return null;

}