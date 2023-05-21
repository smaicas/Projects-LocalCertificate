using Nj.LocalCertificate;

bool exit = false;
do
{
    Console.WriteLine("Create local certificates:");
    Console.WriteLine("Enter 'encryption' or 'e' to create Encryption Certificate");
    Console.WriteLine("Enter 'signing' or 's' to create Signing Certificate");
    string? line = Console.ReadLine();
    switch (line)
    {
        case "encryption" or "e":
            await LocalCertificates.CreateEncryptionCertificate();
            break;
        case "signing" or "s":
            await LocalCertificates.CreateSigningCertificate();
            break;
        case "exit":
            exit = true;
            break;
    }
} while (!exit);
