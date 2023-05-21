﻿using Nj.LocalCertificate;

bool exit = false;
do
{
    Console.WriteLine("Create local certificates:");
    Console.WriteLine("Enter 'encryption' or 'e' to create Encryption Certificate");
    Console.WriteLine("Enter 'signing' or 's' to create Signing Certificate");
    string? line = Console.ReadLine();
    string? p;
    switch (line)
    {
        case "encryption" or "e":
            Console.WriteLine("Insert password (min. 8 characters)");
            p = ReadPassword();
            if (p == null)
            {
                break;
            }
            await LocalCertificates.CreateEncryptionCertificate(p);
            break;
        case "signing" or "s":
            Console.WriteLine("Insert password (min. 8 characters)");
            p = ReadPassword();
            if (p == null)
            {
                break;
            }
            await LocalCertificates.CreateSigningCertificate(p);
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