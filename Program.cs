using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities.IO.Pem;
using OpenSSL = Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using System;
using System.IO;
using System.Text;

class Program
{
    static void Main(string[] args)
    {
        // Test 1: Create key pair
        (RsaKeyParameters privateRsaKey, RsaKeyParameters publicRsaKey) = CreateRsaKeyPair();

        // Test 2: Export PEM encoded private key in PKCS#8 and PKCS#1 format, export PEM encoded key public in SPKI and PKCS#1 format
        string privatePkcs8Pem = ExportPrivateAsPkcs8Pem(privateRsaKey);
        string privatePkcs1Pem = ExportPrivateAsPkcs1Pem(privateRsaKey);
        string publicSpkiPem = ExportPublicAsSpkiPem(publicRsaKey);
        string publicPkcs1Pem = ExportPublicAsPkcs1Pem(publicRsaKey);
        Console.WriteLine(privatePkcs8Pem);
        Console.WriteLine(privatePkcs1Pem);
        Console.WriteLine(publicSpkiPem);
        Console.WriteLine(publicPkcs1Pem);

        // Test 3: Import PEM encoded private key from PKCS#8 and PKCS#1 format, import PEM encoded public key from SPKI and PKCS#1 format
        RsaKeyParameters privateRsaKeyReloaded1 = ImportPrivateFromPkcs8Pem(privatePkcs8Pem);
        RsaKeyParameters privateRsaKeyReloaded2 = ImportPrivateFromPkcs1Pem(privatePkcs1Pem);
        RsaKeyParameters publicRsaKeyReloaded1 = ImportPublicFromSpkiPem(publicSpkiPem);
        RsaKeyParameters publicRsaKeyReloaded2 = ImportPublicFromPkcs1Pem(publicPkcs1Pem);

        // Test 3a: Encrypt/Decrypt
        byte[] plaintext = Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy dog");
        Sha256Digest digest = new Sha256Digest();
        
        byte[] ciphertext1 = CryptWithOAEP(true, plaintext, publicRsaKeyReloaded1, digest, digest, null); 
        byte[] decrypted1 = CryptWithOAEP(false, ciphertext1, privateRsaKeyReloaded1, digest, digest, null); 
        Console.WriteLine(Convert.ToBase64String(ciphertext1));
        Console.WriteLine(Encoding.UTF8.GetString(decrypted1));
        
        // Test 3b: Encrypt/Decrypt
        byte[] ciphertext2 = CryptWithOAEP(true, plaintext, publicRsaKeyReloaded2, digest, digest, null);
        byte[] decrypted2 = CryptWithOAEP(false, ciphertext2, privateRsaKeyReloaded2, digest, digest, null);
        Console.WriteLine(Convert.ToBase64String(ciphertext2));
        Console.WriteLine(Encoding.UTF8.GetString(decrypted2));
    }

    private static (RsaKeyParameters privateRsa, RsaKeyParameters publicRsa) CreateRsaKeyPair(int size = 2048)
    {
        RsaKeyPairGenerator rsaKeyPairGenerator = new RsaKeyPairGenerator();
        rsaKeyPairGenerator.Init(new KeyGenerationParameters(new SecureRandom(), size));
        AsymmetricCipherKeyPair keyPair = rsaKeyPairGenerator.GenerateKeyPair();
        return (keyPair.Private as RsaKeyParameters, keyPair.Public as RsaKeyParameters);
    }

    private static string ExportPrivateAsPkcs8Pem(RsaKeyParameters privateKey)
    {
        OpenSSL.Pkcs8Generator pkcs8Generator = new OpenSSL.Pkcs8Generator(privateKey);
        PemObject pemObjectPkcs8 = pkcs8Generator.Generate();
        OpenSSL.PemWriter pemWriter = new OpenSSL.PemWriter(new StringWriter());
        pemWriter.WriteObject(pemObjectPkcs8);
        return pemWriter.Writer.ToString();
    }

    private static string ExportPrivateAsPkcs1Pem(RsaKeyParameters privateKey)
    {
        OpenSSL.PemWriter pemWriter = new OpenSSL.PemWriter(new StringWriter());
        pemWriter.WriteObject(privateKey);
        return pemWriter.Writer.ToString();
    }

    private static string ExportPublicAsSpkiPem(RsaKeyParameters publicKey)
    {
        OpenSSL.PemWriter pemWriter = new OpenSSL.PemWriter(new StringWriter());
        pemWriter.WriteObject(publicKey);
        return pemWriter.Writer.ToString();
    }

    private static string ExportPublicAsPkcs1Pem(RsaKeyParameters publicKey)
    {
        OpenSSL.PemWriter pemWriter = new OpenSSL.PemWriter(new StringWriter());
        byte[] publicKeyPkcs1 = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey).ParsePublicKey().GetEncoded();
        pemWriter.WriteObject(new PemObject("RSA PUBLIC KEY", publicKeyPkcs1));
        return pemWriter.Writer.ToString();
    }

    private static RsaKeyParameters ImportPrivateFromPkcs8Pem(string privatePkcs8Pem)
    {
        OpenSSL.PemReader pemReader = new OpenSSL.PemReader(new StringReader(privatePkcs8Pem));
        return (RsaKeyParameters)pemReader.ReadObject();
    }

    private static RsaKeyParameters ImportPrivateFromPkcs1Pem(string privatePkcs1Pem)
    {
        OpenSSL.PemReader pemReader = new OpenSSL.PemReader(new StringReader(privatePkcs1Pem));
        return (RsaKeyParameters)((AsymmetricCipherKeyPair)pemReader.ReadObject()).Private;
    }

    private static RsaKeyParameters ImportPublicFromSpkiPem(string publicSpkiPem)
    {
        OpenSSL.PemReader pemReader = new OpenSSL.PemReader(new StringReader(publicSpkiPem));
        return (RsaKeyParameters)pemReader.ReadObject();
    }
    private static RsaKeyParameters ImportPublicFromPkcs1Pem(string publicPkcs1Pem)
    {
        OpenSSL.PemReader prPublic = new OpenSSL.PemReader(new StringReader(publicPkcs1Pem));
        return (RsaKeyParameters)prPublic.ReadObject();
    }

    private static byte[] CryptWithOAEP(bool IsEncrypt, byte[] data, RsaKeyParameters key, IDigest oaepDigest, IDigest mgf1Digest, byte[] label = null)
    {
        OaepEncoding oaepEncoding = new OaepEncoding(new RsaEngine(), oaepDigest, mgf1Digest, label);
        oaepEncoding.Init(IsEncrypt, key);
        return oaepEncoding.ProcessBlock(data, 0, data.Length);
    }
}

