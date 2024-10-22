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
using Org.BouncyCastle.Crypto.Signers;

class Program
{
    static void Main(string[] args)
    {
        ISigner sig = SignerUtilities.GetSigner("NoneWithRSA");

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
        RsaKeyParameters privateRsaKeyReloaded1 = (RsaKeyParameters)ImportPrivateFromPkcs8Pem(privatePkcs8Pem);
        RsaKeyParameters privateRsaKeyReloaded2 = ImportPrivateFromPkcs1Pem(privatePkcs1Pem);
        RsaKeyParameters publicRsaKeyReloaded1 = (RsaKeyParameters)ImportPublicFromSpkiPem(publicSpkiPem);
        RsaKeyParameters publicRsaKeyReloaded2 = ImportPublicFromPkcs1Pem(publicPkcs1Pem);

        // Test 4a: Encrypt/Decrypt with OAEP
        byte[] plaintext = Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy dog");
        Sha256Digest digest = new Sha256Digest();
        
        byte[] ciphertext1 = RsaCryptWithOAEP(true, plaintext, publicRsaKeyReloaded1, digest, digest, null); 
        byte[] decrypted1 = RsaCryptWithOAEP(false, ciphertext1, privateRsaKeyReloaded1, digest, digest, null); 
        Console.WriteLine(Convert.ToBase64String(ciphertext1));
        Console.WriteLine(Encoding.UTF8.GetString(decrypted1));
        Console.WriteLine();
        
        // Test 4b: Encrypt/Decrypt with PKCS#1 v1.5
        byte[] ciphertext2 = RsaCryptWithPkcs1v15(true, plaintext, publicRsaKeyReloaded2);
        byte[] decrypted2 = RsaCryptWithPkcs1v15(false, ciphertext2, privateRsaKeyReloaded2);
        Console.WriteLine(Convert.ToBase64String(ciphertext2));
        Console.WriteLine(Encoding.UTF8.GetString(decrypted2));
        Console.WriteLine();

        // Test 5a: Sign/Verify with PSS
        byte[] message = Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy dog");
        digest = new Sha256Digest();

        byte[] signature = RsaSignWithPSS(message, privateRsaKeyReloaded1, digest, digest, 32, 0xbc);
        bool verified = RsaVerifyWithPSS(message, signature, publicRsaKeyReloaded1, digest, digest); 
        Console.WriteLine(Convert.ToBase64String(signature));
        Console.WriteLine(verified);
        Console.WriteLine();

        // Test 5b: Sign/Verify with Pkcs#1 v1.5
        signature = RsaSignWithPkcs1v15(message, privateRsaKeyReloaded1, digest);
        verified = RsaVerifyWithPkcs1v15(message, signature, publicRsaKeyReloaded1, digest); 
        Console.WriteLine(Convert.ToBase64String(signature));
        Console.WriteLine(verified);
    }

    public static (RsaKeyParameters privateRsa, RsaKeyParameters publicRsa) CreateRsaKeyPair(int size = 2048)
    {
        RsaKeyPairGenerator rsaKeyPairGenerator = new RsaKeyPairGenerator();
        rsaKeyPairGenerator.Init(new KeyGenerationParameters(new SecureRandom(), size));
        AsymmetricCipherKeyPair keyPair = rsaKeyPairGenerator.GenerateKeyPair();
        return (keyPair.Private as RsaKeyParameters, keyPair.Public as RsaKeyParameters);
    }

    public static string ExportPrivateAsPkcs8Pem(AsymmetricKeyParameter privateKey)
    {
        OpenSSL.Pkcs8Generator pkcs8Generator = new OpenSSL.Pkcs8Generator(privateKey);
        PemObject pemObjectPkcs8 = pkcs8Generator.Generate();
        OpenSSL.PemWriter pemWriter = new OpenSSL.PemWriter(new StringWriter());
        pemWriter.WriteObject(pemObjectPkcs8);
        return pemWriter.Writer.ToString();
    }

    public static string ExportPrivateAsPkcs1Pem(RsaKeyParameters privateKey)
    {
        OpenSSL.PemWriter pemWriter = new OpenSSL.PemWriter(new StringWriter());
        pemWriter.WriteObject(privateKey);
        return pemWriter.Writer.ToString();
    }

    public static string ExportPublicAsSpkiPem(AsymmetricKeyParameter publicKey)
    {
        OpenSSL.PemWriter pemWriter = new OpenSSL.PemWriter(new StringWriter());
        pemWriter.WriteObject(publicKey);
        return pemWriter.Writer.ToString();
    }

    public static string ExportPublicAsPkcs1Pem(RsaKeyParameters publicKey)
    {
        OpenSSL.PemWriter pemWriter = new OpenSSL.PemWriter(new StringWriter());
        byte[] publicKeyPkcs1 = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey).ParsePublicKey().GetEncoded();
        pemWriter.WriteObject(new PemObject("RSA PUBLIC KEY", publicKeyPkcs1));
        return pemWriter.Writer.ToString();
    }

    public static AsymmetricKeyParameter ImportPrivateFromPkcs8Pem(string privatePkcs8Pem)
    {
        OpenSSL.PemReader pemReader = new OpenSSL.PemReader(new StringReader(privatePkcs8Pem));
        return (AsymmetricKeyParameter)pemReader.ReadObject();
    }

    public static RsaKeyParameters ImportPrivateFromPkcs1Pem(string privatePkcs1Pem)
    {
        OpenSSL.PemReader pemReader = new OpenSSL.PemReader(new StringReader(privatePkcs1Pem));
        return (RsaKeyParameters)((AsymmetricCipherKeyPair)pemReader.ReadObject()).Private;
    }

    public static AsymmetricKeyParameter ImportPublicFromSpkiPem(string publicSpkiPem)
    {
        OpenSSL.PemReader pemReader = new OpenSSL.PemReader(new StringReader(publicSpkiPem));
        return (AsymmetricKeyParameter)pemReader.ReadObject();
    }
    public static RsaKeyParameters ImportPublicFromPkcs1Pem(string publicPkcs1Pem)
    {
        OpenSSL.PemReader prPublic = new OpenSSL.PemReader(new StringReader(publicPkcs1Pem));
        return (RsaKeyParameters)prPublic.ReadObject();
    }

    public static byte[] RsaCryptWithOAEP(bool IsEncrypt, byte[] data, RsaKeyParameters key, IDigest oaepDigest, IDigest mgf1Digest, byte[] label = null)
    {
        OaepEncoding oaepEncoding = new OaepEncoding(new RsaEngine(), oaepDigest, mgf1Digest, label);
        oaepEncoding.Init(IsEncrypt, key);
        return oaepEncoding.ProcessBlock(data, 0, data.Length);
    }

    public static byte[] RsaCryptWithPkcs1v15(bool IsEncrypt, byte[] data, RsaKeyParameters key)
    {
        Pkcs1Encoding oaepEncoding = new Pkcs1Encoding(new RsaEngine());
        oaepEncoding.Init(IsEncrypt, key);
        return oaepEncoding.ProcessBlock(data, 0, data.Length);
    }

    private static ISigner RsaSignVerifyWithPSS(bool IsSign, byte[] msg, RsaKeyParameters key, IDigest oaepDigest, IDigest mgf1Digest, int saltLen = -1, byte trailerField = 0xbc)
    {
        ISigner signerVerifier = new PssSigner(new RsaEngine(), oaepDigest, mgf1Digest, saltLen == -1 ? oaepDigest.GetDigestSize() : saltLen, trailerField);
        signerVerifier.Init(IsSign, key);
        signerVerifier.BlockUpdate(msg, 0, msg.Length);
        return signerVerifier;
    }

    public static byte[] RsaSignWithPSS(byte[] msg, RsaKeyParameters key, IDigest oaepDigest, IDigest mgf1Digest, int saltLen = -1, byte trailerField = 0xbc)
    {
        ISigner signer = RsaSignVerifyWithPSS(true, msg, key, oaepDigest, mgf1Digest, saltLen, trailerField);
        return signer.GenerateSignature();
    }

    public static bool RsaVerifyWithPSS(byte[] msg, byte[] signature, RsaKeyParameters key, IDigest oaepDigest, IDigest mgf1Digest, int saltLen = -1, byte trailerField = 0xbc)
    {
        ISigner verifier = RsaSignVerifyWithPSS(false, msg, key, oaepDigest, mgf1Digest, saltLen, trailerField);
        return verifier.VerifySignature(signature);
    }

    
    private static ISigner RsaSignVerifyWithPkcs1v15(bool IsSign, byte[] msg, RsaKeyParameters key, IDigest digest)
    {
        RsaDigestSigner signerVerifier = new RsaDigestSigner(digest);
        signerVerifier.Init(IsSign, key);
        signerVerifier.BlockUpdate(msg, 0, msg.Length);
        return signerVerifier;
    }

    public static byte[] RsaSignWithPkcs1v15(byte[] msg, RsaKeyParameters key, IDigest digest)
    {
        ISigner signer = RsaSignVerifyWithPkcs1v15(true, msg, key, digest);
        return signer.GenerateSignature();
    }

    public static bool RsaVerifyWithPkcs1v15(byte[] msg, byte[] signature, RsaKeyParameters key, IDigest digest)
    {
        ISigner verifier = RsaSignVerifyWithPkcs1v15(false, msg, key, digest);
        return verifier.VerifySignature(signature);
    }
}
