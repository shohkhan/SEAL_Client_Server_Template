using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Research.SEAL;

namespace ImageClient
{
    public class EncCal
    {
        private EncryptionParameters parms;
        private static IntegerEncoder encoder;
        private KeyGenerator generator;
        private Encryptor encryptor;
        private Decryptor decryptor;
        private Evaluator evaluator;
        private BigPolyArray publicKey;
        private BigPoly secretKey;
        private EvaluationKeys evaluationKeys;
        public PolyCRTBuilder CrtBuilder { get; set; }

        public EncCal(string polyMod, int coeffDefault, ulong plainMod, int dbc, int noOfEvaluationKeys)
        {

            // Create encryption parameters.
            parms = new EncryptionParameters();
            parms.PolyModulus.Set(polyMod);
            parms.CoeffModulus.Set(ChooserEvaluator.DefaultParameterOptions[coeffDefault]);
            parms.PlainModulus.Set(plainMod);
            // Generate keys.
            generator = new KeyGenerator(parms);
            generator.Generate(noOfEvaluationKeys);     //Integer
            // Generator contains the keys
            publicKey = generator.PublicKey;
            secretKey = generator.SecretKey;
            evaluationKeys = generator.EvaluationKeys;
            // Create encoder (for encoding and decoding)
            encoder = new IntegerEncoder(parms.PlainModulus);        //Integer
            //Create Encryptor
            encryptor = new Encryptor(parms, publicKey);
            //Create Decryptor
            decryptor = new Decryptor(parms, secretKey);
            //Create Evaluator for arithmatic operations
            evaluator = new Evaluator(parms);
            CrtBuilder = new PolyCRTBuilder(parms);
        }

        internal int GetBitCount()
        {
            return parms.PlainModulus.BitCount;
        }

        public EncryptionParameters GetParams()
        {
            return parms;
        }

        public BigPolyArray GetPublicKey()
        {
            return publicKey;
        }

        public BigPolyArray GetEnc(int value)
        {
            var encoded = encoder.Encode(value);
            var encrypted = encryptor.Encrypt(encoded);
            return encrypted;
        }

        internal BigPolyArray MultiplyPlain(BigPolyArray encrypted, BigPoly encoded)
        {
            return evaluator.MultiplyPlain(encrypted, encoded);
        }

        public BigPolyArray GetEnc(BigPoly encoded)
        {
            var encrypted = encryptor.Encrypt(encoded);
            return encrypted;
        }

        public BigPolyArray GetZero()
        {
            var value = 0;
            var encoded = encoder.Encode(value);
            var encrypted = encryptor.Encrypt(encoded);
            return encrypted;
        }

        internal BigPolyArray AddMany(List<BigPolyArray> v)
        {
            return evaluator.AddMany(v);
        }

        public BigPolyArray Add(BigPolyArray encrypted1, BigPolyArray encrypted2)
        {
            return evaluator.Add(encrypted1, encrypted2);
        }

        public BigPolyArray Sub(BigPolyArray encrypted1, BigPolyArray encrypted2)
        {
            return evaluator.Sub(encrypted1, encrypted2);
        }

        public BigPolyArray Multiply(BigPolyArray encrypted1, BigPolyArray encrypted2)
        {
            return evaluator.Multiply(encrypted1, encrypted2);
        }

        public BigPolyArray MultiplyPlain(BigPolyArray encrypted1, int unencrypted2)
        {
            var encoded2 = encoder.Encode(unencrypted2);
            return evaluator.MultiplyPlain(encrypted1, encoded2);
        }

        public BigPolyArray Negate(BigPolyArray encrypted1)
        {
            return evaluator.Negate(encrypted1);
        }

        public BigPolyArray Square(BigPolyArray n)
        {
            return evaluator.Square(n);
        }

        internal BigPoly GetDecrypted(BigPolyArray enc)
        {
            var decrypted = decryptor.Decrypt(enc);
            return decrypted;
        }
        public List<Tuple<BigPolyArray, BigPolyArray>> GetEvaluationKeys()
        {
            return evaluationKeys.Keys;
        }
    }
}
