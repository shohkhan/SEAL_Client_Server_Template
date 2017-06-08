using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Microsoft.Research.SEAL;

namespace ImageServer
{
    public class EncCal
    {
        private EncryptionParameters parms;
        private static IntegerEncoder encoder;
        private Encryptor encryptor;
        private Evaluator evaluator;
        public PolyCRTBuilder CrtBuilder { get; set; }

        public EncCal(BigPolyArray publicKey, string polyMod, int coeffDefault, ulong plainMod)
        {
            // Create encryption parameters.
            parms = new EncryptionParameters();
            parms.PolyModulus.Set(polyMod);
            parms.CoeffModulus.Set(ChooserEvaluator.DefaultParameterOptions[coeffDefault]);
            parms.PlainModulus.Set(plainMod);
            //parms.DecompositionBitCount = 12;
            // Create encoder (for encoding and decoding)
            encoder = new IntegerEncoder(parms.PlainModulus);
            //encoder = new FractionalEncoder(parms.PlainModulus, parms.PolyModulus, 64, 32, 3);

            //Create Encryptor // not mandatory
            encryptor = new Encryptor(parms, publicKey);

            //Create Evaluator for arithmatic operations
            evaluator = new Evaluator(parms);

            CrtBuilder = new PolyCRTBuilder(parms);
        }

        internal int GetBitCount()
        {
            return parms.PlainModulus.BitCount;
        }

        public BigPolyArray GetEnc(int value)
        {
            var encoded = encoder.Encode(value);
            var encrypted = encryptor.Encrypt(encoded);
            return encrypted;
        }

        public BigPolyArray GetEnc(BigPoly value)
        {
            var encrypted = encryptor.Encrypt(value);
            return encrypted;
        }

        public BigPolyArray GetZero()
        {
            var value = 0;
            var encoded = encoder.Encode(value);
            var encrypted = encryptor.Encrypt(encoded);
            return encrypted;
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
            //encrypted1 = Relinearize(encrypted1);
            //encrypted2 = Relinearize(encrypted2);
            return evaluator.Multiply(encrypted1, encrypted2);
        }

        public BigPolyArray MultiplyPlain(BigPolyArray encrypted1, int unencrypted2)
        {
            //encrypted1 = Relinearize(encrypted1);
            var encoded2 = encoder.Encode(unencrypted2);
            return evaluator.MultiplyPlain(encrypted1, encoded2);
        }

        public BigPolyArray MultiplyPlain(BigPolyArray encrypted1, BigPoly encoded2)
        {
            //encrypted1 = Relinearize(encrypted1);
            return evaluator.MultiplyPlain(encrypted1, encoded2);
        }

        public BigPolyArray Negate(BigPolyArray encrypted1)
        {
            return evaluator.Negate(encrypted1);
        }

        //private BigPolyArray Relinearize(BigPolyArray e)
        //{
        //    if (e.Size > 4)
        //    {
        //        e = evaluator.Relinearize(e);
        //    }
        //    return e;
        //}
    }
}
