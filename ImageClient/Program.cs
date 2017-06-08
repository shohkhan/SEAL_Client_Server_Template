using Microsoft.Research.SEAL;
using PgmImage;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Runtime.Serialization.Formatters.Binary;
using System.Text;
using System.Threading.Tasks;

namespace ImageClient
{
    class Program
    {
        const string location = @"\to\location\";
        const string InputFileName = @"this.Pgm";

        const int PORT_NO = 5000;
        const string SERVER_IP = "127.0.0.1";

        static void Main(string[] args)
        {
            //var location = args[0];
            //var InputFileName = args[1];

            Pgm Picture = new Pgm(location + InputFileName);

            EncCal encCal = new EncCal("1x^4096 + 1", 4096, 40961, 12, 10);

            var encryptedDataBat = GetEncryptedDataInBatches(encCal, Picture);

            var binForm = new BinaryFormatter();

            using (TcpClient client = new TcpClient(SERVER_IP, PORT_NO))
            {
                using (NetworkStream nwStream = client.GetStream())
                {
                    //Fixing the buffer size - not mandatory
                    client.ReceiveBufferSize = 131116; 

                    binForm.Serialize(nwStream, encryptedDataBat.Length);
                    Wait(nwStream, binForm);

                    //Send public key
                    SendEncryptedArray(new BigPolyArray[] { encCal.GetPublicKey() }, nwStream, binForm);

                    //Send encrypted data
                    SendEncryptedArray(encryptedDataBat, nwStream, binForm);

                    //Receive results
                    BigPolyArray[] encryptedResults = ReceiveEncryptedArray(encryptedDataBat.Length / 3, client, nwStream, binForm);

                    byte[] results;

                    //Decrypte data
                    GetResults(Picture, "edg", encryptedResults, encCal, location, InputFileName, out results);

                    Console.ReadLine();
                    client.Close();
                }
            }
            Console.WriteLine("Press return to exit.");
            Console.ReadLine();
        }

        static byte[] GetByteFromEnc(BigPolyArray[] valList, EncCal encCal, Pgm picture, int divisor = 1, int offsetLeft = 0)
        {
            var ret = new byte[picture.Length * picture.Width];

            int slotCount = encCal.CrtBuilder.SlotCount;

            Parallel.For(0, valList.Length, l =>
            {
                var values = new List<BigUInt>(slotCount);

                var plain = encCal.GetDecrypted(valList[l]);

                encCal.CrtBuilder.Decompose(plain, values);

                Parallel.For(0, picture.Width, i =>
                {
                    double val = Convert.ToDouble(values[i + offsetLeft].ToDecimalString()) / divisor;
                    ret[l * picture.Width + i] = Convert.ToByte(val < 0 || val > 40000 ? 0 : val > 255 ? 255 : val);
                });
            });

            return ret;
        }

        public static void GetResults(Pgm picture, string name, BigPolyArray[] encArr,
            EncCal encCal, string location, string InputFileName, out byte[] decArr)
        {
            decArr = GetByteFromEnc(encArr, encCal, picture);
            picture.Save(location + "e_" + name + "_" + InputFileName, decArr);
        }

        private static BigPolyArray[] ReceiveEncryptedArray(int length, TcpClient client, NetworkStream nwStream,
            BinaryFormatter binForm)
        {
            var bytesRead = 0;
            var buffer = new byte[client.ReceiveBufferSize];
            var encryptedDataBat = new BigPolyArray[length];
            for (int i = 0; i < encryptedDataBat.Length; i++)
            {
                buffer = new byte[client.ReceiveBufferSize];
                bytesRead = nwStream.Read(buffer, 0, client.ReceiveBufferSize);

                var arr = new BigPolyArray();
                using (var ms = new MemoryStream())
                {
                    ms.Write(buffer, 0, bytesRead);
                    ms.Seek(0, SeekOrigin.Begin);
                    arr.Load(ms);
                    ms.Flush();
                }
                encryptedDataBat[i] = arr;
                binForm.Serialize(nwStream, "OK");
            }
            return encryptedDataBat;
        }

        private static void SendEncryptedArray(BigPolyArray[] encryptedArray, NetworkStream nwStream, BinaryFormatter binForm)
        {
            //long size = 0;
            foreach (var inv in encryptedArray)
            {
                using (MemoryStream ms = new MemoryStream())
                    WriteToStream(ms, inv, nwStream);
                Wait(nwStream, binForm);
            }
            //Console.WriteLine("Total Size: {0}", size / 1024);
        }

        private static void PrintEncryptedImage(BigPolyArray[] encryptedArray)
        {
            long size = 0;
            StringBuilder image = new StringBuilder();
            for (int i = 0; i < encryptedArray.Length; i++)
            {
                using (MemoryStream ms = new MemoryStream())
                {
                    ms.Seek(0, SeekOrigin.Begin);
                    encryptedArray[i].Save(ms);
                    byte[] bytes = ms.ToArray();
                    size += bytes.Length;
                    foreach (int b in bytes)
                    {
                        image.Append(b);
                        image.Append("\t");
                    }
                    image.AppendLine();
                }
            }
            System.IO.File.WriteAllText(location + InputFileName + "_enc.txt", image.ToString());
            Console.WriteLine("Total Size in bytes: {0}", size);
        }

        private static int WriteToStream(MemoryStream ms, BigPolyArray ip, NetworkStream nwStream)
        {
            ms.Seek(0, SeekOrigin.Begin);
            ip.Save(ms);
            byte[] bytesToSend = ms.ToArray();
            nwStream.Write(bytesToSend, 0, bytesToSend.Length);
            ms.Flush();
            return bytesToSend.Length;
        }

        private static void Wait(NetworkStream nwStream, BinaryFormatter binForm)
        {
            if ((string)binForm.Deserialize(nwStream) != "OK")
            {
                throw new  Exception("Connection not OK"); // Need to define a custom exception
            }
        }

        public static BigPolyArray[] GetEncryptedDataInBatches(EncCal encCal, Pgm picture, int size = 3)
        {
            var encryptedData = new BigPolyArray[picture.Length * size];
            Parallel.For(0, picture.Length, l =>
            {
                int slotCount = encCal.CrtBuilder.SlotCount;
                var values1 = new BigUInt[encCal.CrtBuilder.SlotCount];
                var values2 = new BigUInt[encCal.CrtBuilder.SlotCount];
                var values3 = new BigUInt[encCal.CrtBuilder.SlotCount];
                Parallel.For(0, slotCount, i =>
                {
                    values1[i] = new BigUInt(encCal.GetBitCount(), 0);
                    values2[i] = new BigUInt(encCal.GetBitCount(), 0);
                    values3[i] = new BigUInt(encCal.GetBitCount(), 0);
                });
                Parallel.For(0, picture.Width, i =>
                {
                    values1[i].Set(picture.Data[(l * picture.Length) + i]);
                    values2[i + 1].Set(picture.Data[(l * picture.Length) + i]);
                    values3[i + 2].Set(picture.Data[(l * picture.Length) + i]);
                });
                encryptedData[size * l] = encCal.GetEnc(encCal.CrtBuilder.Compose(values1.ToList()));
                encryptedData[size * l + 1] = encCal.GetEnc(encCal.CrtBuilder.Compose(values2.ToList()));
                encryptedData[size * l + 2] = encCal.GetEnc(encCal.CrtBuilder.Compose(values3.ToList()));
            });
            return encryptedData;
        }
    }

    
}
