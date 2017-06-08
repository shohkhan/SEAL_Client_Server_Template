using Microsoft.Research.SEAL;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.Serialization.Formatters.Binary;
using System.Text;
using System.Threading.Tasks;

namespace ImageServer
{
    class Program
    {
        const int PORT_NO = 5000;
        const string SERVER_IP = "127.0.0.1";

        static void Main(string[] args)
        {
            Stopwatch stopwatch = new Stopwatch();

            var binForm = new BinaryFormatter();
            int iterations = 1;

            //---listen at the specified IP and port no.---
            IPAddress localAdd = IPAddress.Parse(SERVER_IP);
            TcpListener listener = new TcpListener(localAdd, PORT_NO);
            Console.WriteLine("Listening...");
            listener.Start();

            //---incoming client connected---
            TcpClient client = listener.AcceptTcpClient();

            client.ReceiveBufferSize = 131116;

            EncCal encCal;

            //---get the incoming data through a network stream---
            using (NetworkStream nwStream = client.GetStream())
            {
                //1. Receive the length of the array of encrypted values
                int length = (int)binForm.Deserialize(nwStream);
                binForm.Serialize(nwStream, "OK");

                //2. Receive the public key
                BigPolyArray publicKey = ReceiveEncryptedArray(1, client, nwStream, binForm)[0];

                //3. Initiate the Encryption Scheme
                //The other parameters should also be sent from the client
                //This is just for testing
                encCal = new EncCal(publicKey, "1x^4096 + 1", 4096, 40961);

                //4. Receive Encrypted data
                stopwatch.Start();
                var encryptedDataBat = ReceiveEncryptedArray(length, client, nwStream, binForm);
                stopwatch.Stop();
                Console.WriteLine("First Communication: {0}", stopwatch.Elapsed);
                stopwatch.Reset();

                int picWidth = length / 3;
                int picLength = length / 3;

                //5. Negation operation
                stopwatch.Reset();
                stopwatch.Start();
                BigPolyArray[] encryptedResult = DoSomeOperation(encryptedDataBat, picWidth, picLength, encCal);
                stopwatch.Stop();
                Console.WriteLine("Negation: {0}", stopwatch.Elapsed);

                //6. Send encrypted results back to client
                SendEncryptedArray(encryptedResult, nwStream, binForm);
            }
            client.Close();
            listener.Stop();
            Console.ReadLine();
        }

        private static BigPolyArray[] ReceiveEncryptedArray(int length, TcpClient client, NetworkStream nwStream,
            BinaryFormatter binForm)
        {
            int bytesRead = 0;
            byte[] buffer = new byte[client.ReceiveBufferSize];
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
            foreach (var inv in encryptedArray)
            {
                using (MemoryStream ms = new MemoryStream())
                    WriteToStream(ms, inv, nwStream);
                Wait(nwStream, binForm);
            }
        }

        private static void WriteToStream(MemoryStream ms, BigPolyArray ip, NetworkStream nwStream)
        {
            ms.Seek(0, SeekOrigin.Begin);
            ip.Save(ms);
            byte[] bytesToSend = ms.ToArray();
            nwStream.Write(bytesToSend, 0, bytesToSend.Length);
            //ms.WriteTo(nwStream);
            //Console.WriteLine(bytesToSend.Length);
            ms.Flush();
        }

        private static void Wait(NetworkStream nwStream, BinaryFormatter binForm)
        {
            if ((string)binForm.Deserialize(nwStream) != "OK")
            {
                throw new Exception("Connection not OK");
            }
        }
    }
}
