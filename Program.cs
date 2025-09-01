using System.Collections;

namespace Encryption_software
{
    public static class Program
    {
        public static int Main(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine("yap yap yap main menu thingy idk");
                if (args.Length == 1)
                { Console.WriteLine("\nYou only gave one argument. You need to give the path to the file to be encrypted and the target directory path."); }
                return 0;
            }

            string fileToBeEncryptedPath = args[0];
            string targetDirectoryPath = args[1];

            if (!File.Exists(fileToBeEncryptedPath))
            {
                Console.WriteLine("The path to the file to be encrypted does not exist.");
                return 0;
            }
            if (!Directory.Exists(targetDirectoryPath))
            {
                Console.WriteLine("The target directory path does not exist.");
                return 0;
            }

            FileInfo fileInfo = new(fileToBeEncryptedPath);
            long howManyBytes = fileInfo.Length;
            long howManyBits = fileInfo.Length * 8;

            List<bool> randomBits = [];
            for (int i = 1; i <= howManyBits; i++)
            { randomBits.Add(new Random().Next(0, 2) == 1); }
            LongBitArray key = new([.. randomBits]);
            File.WriteAllBytes($"{targetDirectoryPath}/key", key.ToByteArray());

            for (long i = 0; i < howManyBytes; i++)
            {
                byte b = 0;
                for (int bit = 0; bit < 8; bit++)
                {
                    long bitIndex = i * 8 + bit;
                    if (bitIndex >= key.Length) { break; }

                    if (key[bitIndex]) { b |= (byte)(1 << bit); }
                }
                int totalRepetitions = b;
                int currentRepetitions = 0;

                long currentBitWatching = howManyBits / 2;
                
                List<int> sizeOfJump = [1, 1];
                for (long j = 0; j < totalRepetitions - 2; j++)
                { sizeOfJump.Add(sizeOfJump[^1] + sizeOfJump[^2]); }

                BitArray selectedBits = new(totalRepetitions);

                while (currentRepetitions < totalRepetitions)
                {
                    selectedBits[currentRepetitions] = key[currentBitWatching];

                    if (key[currentBitWatching] == true)
                    { currentBitWatching += sizeOfJump[^currentRepetitions]; }
                    if (key[currentBitWatching] == false)
                    { currentBitWatching -= sizeOfJump[^currentRepetitions]; }

                    //EDIT BYTES IN TO BE ENCRYPTED FILE

                    currentRepetitions++;
                }
            }

            return 0;
        }
    }

    public class LongBitArray
    {
        private readonly ulong[] _data;
        public long Length { get; }

        public LongBitArray(long length)
        {
            ArgumentOutOfRangeException.ThrowIfNegative(length);
            Length = length;
            long arrayLength = (length + 63) / 64;
            if (arrayLength > int.MaxValue)
                throw new ArgumentOutOfRangeException(nameof(length), "Array too big for CLR object.");
            _data = new ulong[arrayLength];
        }

        public LongBitArray(bool[] bits)
        {
            ArgumentNullException.ThrowIfNull(bits);

            Length = bits.LongLength;
            long buckets = (Length + 63) / 64;
            if (buckets > int.MaxValue)
                throw new ArgumentOutOfRangeException(nameof(bits), "Too many bits.");

            _data = new ulong[buckets];

            for (long i = 0; i < Length; i++)
            {
                if (bits[i])
                {
                    int bucket = (int)(i / 64);
                    int bit = (int)(i % 64);
                    _data[bucket] |= 1UL << bit;
                }
            }
        }

        public bool this[long index]
        {
            get
            {
                if (index < 0 || index >= Length) throw new ArgumentOutOfRangeException(nameof(index));
                int bucket = (int)(index / 64);
                int bit = (int)(index % 64);
                return (_data[bucket] & (1UL << bit)) != 0;
            }
            set
            {
                if (index < 0 || index >= Length) throw new ArgumentOutOfRangeException(nameof(index));
                int bucket = (int)(index / 64);
                int bit = (int)(index % 64);
                if (value)
                    _data[bucket] |= 1UL << bit;
                else
                    _data[bucket] &= ~(1UL << bit);
            }
        }
        
        public byte[] ToByteArray()
        {
            long byteLength = (Length + 7) / 8;
            if (byteLength > int.MaxValue)
                throw new InvalidOperationException("Too many bits to fit in a single byte array.");

            byte[] result = new byte[byteLength];

            for (long i = 0; i < Length; i++)
            {
                if (this[i])
                {
                    long byteIndex = i / 8;
                    int bitIndex = (int)(i % 8);
                    result[byteIndex] |= (byte)(1 << bitIndex);
                }
            }

            return result;
        }
    }
}