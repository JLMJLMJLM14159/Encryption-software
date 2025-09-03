using System.Collections;
using System.Reflection;

namespace Encryption
{
    public static class Program
    {
        public static int Main(string[] args)
        {
            if (args.Length < 1)
            {
                Console.WriteLine("yap yap yap main menu thingy idk");
                return 0;
            }

            string fileToBeEncryptedPath = args[0];

            if (!File.Exists(fileToBeEncryptedPath))
            {
                Console.WriteLine("The specified file does not exist.");
                return 0;
            }

            Directory.CreateDirectory($"{AppContext.BaseDirectory}/KEYS - USE TO DECRYPT FILES");
            Directory.CreateDirectory($"{AppContext.BaseDirectory}/ENCRYPTED FILES - DECRYPT WITH KEY");

            string fileName = Path.GetFileNameWithoutExtension(fileToBeEncryptedPath);
            string? fileExtension = Path.GetExtension(fileToBeEncryptedPath);

            byte[] bytesToBeEncrypted = File.ReadAllBytes(fileToBeEncryptedPath);
            FileInfo fileInfo = new(fileToBeEncryptedPath);
            long howManyBytes = fileInfo.Length;
            long howManyBits = fileInfo.Length * 8;

            List<bool> randomBits = [];
            Random random = new();
            for (int i = 1; i <= howManyBits; i++)
            { randomBits.Add(random.Next(0, 2) == 1); }
            LongBitArray key = new([.. randomBits]);
            File.WriteAllBytes($"{AppContext.BaseDirectory}/KEYS - USE TO DECRYPT FILES/{fileName} (key)", key.ToByteArray());

            long currentBitWatching = key.Length / 2;
            List<byte> encryptedBytes = [];

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
                if (totalRepetitions < 8) { totalRepetitions *= 8; }
                int currentRepetitions = 0;

                List<int> sizeOfJump = [1, 1];
                for (long j = 0; j < totalRepetitions - 2; j++)
                { sizeOfJump.Add(sizeOfJump[^1] + sizeOfJump[^2]); }

                BitArray selectedBits = new(totalRepetitions);

                while (currentRepetitions < totalRepetitions)
                {
                    selectedBits[currentRepetitions] = key[currentBitWatching];

                    if (key[currentBitWatching])
                    {
                        currentBitWatching = Mod(
                            currentBitWatching + sizeOfJump[^(currentRepetitions + 1)],
                            key.Length
                        );
                    }
                    else
                    {
                        currentBitWatching = Mod(
                            currentBitWatching - sizeOfJump[^(currentRepetitions + 1)],
                            key.Length
                        );
                    }

                    currentRepetitions++;
                }

                int dividedNumber = (int)Math.Round(selectedBits.Length / 8.0);
                BitArray bitsToConvert = new(8);
                for (int j = 0; j < 8; j++)
                {
                    try
                    { bitsToConvert[j] = selectedBits[(dividedNumber * (j + 1)) - 1]; }
                    catch { bitsToConvert[j] = selectedBits[^1]; }
                }

                byte numberToShiftWith = ((Func<BitArray, byte>)(bitArray =>
                {
                    byte[] idkAnymore = new byte[1];
                    bitArray.CopyTo(idkAnymore, 0);
                    return idkAnymore[0];
                }))(bitsToConvert);

                encryptedBytes.Add(CaesarCipherMod256(bytesToBeEncrypted[i], numberToShiftWith, true));
            }

            File.WriteAllBytes($"{AppContext.BaseDirectory}/ENCRYPTED FILES - DECRYPT WITH KEY/{fileName} (encrypted){fileExtension}", [.. encryptedBytes]);

            return 0;
        }

        private static long Mod(long value, long modulus)
        {
            return ((value % modulus) + modulus) % modulus;
        }


        public static byte CaesarCipherMod256(byte value, byte shift, bool isUp)
        {
            int result = (int)value;
            result = isUp ? (result + shift) : (result - shift);
            result = (result + 256) % 256;
            return (byte)result;

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