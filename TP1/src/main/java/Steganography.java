import org.apache.commons.cli.*;
import org.apache.commons.lang3.ArrayUtils;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class Steganography {

    static int BMP_HEADER_SIZE = 54;

    public static void embed(File hostFile, File payloadFile, String outFileName, EncodeMode encodeMode, String password, EncryptionCypher cypher, EncryptionChaining chaining) throws IOException {
        int n = encodeMode== EncodeMode.LSB1 || encodeMode== EncodeMode.LSBI ? 1 : 4;
        int hostOffset = BMP_HEADER_SIZE + (encodeMode == EncodeMode.LSBI ? 4 : 0);

        // Check that host file is big enough

        String extensionName = payloadFile.getName().split("\\.")[1];
        extensionName = String.format(".%s", extensionName);

        int minSize = (int) (4 + payloadFile.length() + extensionName.length() + 1);
        minSize *= Math.floorDiv(8, n);
        minSize += hostOffset;

        if(hostFile.length() <  minSize)
            throw new RuntimeException(String.format("Host file must have at least %d bytes", minSize));

        // Read host file

        FileInputStream is = new FileInputStream(hostFile);
        byte[] hostBytes = new byte[(int) hostFile.length()];
        is.read(hostBytes);

        // Get payload metadata

        int payloadSize = (int) payloadFile.length();
        byte[] payloadSizeBytes = ByteBuffer.allocate(4).putInt(payloadSize).array();

        byte[] extensionNameBytes = ArrayUtils.addAll(extensionName.getBytes(), new byte[]{0});

        // Get payload data

        is = new FileInputStream(payloadFile);
        byte[] payloadDataBytes = new byte[payloadSize];
        is.read(payloadDataBytes);

        // Create sequence with payload data and metadata

        byte[] extendedPayload = ArrayUtils.addAll(payloadSizeBytes, payloadDataBytes);
        extendedPayload = ArrayUtils.addAll(extendedPayload, extensionNameBytes);

        // Encrypt if a password is given

        if(password != null) {
            extendedPayload = Cryptography.encrypt(extendedPayload, password, cypher, chaining);

            int sequenceSize = extendedPayload.length;
            byte[] sequenceSizeBytes = ByteBuffer.allocate(4).putInt(sequenceSize).array();

            extendedPayload = ArrayUtils.addAll(sequenceSizeBytes, extendedPayload);
        }

        byte[] hostBytesOriginal = hostBytes.clone();
        LSBEncode(extendedPayload, hostBytes, n, hostOffset);

        if(encodeMode == EncodeMode.LSBI)
            LSBIApply(hostBytesOriginal, hostBytes, hostOffset);

        // Write tampered host bytes

        FileOutputStream os = new FileOutputStream(outFileName);
        os.write(hostBytes);
    }


    public static File extract(File hostFile, String outFileName, EncodeMode encodeMode, String password, EncryptionCypher cypher, EncryptionChaining chaining) throws IOException {
        int n = encodeMode== EncodeMode.LSB1 || encodeMode== EncodeMode.LSBI ? 1 : 4;
        int hostOffset = BMP_HEADER_SIZE + (encodeMode == EncodeMode.LSBI ? 4 : 0);

        // Read host file

        FileInputStream is = new FileInputStream(hostFile);
        byte[] hostBytes = new byte[(int) hostFile.length()];
        is.read(hostBytes);

        // Decode payload data with metadata

        if(encodeMode == EncodeMode.LSBI)
            LSBIUnapply(hostBytes, hostOffset);

        byte[] dataBytes = LSBDecode(hostBytes, n, hostOffset);

        // Decrypt if a password is given

        if(password != null) {
            dataBytes = ArrayUtils.subarray(dataBytes, 4, dataBytes.length);
            dataBytes = Cryptography.decrypt(dataBytes, password, cypher, chaining);
        }

        // Get payload metadata

        int payloadSize = ByteBuffer.wrap(dataBytes, 0, 4).getInt();

        List<Byte> extensionNameBytes = new ArrayList<>();
        for(int i=4+payloadSize; dataBytes[i] != 0; i++)
            extensionNameBytes.add(dataBytes[i]);
        String extensionName = new String(ArrayUtils.toPrimitive(extensionNameBytes.toArray(new Byte[0])), StandardCharsets.UTF_8);

        // Write payload data into output file

        String filename = String.format("%s%s", outFileName, extensionName);
        File outputFile = new File(filename);
        FileOutputStream os = new FileOutputStream(outputFile);

        os.write(dataBytes, 4, payloadSize);

        return outputFile;
    }


    static void LSBEncode(byte[] data, byte[] host, int n, int hostOffset) {
        int dataBit=0, hostBit=8-n + hostOffset*8;
        while(dataBit < data.length * 8) {
            for(int i=hostBit; i<hostBit+n; i++)
                copyBit(data, dataBit++, host, i);
            hostBit += 8;
        }
    }


    static byte[] LSBDecode(byte[] host, int n, int hostOffset) {
        byte[] dataBytes = new byte[(int) Math.ceil((host.length - hostOffset) / (8.0 / n))];

        int dataBit=0, hostBit=8-n + hostOffset*8;
        while(hostBit < host.length*8-n) {
            for(int i=hostBit; i<hostBit+n; i++)
                copyBit(host, i, dataBytes, dataBit++);
            hostBit += 8;
        }

        return dataBytes;
    }


    static void LSBIApply(byte[] original_host, byte[] tampered_host, int hostOffset) {
        int[] changes = new int[4];
        int[] conservations = new int[4];

        // Count the amount of changes and conservations for each 2-bit group

        for(int i=hostOffset+4; i<original_host.length; i++) {
            int group = (original_host[i] & 0b00000110) >> 1;

            if(original_host[i] != tampered_host[i])
                changes[group] += 1;
            else
                conservations[group] += 1;
        }

        // Flip the LSB of the 2-bit groups with more changes than conservations

        boolean[] flipped_groups = new boolean[]{false, false, false, false};

        for(int i=hostOffset+4; i<original_host.length; i++) {
            int group = (original_host[i] & 0b00000110) >> 1;

            if(changes[group] > conservations[group]) {
                flipped_groups[group] = true;
                if((tampered_host[i] & 1) == 1)
                    tampered_host[i] &= 0b11111110;
                else
                    tampered_host[i] |= 0b00000001;
            }
        }

        // Create and return the flip byte

        for(int i=0; i<4; i++)
            if(flipped_groups[i])
                tampered_host[hostOffset+i] |= 0b00000001;
            else
                tampered_host[hostOffset+i] &= 0b11111110;
    }


    static void LSBIUnapply(byte[] host, int hostOffset) {
        boolean[] flipped_groups = new boolean[]{false, false, false, false};

        // Recover flipped groups information

        for(int i=0; i<4; i++)
            if((host[hostOffset+i] & 1) == 1)
                flipped_groups[i] = true;

        // Restore the flipped groups

        for(int i=hostOffset+4; i<host.length; i++) {
            int group = (host[i] & 0b00000110) >> 1;

            if(flipped_groups[group]) {
                if((host[i] & 1) == 1)
                    host[i] &= 0b11111110;
                else
                    host[i] |= 0b00000001;
            }
        }
    }


    static void copyBit(byte[] src, int srcBitN, byte[] target, int targetBitN) {
        int mask = 1 << (7 - srcBitN % 8);
        int bit = (src[srcBitN / 8] & mask) >> (7 - srcBitN % 8);

        if(bit == 1)
            target[targetBitN / 8] |= 1 << (7 - targetBitN % 8);
        else
            target[targetBitN / 8] &= ~(1 << (7 - targetBitN % 8));
    }


    static void checkValidBMP(File file) throws IOException {
        FileInputStream is = new FileInputStream(file);
        byte[] bytes = new byte[(int) file.length()];
        is.read(bytes);

        if (bytes[0] != 0x42 || bytes[1] != 0x4D)
            throw new RuntimeException("Host file must be a BMP");

        if (bytes[28] != 24)
            throw new RuntimeException("BMP must be 24 bits per pixel");

        if (bytes[30] != 0)
            throw new RuntimeException("BMP must have no compression");
    }


    public static void main(String[] args) throws IOException, ParseException {
//        String arguments = "-embed -in tmp/payload.bin -p tmp/host.bmp -out tmp/host_tampered.bmp -steg LSBI";
//        String arguments = "-extract -p tmp/host_tampered.bmp -out tmp/payload_recovered -steg LSBI";
        String arguments = "-extract -p tmp/ladoLSBI.bmp -out tmp/out -steg LSBI";
        args = arguments.split(" ");

        Options options = new Options();
        options.addOption("embed", false, "Embed a payload into a host");
        options.addOption("extract", false, "Extract payload from a host");
        options.addOption("in", true, "Payload file (only when embedding)");
        options.addOption("p", true, "Host file (original when embedding, tampered when extracting");
        options.addOption("out", true, "Output file (tampered host when embedding, payload when extracting)");
        options.addOption("steg", true, "Steganography method: <LSB1 | LSB4 | LSBI>");
        options.addOption("a", true, "Encryption cypher method <aes128 | aes192 | aes256 | des>");
        options.addOption("m", true, "Encryption chaining method <ecb | cfb | ofb | cbc>");
        options.addOption("pass", true, "Encryption password");

        CommandLineParser parser = new DefaultParser();
        CommandLine cmd = parser.parse(options, args);

        if(!cmd.hasOption("p") || !cmd.hasOption("out") || !cmd.hasOption("steg")) {
            System.out.println("Missing host file, output file and/or steganography mode");
            return;
        }

        // Get and validate host file

        File hostFile = new File(cmd.getOptionValue("p"));
        checkValidBMP(hostFile);

        // Get and validate encode mode

        EncodeMode encodeMode;
        try {
            encodeMode = EncodeMode.valueOf(cmd.getOptionValue("steg"));
        } catch (IllegalArgumentException e) {
            System.out.println("Invalid steganography mode");
            return;
        }

        // Check if encryption is requested

        String password = null;
        EncryptionCypher cypher = EncryptionCypher.AES128;
        EncryptionChaining chaining = EncryptionChaining.CBC;

        if(cmd.hasOption("pass")) {
            // Get and validate algorithm and chaining

            password = cmd.getOptionValue("pass");

            if(cmd.hasOption("a"))
                try {
                    cypher = EncryptionCypher.valueOf(cmd.getOptionValue("a").toUpperCase());
                } catch (IllegalArgumentException e) {
                    System.out.println("Invalid encryption cypher method");
                    return;
                }

            if(cmd.hasOption("m"))
                try {
                    chaining = EncryptionChaining.valueOf(cmd.getOptionValue("m").toUpperCase());
                } catch (IllegalArgumentException e) {
                    System.out.println("Invalid encryption chaining method");
                    return;
                }
        }

        // Handle the embed request

        if(cmd.hasOption("embed")) {
            if(!cmd.hasOption("in") ) {
                System.out.println("Missing payload file");
                return;
            }
            File payloadFile = new File(cmd.getOptionValue("in"));
            embed(hostFile, payloadFile, cmd.getOptionValue("out"), encodeMode, password, cypher, chaining);
            System.out.printf("Embedded payload into %s\n", cmd.getOptionValue("out"));
        }

        // Handle the extract request

        if(cmd.hasOption("extract")) {
            File outputFile;
            outputFile = extract(hostFile, cmd.getOptionValue("out"), encodeMode, password, cypher, chaining);
            System.out.printf("Extracted payload to %s\n", outputFile.getName());
        }
    }

    // HT: FF x31 FF  FF x8 FF FF FF FF
    // PL: 0  x31 1   0  x8 0  0  1  0
    // OT: FE x31 FF  FE x8 FE FE FF FE

    // 110 -> 111 F
    // 111 -> 110 E

    public enum EncodeMode {LSB1, LSB4, LSBI}

    public enum EncryptionCypher {AES128, AES192, AES256, DES}

    public enum EncryptionChaining {ECB, CFB, OFB, CBC}

}
